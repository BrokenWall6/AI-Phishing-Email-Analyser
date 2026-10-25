import hashlib
import os
import tempfile
import threading
from collections import Counter
from typing import List

from fastapi import APIRouter, Body, File, Form, HTTPException, Request, UploadFile
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.services import evaluation
from app.services.analysis_service import AnalysisService

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")

# Written by the CLI (python -m tests.evaluate_dataset --csv evaluation_results.csv)
# or by a batch test run from the dashboard.
EVALUATION_CSV = "evaluation_results.csv"

MAX_BATCH_FILES = 50
MAX_FILE_BYTES = 10 * 1024 * 1024

# Batch requests temporarily change the network setting; run them one at a time.
_batch_lock = threading.Lock()


@router.get("/dashboard")
async def dashboard(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html"
    )


@router.get("/evaluation-results")
def evaluation_results():
    """
    Summarise the latest evaluation results for the dashboard's Accuracy view.
    Returns {"available": false, ...} when no results exist yet.
    """
    rows = evaluation.read_csv(EVALUATION_CSV)

    if rows is None:
        return {
            "available": False,
            "command": "python -m tests.evaluate_dataset --offline --csv evaluation_results.csv",
        }

    unique = [r for r in rows if not r.get("duplicate_of")]

    distribution = {
        label: dict(Counter(r["predicted"] for r in rows if r["expected"] == label))
        for label in ("Phishing", "Benign")
    }

    return {
        "available": True,
        "generated_at": os.path.getmtime(EVALUATION_CSV),
        "rows": rows,
        "duplicates": len(rows) - len(unique),
        "distribution": distribution,
        "metrics": evaluation.all_metrics(rows),
    }


@router.post("/evaluation-results")
def save_evaluation_results(payload: dict = Body(...)):
    """Save rows from a dashboard batch test so the Accuracy view shows them."""
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        raise HTTPException(status_code=400, detail="No rows to save.")
    if len(rows) > 20000:
        raise HTTPException(status_code=413, detail="Too many rows.")

    clean = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        expected = row.get("expected")
        if expected not in ("Phishing", "Benign"):
            continue
        clean.append({k: str(row.get(k, ""))[:500] for k in evaluation.CSV_FIELDS})

    if not clean:
        raise HTTPException(status_code=400, detail="No labelled rows (Phishing/Benign) to save.")

    evaluation.write_csv(EVALUATION_CSV, clean)
    return {"saved": len(clean)}


@router.post("/analyze-batch")
def analyze_batch(
    files: List[UploadFile] = File(...),
    labels: List[str] = Form(default=[]),
    network: bool = False,
):
    """
    Analyse up to MAX_BATCH_FILES emails in one request (the dashboard sends
    larger sets in chunks). `labels[i]` is "Phishing", "Benign" or "" for
    files[i]. No AI report is generated: it does not affect the verdict.
    """
    if len(files) > MAX_BATCH_FILES:
        raise HTTPException(status_code=413, detail=f"Send at most {MAX_BATCH_FILES} files per request.")

    service = AnalysisService()
    rows = []

    with _batch_lock:
        previous = settings.ENABLE_NETWORK_LOOKUPS
        settings.ENABLE_NETWORK_LOOKUPS = bool(network) and previous
        try:
            with tempfile.TemporaryDirectory(prefix="batch_") as tmp:
                for index, upload in enumerate(files):
                    name = os.path.basename(upload.filename or f"email_{index}.eml")
                    label = labels[index] if index < len(labels) else ""
                    label = label if label in ("Phishing", "Benign") else ""

                    data = upload.file.read(MAX_FILE_BYTES + 1)
                    if len(data) > MAX_FILE_BYTES:
                        rows.append({"file": name, "expected": label, "error": "File larger than 10 MB"})
                        continue

                    path = os.path.join(tmp, f"{index}.eml")
                    with open(path, "wb") as handle:
                        handle.write(data)

                    try:
                        result = service.analyze_email(path, include_ai_report=False)
                    except Exception as exc:  # report and continue
                        rows.append({"file": name, "expected": label, "error": type(exc).__name__})
                        continue

                    row = evaluation.result_to_row(name, label, result)
                    row["sha256"] = hashlib.sha256(data).hexdigest()
                    rows.append(row)
        finally:
            settings.ENABLE_NETWORK_LOOKUPS = previous

    return {"rows": rows, "network": bool(network) and previous}
