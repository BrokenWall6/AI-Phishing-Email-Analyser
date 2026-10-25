import os
import shutil

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import settings
from app.llm.ollama_client import OllamaClient
from app.services.analysis_service import AnalysisService
from app.services.analyzers import threat_intelligence

router = APIRouter()

UPLOAD_DIR = "uploads"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _save_upload(file: UploadFile) -> str:
    # basename() keeps names like "../../app/main.py" inside the uploads folder
    filename = os.path.basename(file.filename or "")
    if not filename:
        raise HTTPException(status_code=400, detail="Uploaded file has no name.")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(UPLOAD_DIR, filename)

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    if os.path.getsize(filepath) > MAX_UPLOAD_BYTES:
        os.remove(filepath)
        raise HTTPException(status_code=413, detail="Email file is larger than 10 MB.")

    return filepath


@router.post("/analyze-email")
def analyze_email(file: UploadFile = File(...), include_ai_report: bool = True):
    """Full analysis: verdict, evidence, MITRE mapping and AI report."""
    filepath = _save_upload(file)
    return AnalysisService().analyze_email(filepath, include_ai_report=include_ai_report)


@router.post("/upload-email")
def upload_email(file: UploadFile = File(...), include_ai_report: bool = True):
    """Same as /analyze-email, kept for older clients."""
    filepath = _save_upload(file)
    return AnalysisService().analyze_email(filepath, include_ai_report=include_ai_report)


@router.get("/lookup-status")
def lookup_status():
    """Which online checks are switched on (shown in the dashboard)."""
    return {
        "network_lookups": settings.ENABLE_NETWORK_LOOKUPS,
        "whois_timeout": settings.WHOIS_TIMEOUT,
        "dns_timeout": settings.DNS_TIMEOUT,
        "max_domain_lookups": settings.MAX_DOMAIN_LOOKUPS,
        "virustotal": threat_intelligence.status(),
    }


@router.get("/llm-health")
def llm_health():
    """Is Ollama running and is the configured model installed?"""
    return OllamaClient().health()
