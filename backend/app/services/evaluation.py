"""
Evaluation helpers shared by tests/evaluate_dataset.py and the dashboard's
batch test, so both report the same numbers.
"""

import csv
import os

POSITIVE_VERDICTS = {"Phishing", "Suspicious"}

CSV_FIELDS = [
    "file", "expected", "predicted", "risk_score", "duplicate_of",
    "urls", "suspicious_urls", "url", "brand", "header", "content",
    "whois", "dns", "ti", "signals", "top_findings",
]

MODES = {
    "binary": lambda v: v in POSITIVE_VERDICTS,
    "strict": lambda v: v == "Phishing",
    "lenient": lambda v: v != "Benign",
}


def result_to_row(file_name, expected, result, duplicate_of=""):
    """Flatten one AnalysisService result into an evaluation row."""
    evidence = result.get("evidence", {})
    verdict = result.get("verdict", {})
    return {
        "file": file_name,
        "expected": expected,
        "predicted": verdict.get("verdict", ""),
        "risk_score": verdict.get("risk_score", 0),
        "duplicate_of": duplicate_of or "",
        "urls": evidence.get("url_count", 0),
        "suspicious_urls": evidence.get("suspicious_url_count", 0),
        "url": evidence.get("url_risk_score", 0),
        "brand": evidence.get("brand_risk_score", 0),
        "header": evidence.get("header_risk_score", 0),
        "content": evidence.get("content_risk_score", 0),
        "whois": evidence.get("whois_risk_score", 0),
        "dns": evidence.get("dns_risk_score", 0),
        "ti": evidence.get("threat_intelligence_risk_score", 0),
        "signals": "+".join(evidence.get("signals", [])),
        "top_findings": " | ".join(evidence.get("findings", [])[:4]),
    }


def metrics(rows, is_positive):
    labelled = [r for r in rows if r.get("expected") in ("Phishing", "Benign")]
    tp = sum(1 for r in labelled if r["expected"] == "Phishing" and is_positive(r["predicted"]))
    fn = sum(1 for r in labelled if r["expected"] == "Phishing" and not is_positive(r["predicted"]))
    tn = sum(1 for r in labelled if r["expected"] == "Benign" and not is_positive(r["predicted"]))
    fp = sum(1 for r in labelled if r["expected"] == "Benign" and is_positive(r["predicted"]))

    def pct(a, b):
        return round(a / b * 100, 2) if b else 0.0

    precision = pct(tp, tp + fp)
    recall = pct(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 2) if precision + recall else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total": tp + fp + tn + fn,
        "accuracy": pct(tp + tn, tp + fp + tn + fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": pct(fp, fp + tn),
    }


def all_metrics(rows):
    unique = [r for r in rows if not r.get("duplicate_of")]
    out = {name: metrics(rows, fn) for name, fn in MODES.items()}
    out["binary_unique"] = metrics(unique, MODES["binary"])
    return out


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


def read_csv(path):
    if not os.path.exists(path):
        return None
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        try:
            row["risk_score"] = int(float(row.get("risk_score") or 0))
        except ValueError:
            row["risk_score"] = 0
    return rows
