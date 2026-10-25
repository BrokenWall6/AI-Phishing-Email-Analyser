"""API smoke tests. Network lookups and the LLM are disabled/mocked."""

import os

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.llm.ollama_client import OllamaClient, OllamaError

from app.main import app  # noqa: E402

client = TestClient(app)

PHISH = b"""From: PayPal Security <alert@paypa1-support.xyz>
To: victim@example.com
Subject: Your account has been suspended
Reply-To: recover@gmail.com
Content-Type: text/plain

Your account has been suspended due to unauthorized access.
Verify your account within 24 hours immediately: http://paypa1.xyz/login
"""

BENIGN = b"""From: Ana <ana@example.org>
To: sam@example.org
Subject: Lunch on Friday
Content-Type: text/plain

Hi Sam, are we still on for lunch on Friday? Cheers, Ana
"""


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_NETWORK_LOOKUPS", False)


@pytest.fixture(autouse=True)
def no_llm(monkeypatch):
    def fail(self, prompt, json_mode=True):
        raise OllamaError("Cannot connect to Ollama (test)")
    monkeypatch.setattr(OllamaClient, "generate", fail)


@pytest.fixture(autouse=True)
def tmp_cwd(tmp_path, monkeypatch):
    # uploads/ is written relative to the working directory.
    backend = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    monkeypatch.chdir(backend)


def test_analyze_phishing_email():
    r = client.post("/analyze-email", files={"file": ("test_phish.eml", PHISH, "message/rfc822")})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["verdict"] == "Phishing"
    assert body["ai_report"]["status"] == "unavailable"   # fallback is labelled
    assert any(t["id"] == "T1566.002" for t in body["mitre_attack"])


def test_analyze_benign_email():
    r = client.post("/analyze-email", files={"file": ("test_benign.eml", BENIGN, "message/rfc822")})
    assert r.status_code == 200
    assert r.json()["verdict"]["verdict"] == "Benign"


def test_upload_email_route_works():
    r = client.post("/upload-email?include_ai_report=false",
                    files={"file": ("test_benign.eml", BENIGN, "message/rfc822")})
    assert r.status_code == 200
    assert r.json()["ai_report"]["status"] == "skipped"


def test_upload_filename_cannot_escape_uploads_folder():
    r = client.post("/analyze-email?include_ai_report=false",
                    files={"file": ("../../evil_test.eml", BENIGN, "message/rfc822")})
    assert r.status_code == 200
    assert not os.path.exists(os.path.join("..", "evil_test.eml"))
    assert os.path.exists(os.path.join("uploads", "evil_test.eml"))
    os.remove(os.path.join("uploads", "evil_test.eml"))


def test_llm_health_when_ollama_is_down(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_HOST", "http://127.0.0.1:9")
    r = client.get("/llm-health")
    assert r.status_code == 200
    assert r.json()["ollama_reachable"] is False


def test_lookup_status_reports_settings():
    body = client.get("/lookup-status").json()
    assert body["network_lookups"] is False
    assert "virustotal" in body


@pytest.fixture(autouse=True, scope="module")
def cleanup():
    yield
    for name in ("test_phish.eml", "test_benign.eml"):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads", name)
        if os.path.exists(path):
            os.remove(path)


def test_dashboard_page_loads():
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "Phishing Email Analyzer" in r.text


def test_evaluation_results_without_csv(tmp_path, monkeypatch):
    import app.api.dashboard_routes as routes
    monkeypatch.setattr(routes, "EVALUATION_CSV", str(tmp_path / "missing.csv"))
    r = client.get("/evaluation-results")
    assert r.status_code == 200
    assert r.json()["available"] is False


def test_evaluation_results_metrics(tmp_path, monkeypatch):
    import app.api.dashboard_routes as routes
    csv_path = tmp_path / "results.csv"
    csv_path.write_text(
        "file,expected,predicted,risk_score,duplicate_of\n"
        "a.eml,Phishing,Phishing,90,\n"
        "b.eml,Phishing,Low Risk,25,\n"
        "c.eml,Benign,Benign,0,\n"
        "d.eml,Benign,Suspicious,50,\n"
        "e.eml,Phishing,Phishing,90,a.eml\n"
    )
    monkeypatch.setattr(routes, "EVALUATION_CSV", str(csv_path))
    body = client.get("/evaluation-results").json()
    binary = body["metrics"]["binary"]
    assert (binary["tp"], binary["fn"], binary["tn"], binary["fp"]) == (2, 1, 1, 1)
    assert body["metrics"]["lenient"]["tp"] == 3
    assert body["duplicates"] == 1
    assert body["metrics"]["binary_unique"]["total"] == 4


def test_analyze_batch_and_save(tmp_path, monkeypatch):
    import app.api.dashboard_routes as routes
    monkeypatch.setattr(routes, "EVALUATION_CSV", str(tmp_path / "results.csv"))

    r = client.post(
        "/analyze-batch",
        files=[("files", ("p.eml", PHISH, "message/rfc822")),
               ("files", ("b.eml", BENIGN, "message/rfc822"))],
        data={"labels": ["Phishing", "Benign"]},
    )
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert [row["predicted"] for row in rows] == ["Phishing", "Benign"]
    assert rows[0]["expected"] == "Phishing" and rows[1]["expected"] == "Benign"

    saved = client.post("/evaluation-results", json={"rows": rows})
    assert saved.status_code == 200 and saved.json()["saved"] == 2

    summary = client.get("/evaluation-results").json()
    assert summary["metrics"]["binary"]["accuracy"] == 100.0


def test_analyze_batch_rejects_too_many_files():
    files = [("files", (f"{i}.eml", BENIGN, "message/rfc822")) for i in range(51)]
    r = client.post("/analyze-batch", files=files)
    assert r.status_code == 413
