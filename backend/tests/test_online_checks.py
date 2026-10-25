"""WHOIS / DNS / VirusTotal paths with the network mocked out."""

import pytest

import app.services.analyzers.threat_intelligence as ti
from app.config import settings
from app.services.evidence_builder import EvidenceBuilder
from app.services.verdict_engine import VerdictEngine


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def reset_vt(monkeypatch):
    ti._CACHE.clear()
    ti._SENT.clear()
    monkeypatch.setattr(ti, "_PAUSED_UNTIL", 0.0)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(settings, "ENABLE_NETWORK_LOOKUPS", True)
    monkeypatch.setattr(settings, "ENABLE_THREAT_INTEL", True)
    yield
    ti._CACHE.clear()
    ti._SENT.clear()


def malicious(*_, **__):
    return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 7}}}})


def test_virustotal_detection_raises_verdict(monkeypatch):
    monkeypatch.setattr(ti.requests, "get", malicious)
    email = {"ioc_analysis": {"domains": ["evil-login.example"], "ip_addresses": []}}
    result = ti.ThreatIntelligence().analyze(email)

    assert result["status"] == "Configured"
    assert result["malicious"] is True
    assert result["risk_score"] >= 40

    evidence = EvidenceBuilder().build({"threat_intelligence": result})
    assert VerdictEngine().calculate(evidence)["verdict"] == "Phishing"


def test_rate_limit_spaces_requests(monkeypatch):
    calls, sleeps = [], []
    monkeypatch.setattr(ti.requests, "get", lambda *a, **k: calls.append(1) or malicious())
    monkeypatch.setattr(ti.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(settings, "VT_REQUESTS_PER_MINUTE", 2)

    for i in range(3):
        ti._cached_get("test-key", f"domains/d{i}.example")

    assert len(calls) == 3
    assert len(sleeps) == 1 and sleeps[0] > 50   # third request waited for a free slot


def test_quota_error_pauses_virustotal(monkeypatch):
    calls = []
    monkeypatch.setattr(ti.requests, "get", lambda *a, **k: calls.append(1) or FakeResponse(429))

    first = ti._cached_get("test-key", "domains/a.example")
    second = ti._cached_get("test-key", "domains/b.example")

    assert first == ("unavailable", None) and second == ("unavailable", None)
    assert len(calls) == 1                      # paused after the 429, no hammering
    assert ti.status()["paused_seconds"] > 0


def test_unavailable_virustotal_is_unknown_not_clean(monkeypatch):
    monkeypatch.setattr(ti.requests, "get", lambda *a, **k: FakeResponse(429))
    result = ti.ThreatIntelligence().analyze(
        {"ioc_analysis": {"domains": ["x.example"], "ip_addresses": []}})
    assert result["status"] == "Unavailable"
    assert result["risk_score"] == 0
    assert "x.example" in result["unavailable_indicators"]


def test_lookup_status_route(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    body = TestClient(app).get("/lookup-status").json()
    assert body["network_lookups"] is True
    assert body["virustotal"]["configured"] is True
    assert body["virustotal"]["requests_per_minute"] >= 1


def test_sender_and_reply_to_domains_are_checked_first(monkeypatch):
    email = {
        "from": "PayPal <security@mail.paypa1-support.xyz>",
        "reply_to": "help@recover-acct.top",
        "ioc_analysis": {"ip_addresses": ["8.8.4.4"], "domains": []},
        "url_analysis": [
            {"url": "https://aaa-harmless.example/x", "domain": "aaa-harmless.example", "risk_score": 0},
            {"url": "http://zz-login.xyz/verify", "domain": "zz-login.xyz", "risk_score": 45},
        ],
    }
    picked = ti.ThreatIntelligence().select_indicators(email)
    assert [(v, r) for _, v, r in picked] == [
        ("paypa1-support.xyz", "sender domain"),
        ("recover-acct.top", "Reply-To domain"),
        ("8.8.4.4", "IP address"),
        ("zz-login.xyz", "link domain"),       # riskiest link wins the last slot
    ]


def test_free_mail_and_trusted_domains_are_skipped(monkeypatch):
    email = {
        "from": "Someone <someone@gmail.com>",
        "reply_to": "x@outlook.com",
        "ioc_analysis": {"ip_addresses": ["10.0.0.1"], "domains": []},
        "url_analysis": [
            {"url": "https://www.google.com/", "domain": "google.com", "risk_score": 0},
            {"url": "https://evil.example/", "domain": "evil.example", "risk_score": 5},
        ],
    }
    picked = ti.ThreatIntelligence().select_indicators(email)
    assert [v for _, v, _ in picked] == ["evil.example"]


def test_malicious_sender_domain_is_reported(monkeypatch):
    monkeypatch.setattr(ti.requests, "get", malicious)
    result = ti.ThreatIntelligence().analyze({"from": "a@bad-sender.example", "url_analysis": [], "ioc_analysis": {}})
    assert result["malicious"] is True
    assert any("sender domain bad-sender.example" in f for f in result["findings"])
    assert result["indicator_roles"]["bad-sender.example"] == "sender domain"


def test_single_vendor_flag_is_weak(monkeypatch):
    one_vendor = lambda *a, **k: FakeResponse(
        200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}
    )
    monkeypatch.setattr(ti.requests, "get", one_vendor)
    email = {"ioc_analysis": {"domains": ["pypi.example"], "ip_addresses": []}}
    result = ti.ThreatIntelligence().analyze(email)

    assert result["malicious"] is False
    assert result["risk_score"] == 10
    assert any("weak on its own" in f for f in result["findings"])

    evidence = EvidenceBuilder().build({"threat_intelligence": result})
    assert VerdictEngine().calculate(evidence)["verdict"] == "Benign"
