from app.services.verdict_engine import VerdictEngine


def test_benign_email():
    evidence = {
        "overall_risk_score": 0,
        "brand_risk_score": 0,
        "suspicious_url_count": 0,
        "whois_risk_score": 0,
        "dns_risk_score": 0,
        "header_risk_score": 0,
        "threat_intelligence_risk_score": 0,
        "url_risk_score": 0,
        "findings": []
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Benign"
    assert result["confidence"] == "High"
    assert result["risk_score"] == 0


def test_low_risk_email():
    evidence = {
        "overall_risk_score": 25,
        "brand_risk_score": 0,
        "suspicious_url_count": 1,
        "whois_risk_score": 0,
        "dns_risk_score": 0,
        "header_risk_score": 0,
        "threat_intelligence_risk_score": 0,
        "url_risk_score": 10,
        "findings": [
            "URL contains authentication or account-related keywords."
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Low Risk"
    assert result["confidence"] == "Low"
    assert result["risk_score"] == 25


def test_suspicious_email():
    evidence = {
        "overall_risk_score": 50,
        "brand_risk_score": 0,
        "suspicious_url_count": 1,
        "whois_risk_score": 0,
        "dns_risk_score": 0,
        "header_risk_score": 30,
        "threat_intelligence_risk_score": 0,
        "url_risk_score": 15,
        "findings": [
            "Reply-To domain differs from sender domain."
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Suspicious"
    assert result["confidence"] == "Medium"
    assert result["risk_score"] >= 45


def test_brand_impersonation_with_header_anomaly_is_phishing():
    evidence = {
        "overall_risk_score": 50,
        "brand_risk_score": 35,
        "suspicious_url_count": 1,
        "whois_risk_score": 0,
        "dns_risk_score": 0,
        "header_risk_score": 30,
        "threat_intelligence_risk_score": 0,
        "url_risk_score": 15,
        "findings": [
            "Brand impersonation detected.",
            "Reply-To domain differs from sender domain."
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Phishing"
    assert result["confidence"] == "High"
    assert result["risk_score"] >= 75


def test_multiple_independent_signals_are_phishing():
    evidence = {
        "overall_risk_score": 40,
        "brand_risk_score": 35,
        "suspicious_url_count": 1,
        "whois_risk_score": 15,
        "dns_risk_score": 30,
        "header_risk_score": 30,
        "threat_intelligence_risk_score": 20,
        "url_risk_score": 15,
        "findings": [
            "Brand impersonation detected.",
            "WHOIS information unavailable",
            "No A records found",
            "Reply-To domain differs from sender domain."
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Phishing"
    assert result["confidence"] == "High"
    assert result["risk_score"] >= 70


def test_malicious_threat_intelligence_is_phishing():
    evidence = {
        "overall_risk_score": 20,
        "brand_risk_score": 0,
        "suspicious_url_count": 0,
        "whois_risk_score": 0,
        "dns_risk_score": 0,
        "header_risk_score": 0,
        "threat_intelligence_risk_score": 40,
        "url_risk_score": 0,
        "findings": [
            "Threat intelligence identified malicious indicators."
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["verdict"] == "Phishing"
    assert result["confidence"] == "High"
    assert result["risk_score"] >= 75


def test_infrastructure_only_risk_does_not_become_phishing():
    evidence = {
        "overall_risk_score": 60,
        "brand_risk_score": 0,
        "suspicious_url_count": 0,
        "whois_risk_score": 15,
        "dns_risk_score": 30,
        "header_risk_score": 0,
        "threat_intelligence_risk_score": 0,
        "url_risk_score": 0,
        "findings": [
            "WHOIS information unavailable",
            "No A records found"
        ]
    }

    result = VerdictEngine().calculate(evidence)

    assert result["risk_score"] <= 30
    assert result["verdict"] == "Low Risk"
