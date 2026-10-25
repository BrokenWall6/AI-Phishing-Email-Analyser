from app.services.evidence_builder import EvidenceBuilder


def _email(**overrides):
    email = {
        "url_analysis": [],
        "whois_analysis": [],
        "dns_analysis": [],
        "header_analysis": {"risk_score": 0, "findings": []},
        "brand_analysis": {"risk_score": 0, "findings": []},
        "content_analysis": {"risk_score": 0, "findings": []},
        "threat_intelligence": {"risk_score": 0, "findings": []},
    }
    email.update(overrides)
    return email


def test_benign_email_has_zero_risk():
    email = _email(
        url_analysis=[{"risk_score": 0, "findings": []}],
        whois_analysis=[{"risk_score": 0, "findings": []}],
        dns_analysis=[{"risk_score": 0, "findings": []}],
    )
    evidence = EvidenceBuilder().build(email)

    assert evidence["overall_risk_score"] == 0
    assert evidence["suspicious_url_count"] == 0
    assert evidence["brand_risk_score"] == 0
    assert evidence["header_risk_score"] == 0


def test_suspicious_url_creates_risk():
    email = _email(url_analysis=[{"risk_score": 15, "findings": ["Suspicious TLD"]}])
    evidence = EvidenceBuilder().build(email)

    assert evidence["url_risk_score"] == 15
    assert evidence["suspicious_url_count"] == 1
    assert evidence["overall_risk_score"] > 0


def test_plain_http_link_is_not_a_suspicious_url():
    # 5 points for plain HTTP is below the suspicious-URL threshold
    email = _email(url_analysis=[{"risk_score": 5, "findings": ["URL uses HTTP instead of HTTPS."]}])
    evidence = EvidenceBuilder().build(email)

    assert evidence["suspicious_url_count"] == 0
    assert evidence["signal_count"] == 0
    assert evidence["overall_risk_score"] < 20


def test_brand_impersonation_creates_risk():
    email = _email(brand_analysis={"risk_score": 35, "findings": ["Brand impersonation detected."]})
    evidence = EvidenceBuilder().build(email)

    assert evidence["brand_risk_score"] == 35
    assert evidence["overall_risk_score"] > 0


def test_multiple_independent_signals_create_high_risk():
    email = _email(
        url_analysis=[{"risk_score": 15, "findings": ["Suspicious TLD"]}],
        whois_analysis=[{"risk_score": 30, "findings": ["Recently registered domain"]}],
        dns_analysis=[{"risk_score": 20, "findings": ["Link domain does not exist in DNS (NXDOMAIN)"]}],
        header_analysis={"risk_score": 30, "findings": ["Reply-To domain differs from sender domain."]},
        brand_analysis={"risk_score": 35, "findings": ["Brand impersonation detected."]},
        threat_intelligence={"risk_score": 20, "findings": ["Suspicious indicators."]},
    )
    evidence = EvidenceBuilder().build(email)

    assert evidence["suspicious_url_count"] == 1
    assert evidence["brand_risk_score"] == 35
    assert evidence["header_risk_score"] == 30
    assert evidence["threat_intelligence_risk_score"] == 20
    assert evidence["overall_risk_score"] >= 80


def test_many_links_are_not_summed():
    # worst link + small bonus, not 80 x 15
    urls = [{"risk_score": 15, "findings": ["Suspicious TLD"]} for _ in range(80)]
    evidence = EvidenceBuilder().build(_email(url_analysis=urls))

    assert evidence["url_risk_score"] <= 40
    assert evidence["overall_risk_score"] < 70


def test_unavailable_lookups_add_no_risk():
    # a failed lookup is unknown, not evidence
    email = _email(
        url_analysis=[{"risk_score": 5, "findings": ["URL uses HTTP instead of HTTPS."]}],
        whois_analysis=[{"status": "unavailable", "risk_score": 0, "findings": []}],
        dns_analysis=[{"status": "unavailable", "risk_score": 0, "findings": []}],
    )
    evidence = EvidenceBuilder().build(email)

    assert evidence["whois_risk_score"] == 0
    assert evidence["dns_risk_score"] == 0
    assert evidence["signal_count"] == 0
    assert "WHOIS" in evidence["unavailable_checks"]
    assert "DNS" in evidence["unavailable_checks"]


def test_infrastructure_only_is_capped():
    email = _email(
        whois_analysis=[{"risk_score": 30, "findings": ["Recently registered domain"]}],
        dns_analysis=[{"risk_score": 20, "findings": ["NXDOMAIN"]}],
    )
    evidence = EvidenceBuilder().build(email)
    assert evidence["overall_risk_score"] <= 30


def _verdict(email):
    from app.services.verdict_engine import VerdictEngine
    return VerdictEngine().calculate(EvidenceBuilder().build(email))["verdict"]


def test_brand_claim_alone_is_suspicious():
    email = _email(brand_analysis={
        "risk_score": 35, "sender_claim": True,
        "findings": ["The sender name claims to be 'binance' but the email was sent from 'x.com'."],
    })
    assert _verdict(email) == "Suspicious"


def test_brand_mentioned_without_claim_is_not_raised():
    email = _email(brand_analysis={"risk_score": 35, "sender_claim": False, "findings": ["Brand note"]})
    assert _verdict(email) == "Low Risk"


def test_auth_failure_alone_stays_low_risk():
    header = {"risk_score": 25, "auth_failures": ["DMARC"], "auth_score": 25,
              "findings": ["Sender authentication failed: DMARC."]}
    assert _verdict(_email(header_analysis=header)) == "Low Risk"


def test_auth_failure_with_plain_http_link_stays_low_risk():
    header = {"risk_score": 25, "auth_failures": ["DMARC"], "auth_score": 25, "findings": []}
    url = [{"risk_score": 5, "findings": ["URL uses HTTP instead of HTTPS."]}]
    assert _verdict(_email(header_analysis=header, url_analysis=url)) == "Low Risk"


def test_auth_failure_with_another_finding_is_suspicious():
    header = {"risk_score": 25, "auth_failures": ["SPF"], "auth_score": 25, "findings": []}
    content = {"risk_score": 10, "findings": ["Email contains financial-lure or scam language."]}
    assert _verdict(_email(header_analysis=header, content_analysis=content)) == "Suspicious"


def test_auth_and_reply_to_count_as_two_signals():
    header = {"risk_score": 45, "auth_failures": ["DMARC"], "auth_score": 25,
              "findings": ["Reply-To domain differs from sender domain."]}
    evidence = EvidenceBuilder().build(_email(header_analysis=header))
    assert set(evidence["signals"]) == {"header", "auth"}
