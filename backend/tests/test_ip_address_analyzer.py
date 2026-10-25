from app.services.analyzers.ip_address_analyzer import IPAddressAnalyzer


def test_ip_address_detection():

    analyzer = IPAddressAnalyzer()

    score, findings = analyzer.analyze(
        "http://185.199.108.153/login"
    )

    assert score == 25

    assert (
        "URL uses an IP address instead of a domain."
        in findings
    )
