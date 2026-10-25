import re


class SuspiciousDomainAnalyzer:
    """
    Structural checks on a hostname: very long names, many hyphens and
    many digits. Thresholds are set so ordinary hosts such as
    lists.sourceforge.net don't trigger them.
    """

    def analyze(self, hostname):

        findings = []
        risk_score = 0

        hostname = (hostname or "").lower()

        if len(hostname) > 40:
            findings.append("Unusually long domain")
            risk_score += 10

        if hostname.count("-") >= 3:
            findings.append("Multiple hyphens in domain")
            risk_score += 10

        if len(re.findall(r"\d", hostname)) >= 5:
            findings.append("Contains many numeric characters")
            risk_score += 5

        return risk_score, findings
