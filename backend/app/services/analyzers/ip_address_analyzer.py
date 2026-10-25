import ipaddress
from urllib.parse import urlparse


class IPAddressAnalyzer:

    def analyze(self, url):

        findings = []

        score = 0

        try:

            hostname = urlparse(url).hostname

            ipaddress.ip_address(hostname)

            findings.append(
                "URL uses an IP address instead of a domain."
            )

            score += 25

        except (TypeError, ValueError):
            # hostname is a normal domain name (or missing)

            pass

        return score, findings
