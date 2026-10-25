import re

from app.services import domain_utils
from app.services.url_extractor import URLExtractor


class IOCExtractor:
    """
    Collects indicators of compromise: URLs, domains, email addresses and
    public IP addresses (version numbers and private ranges are skipped).
    """

    def __init__(self):
        self.url_extractor = URLExtractor()

    def analyze(self, email):

        text = " ".join([
            email.get("subject", "") or "",
            email.get("from", "") or "",
            email.get("reply_to", "") or "",
            email.get("body", "") or "",
        ])

        urls = self.url_extractor.extract_urls(text, email.get("html_body", ""))

        email_addresses = re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text
        )

        ip_addresses = [
            ip for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
            if domain_utils.is_public_ip(ip)
        ]

        domains = []
        for url in urls:
            registered = domain_utils.registered_domain(url)
            if registered:
                domains.append(registered)

        return {
            "urls": sorted(set(urls)),
            "domains": sorted(set(domains)),
            "email_addresses": sorted(set(email_addresses)),
            "ip_addresses": sorted(set(ip_addresses)),
        }
