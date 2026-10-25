from app.services import domain_utils


class TrustedDomainFilter:
    """
    Well-known domains that are skipped for WHOIS, DNS and VirusTotal.
    Being on this list does not make an email safe; it only saves lookups.
    """

    TRUSTED_DOMAINS = {
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "youtube.com", "microsoft.com", "office.com", "office365.com",
        "live.com", "outlook.com", "cloudflare.com", "cdnjs.com", "jquery.com",
        "bootstrapcdn.com", "amazonaws.com", "github.com",
        "githubusercontent.com", "apple.com", "paypal.com", "amazon.com",
        "linkedin.com", "facebook.com", "w3.org", "wikipedia.org",
        "sourceforge.net", "python.org", "mozilla.org",
    }

    def is_trusted(self, url):
        return domain_utils.registered_domain(url) in self.TRUSTED_DOMAINS
