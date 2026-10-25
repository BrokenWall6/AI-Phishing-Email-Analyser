import logging
import threading
import time
from collections import deque

import requests

from app.config import settings
from app.services import domain_utils
from app.services.trusted_domains import TrustedDomainFilter

log = logging.getLogger(__name__)


# A single engine flagging a domain is often a false positive.
MIN_MALICIOUS_VENDORS = 2


class ThreatIntelligence:
    """
    VirusTotal reputation checks for the sender, Reply-To, IPs and links.

    A lookup that fails (quota, network, bad key) is reported as
    unavailable: it adds no risk and is never shown as clean. Status is one
    of Not Configured / Disabled / Unavailable / Partial / Configured.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        } if self.api_key else {}
        self.trusted = TrustedDomainFilter()

    # --------------------------------------------------------------
    # HTTP
    # --------------------------------------------------------------

    def _get(self, endpoint):
        """Return (status, json). status: ok | not_found | unavailable"""
        return _cached_get(self.api_key, endpoint)

    def lookup_ip(self, ip):
        return self._get(f"ip_addresses/{ip}")

    def lookup_domain(self, domain):
        return self._get(f"domains/{domain}")

    def get_statistics(self, result):
        if not result:
            return {}
        return (
            result.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

    # --------------------------------------------------------------
    # Analysis
    # --------------------------------------------------------------

    def analyze(self, email):

        if not settings.ENABLE_THREAT_INTEL or not settings.ENABLE_NETWORK_LOOKUPS:
            return self._empty("Disabled", "Threat intelligence lookups are disabled.")

        if not self.api_key:
            return self._empty("Not Configured", "Threat intelligence integration not configured.")

        indicators = self.select_indicators(email)
        roles = {value: role for _, value, role in indicators}

        findings = []
        sources = []
        unavailable = []
        checked = []
        malicious = False
        risk_score = 0

        for kind, value, role in indicators:

            status, result = (
                self.lookup_ip(value) if kind == "ip" else self.lookup_domain(value)
            )

            if status == "unavailable":
                unavailable.append(value)
                continue

            checked.append(value)

            if status == "not_found":
                continue

            if "VirusTotal" not in sources:
                sources.append("VirusTotal")

            stats = self.get_statistics(result)
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            label = role

            # One engine flagging a popular domain is a common false positive
            # (seen with pypi.org), so it takes two to count as malicious.
            if malicious_count >= MIN_MALICIOUS_VENDORS:
                malicious = True
                risk_score += 40
                findings.append(
                    f"VirusTotal: {malicious_count} vendors flag {label} {value} as malicious."
                )
            elif malicious_count or suspicious_count:
                risk_score += 10
                findings.append(
                    f"VirusTotal: {malicious_count or suspicious_count} vendor flags {label} "
                    f"{value} as {'malicious' if malicious_count else 'suspicious'} "
                    f"(weak on its own)."
                )

        if not indicators:
            status = "Configured"
            notes = ["No external indicators to check."]
        elif unavailable and not checked:
            status = "Unavailable"
            notes = ["VirusTotal could not be queried (quota or network). Result is UNKNOWN, not clean."]
        elif unavailable:
            status = "Partial"
            notes = [f"{len(unavailable)} indicator(s) could not be checked and are treated as unknown."]
        else:
            status = "Configured"
            notes = []

        return {
            "status": status,
            "sources": sources,
            "malicious": malicious,
            "risk_score": min(risk_score, 100),
            "findings": findings,
            "checked_indicators": checked,
            "unavailable_indicators": unavailable,
            "indicator_roles": roles,
            "notes": notes,
        }

    # --------------------------------------------------------------
    # Which indicators to spend the (limited) lookups on
    # --------------------------------------------------------------

    def select_indicators(self, email):
        """
        Return [(kind, value, role)] in priority order, at most MAX_TI_LOOKUPS:

        1. the sender's domain (From), then the Reply-To domain if different
           - free webmail (gmail.com, outlook.com ...) and well-known domains
             are skipped: their reputation says nothing about this email;
        2. public IP addresses written in the email;
        3. link domains, the most suspicious first (by URL risk score), so a
           malicious link is not skipped just because it sorts late
           alphabetically.
        """
        chosen = []
        seen = set()

        def add(kind, value, role):
            if value and value not in seen:
                seen.add(value)
                chosen.append((kind, value, role))

        def usable_domain(domain):
            return (
                domain
                and not domain_utils.is_ip(domain)
                and domain not in domain_utils.FREE_MAIL_DOMAINS
                and not self.trusted.is_trusted(domain)
            )

        # 1. Sender and Reply-To domains
        for header, role in (("from", "sender domain"), ("reply_to", "Reply-To domain")):
            address_domain = domain_utils.address_domain(email.get(header, ""))
            # Unknown endings (not on the public-suffix list) keep the full domain.
            domain = domain_utils.registered_domain(address_domain) or address_domain
            if usable_domain(domain):
                add("domain", domain, role)

        # 2. Public IP addresses
        for ip in email.get("ioc_analysis", {}).get("ip_addresses", []):
            if domain_utils.is_public_ip(ip):
                add("ip", ip, "IP address")

        # 3. Link domains, riskiest first (stable for equal scores)
        best = {}
        order = []
        for item in email.get("url_analysis", []) or []:
            domain = item.get("domain") or domain_utils.registered_domain(item.get("url", ""))
            if not domain:
                continue
            if domain not in best:
                order.append(domain)
                best[domain] = item.get("risk_score", 0)
            else:
                best[domain] = max(best[domain], item.get("risk_score", 0))

        # Fall back to the IOC list when URL analysis is not available.
        if not order:
            order = list(email.get("ioc_analysis", {}).get("domains", []))
            best = {d: 0 for d in order}

        for domain in sorted(order, key=lambda d: -best[d]):
            if usable_domain(domain):
                add("domain", domain, "link domain")

        return chosen[: settings.MAX_TI_LOOKUPS]

    @staticmethod
    def _empty(status, note):
        return {
            "status": status,
            "sources": [],
            "malicious": False,
            "risk_score": 0,
            "findings": [],
            "checked_indicators": [],
            "unavailable_indicators": [],
            "indicator_roles": {},
            "notes": [note],
        }


_CACHE = {}

# The free API allows 4 requests a minute. Requests are spaced to
# VT_REQUESTS_PER_MINUTE, and after an HTTP 429 lookups pause for
# VT_PAUSE_AFTER_429 seconds.

_LOCK = threading.Lock()
_SENT = deque()            # timestamps of recent requests
_PAUSED_UNTIL = 0.0        # set after HTTP 429


def _wait_for_slot():
    """Block until a request is allowed. Returns False if VT is paused."""
    limit = max(1, settings.VT_REQUESTS_PER_MINUTE)
    with _LOCK:
        now = time.monotonic()
        if now < _PAUSED_UNTIL:
            return False
        while _SENT and now - _SENT[0] >= 60:
            _SENT.popleft()
        if len(_SENT) >= limit:
            wait = 60 - (now - _SENT[0]) + 0.05
            if wait > settings.VT_MAX_WAIT_SECONDS:
                return False
            time.sleep(wait)
            now = time.monotonic()
            while _SENT and now - _SENT[0] >= 60:
                _SENT.popleft()
        _SENT.append(now)
        return True


def _pause(seconds):
    global _PAUSED_UNTIL
    with _LOCK:
        _PAUSED_UNTIL = max(_PAUSED_UNTIL, time.monotonic() + seconds)


def status():
    """Small summary used by the dashboard."""
    remaining = max(0, int(_PAUSED_UNTIL - time.monotonic()))
    return {
        "configured": bool(settings.VIRUSTOTAL_API_KEY),
        "enabled": bool(settings.ENABLE_THREAT_INTEL and settings.ENABLE_NETWORK_LOOKUPS),
        "requests_per_minute": settings.VT_REQUESTS_PER_MINUTE,
        "max_lookups_per_email": settings.MAX_TI_LOOKUPS,
        "paused_seconds": remaining,
    }


def _cached_get(api_key, endpoint):
    """GET with caching and rate limiting. Only successful answers are cached."""

    if not api_key:
        return ("unavailable", None)

    if endpoint in _CACHE:
        return _CACHE[endpoint]

    if not _wait_for_slot():
        return ("unavailable", None)

    try:
        response = requests.get(
            f"{ThreatIntelligence.BASE_URL}/{endpoint}",
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=15,
        )
    except requests.RequestException as error:
        log.warning("VirusTotal lookup failed: %s", error)
        return ("unavailable", None)

    if response.status_code == 404:
        _CACHE[endpoint] = ("not_found", None)
        return _CACHE[endpoint]

    if response.status_code == 429:
        log.warning("VirusTotal quota reached (HTTP 429), pausing lookups")
        _pause(settings.VT_PAUSE_AFTER_429)
        return ("unavailable", None)

    if response.status_code != 200:
        # e.g. 401 for a bad key: unknown, not clean
        log.warning("VirusTotal lookup unavailable: HTTP %s", response.status_code)
        return ("unavailable", None)

    _CACHE[endpoint] = ("ok", response.json())
    return _CACHE[endpoint]
