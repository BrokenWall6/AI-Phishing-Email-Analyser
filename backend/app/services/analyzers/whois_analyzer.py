import logging
import socket
from datetime import datetime, timezone
from functools import lru_cache

import whois

from app.config import settings
from app.services import domain_utils

# python-whois logs every timeout as an ERROR. A failed lookup is already
# reported as "unavailable" in the result, so keep the console quiet.
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)


class WhoisAnalyzer:
    """
    Domain-age check via WHOIS, once per registered domain (cached).

    A domain registered in the last 30 days adds 30 points, under 180 days
    adds 10. A failed lookup is reported as unavailable with 0 risk, and a
    missing registrar (common with privacy services) is informational only.
    """

    def analyze(self, domain):

        registered = domain_utils.registered_domain(domain) or domain

        if not settings.ENABLE_NETWORK_LOOKUPS:
            return self._unavailable(registered, "Network lookups disabled.")

        return dict(_cached_whois(registered))

    @staticmethod
    def _unavailable(domain, reason):
        return {
            "domain": domain,
            "status": "unavailable",
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "risk_score": 0,
            "findings": [],
            "notes": [f"WHOIS unavailable ({reason}); treated as unknown, not as risk."],
        }


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_utc(value):
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@lru_cache(maxsize=1024)
def _cached_whois_tuple(domain):

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(settings.WHOIS_TIMEOUT)

    try:
        result = whois.whois(domain)
    except Exception as exc:
        return tuple(WhoisAnalyzer._unavailable(domain, type(exc).__name__).items())
    finally:
        socket.setdefaulttimeout(previous_timeout)

    registrar = _first(getattr(result, "registrar", None))
    creation = _as_utc(_first(getattr(result, "creation_date", None)))
    expiration = _as_utc(_first(getattr(result, "expiration_date", None)))

    findings = []
    notes = []
    risk_score = 0
    age_days = None

    if not registrar and not creation:
        return tuple(WhoisAnalyzer._unavailable(domain, "empty WHOIS record").items())

    if not registrar:
        notes.append("Registrar not disclosed (often a privacy service).")

    if creation:
        age_days = (datetime.now(timezone.utc) - creation).days

        if age_days < 30:
            findings.append(f"Recently registered domain ({age_days} days old)")
            risk_score += 30
        elif age_days < 180:
            findings.append(f"Young domain ({age_days} days old)")
            risk_score += 10

    return tuple({
        "domain": domain,
        "status": "ok",
        "registrar": registrar,
        "creation_date": creation.isoformat() if creation else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "domain_age_days": age_days,
        "risk_score": risk_score,
        "findings": findings,
        "notes": notes,
    }.items())


def _cached_whois(domain):
    return _cached_whois_tuple(domain)
