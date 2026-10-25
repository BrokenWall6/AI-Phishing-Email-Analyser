from functools import lru_cache

import dns.exception
import dns.resolver

from app.config import settings
from app.services import domain_utils


class DNSAnalyzer:
    """
    DNS existence check for link domains, once per registered domain.

    Only a domain that does not exist (NXDOMAIN) adds risk. A lookup that
    fails because of the network is reported as unavailable with 0 risk.
    MX records are kept for information only, since web links don't need them.
    """

    def analyze(self, domain):

        registered = domain_utils.registered_domain(domain) or domain

        if not settings.ENABLE_NETWORK_LOOKUPS:
            return _unavailable(registered, "Network lookups disabled.")

        return dict(_cached_dns(registered))


def _unavailable(domain, reason):
    return {
        "domain": domain,
        "status": "unavailable",
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "risk_score": 0,
        "findings": [],
        "notes": [f"DNS unavailable ({reason}); treated as unknown, not as risk."],
    }


def _resolve(resolver, domain, record_type):
    answers = resolver.resolve(domain, record_type)
    return [r.to_text() for r in answers]


@lru_cache(maxsize=1024)
def _cached_dns(domain):

    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.DNS_TIMEOUT
    resolver.timeout = settings.DNS_TIMEOUT

    result = {
        "domain": domain,
        "status": "ok",
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "risk_score": 0,
        "findings": [],
        "notes": [],
    }

    try:
        result["a_records"] = _resolve(resolver, domain, "A")

    except dns.resolver.NXDOMAIN:
        result["risk_score"] = 20
        result["findings"].append("Link domain does not exist in DNS (NXDOMAIN)")
        return tuple(result.items())

    except dns.resolver.NoAnswer:
        result["notes"].append("No A record (domain exists).")

    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return tuple(_unavailable(domain, type(exc).__name__).items())

    except Exception as exc:
        return tuple(_unavailable(domain, type(exc).__name__).items())

    for record_type, key in (("MX", "mx_records"), ("NS", "ns_records")):
        try:
            result[key] = _resolve(resolver, domain, record_type)
        except Exception:
            pass

    return tuple(result.items())
