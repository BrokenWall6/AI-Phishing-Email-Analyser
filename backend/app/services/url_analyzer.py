import re
from urllib.parse import urlparse, unquote

from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from app.services import domain_utils
from app.services.analyzers.suspicious_tld import SuspiciousTLDAnalyzer
from app.services.analyzers.ip_address_analyzer import IPAddressAnalyzer
from app.services.analyzers.suspicious_domain_analyzer import SuspiciousDomainAnalyzer


class URLAnalyzer:
    """
    Heuristic risk score for a single URL.

    Checks: IP-address hosts, look-alike brand names (small edit distance,
    common words skipped), brand names used as subdomains, "@" in the host,
    deep subdomains, shorteners, risky TLDs and pages on free hosting.
    Plain HTTP adds a few points but is not enough on its own to mark a URL
    as suspicious.
    """

    TRUSTED_DOMAINS = [
        "paypal",
        "google",
        "amazon",
        "microsoft",
        "apple",
        "facebook",
        "netflix",
        "linkedin",
        "github",
    ]

    # Registered-domain labels that legitimately belong to the brands above.
    LEGIT_BRAND_LABELS = {
        "google": {"google", "googleapis", "gstatic", "googleusercontent",
                   "withgoogle", "googlemail", "googlegroups", "youtube"},
        "microsoft": {"microsoft", "microsoftonline", "office", "office365",
                      "live", "outlook", "windows", "msn", "bing", "azure"},
        "amazon": {"amazon", "amazonaws", "amazonses"},
        "apple": {"apple", "icloud"},
        "facebook": {"facebook", "fb", "fbcdn", "meta"},
        "github": {"github", "githubusercontent", "githubassets"},
        "linkedin": {"linkedin", "licdn"},
        "netflix": {"netflix", "nflxext"},
        "paypal": {"paypal", "paypalobjects"},
    }

    # Real words that are close to a brand name but not impersonation.
    COMMON_WORDS = {
        "apply", "ample", "maple", "applet", "apples", "amazing", "amazed",
        "goggle", "googol", "netflux", "linked", "linkin",
    }

    LOGIN_KEYWORDS = [
        "login", "signin", "sign-in", "logon", "verify", "verification",
        "account", "secure", "security", "password", "authenticate",
        "authentication", "update", "confirm", "unlock", "webscr", "billing",
    ]

    # Free hosting / storage that phishing kits use to host fake login pages.
    # Only scored when the link points at a page (html/php/no file) on them.
    ABUSED_HOSTING = (
        "storage.googleapis.com", "firebasestorage.googleapis.com", "web.app",
        "firebaseapp.com", "r2.dev", "pages.dev", "workers.dev", "netlify.app",
        "vercel.app", "glitch.me", "github.io", "weebly.com", "wixsite.com",
        "webflow.io", "blob.core.windows.net", "ipfs.io", "dweb.link",
        "sites.google.com", "forms.gle", "000webhostapp.com", "replit.app",
        "s3.amazonaws.com",
    )

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
    }

    def __init__(self):
        self.tld_analyzer = SuspiciousTLDAnalyzer()
        self.ip_analyzer = IPAddressAnalyzer()
        self.domain_analyzer = SuspiciousDomainAnalyzer()

    def analyze(self, url, verbose=False):

        findings = []
        informational_findings = []
        risk_score = 0

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            netloc = parsed.netloc or ""
        except ValueError:
            parsed = None
            hostname = ""
            netloc = ""

        path = parsed.path if parsed else ""
        query = parsed.query if parsed else ""
        scheme = (parsed.scheme if parsed else "").lower()

        subdomain, domain, suffix = domain_utils.split(hostname or url)
        registered = domain_utils.registered_domain(hostname or url)

        # Domain structure (length / hyphens / digits) - not for raw IPs
        if not domain_utils.is_ip(hostname):
            score, domain_findings = self.domain_analyzer.analyze(hostname)
            risk_score += score
            findings.extend(domain_findings)

        # Suspicious TLD
        score, tld_findings = self.tld_analyzer.analyze(url)
        risk_score += score
        findings.extend(tld_findings)

        # Direct IP address (scored once)
        score, ip_findings = self.ip_analyzer.analyze(url)
        risk_score += score
        findings.extend(ip_findings)
        direct_ip_detected = score > 0

        # HTTP instead of HTTPS (weak on its own)
        http_detected = scheme == "http"
        if http_detected:
            findings.append("URL uses HTTP instead of HTTPS.")
            risk_score += 5

        # URL length
        long_url_detected = len(url) > 150
        if long_url_detected:
            findings.append("URL is unusually long.")
            risk_score += 5

        # "@" in the authority part hides the real destination
        at_symbol_detected = "@" in netloc
        if at_symbol_detected:
            findings.append(
                "URL contains an @ symbol that may be used for URL obfuscation."
            )
            risk_score += 20

        # Punycode
        punycode_detected = "xn--" in hostname
        if punycode_detected:
            findings.append("Domain uses Punycode encoding.")
            risk_score += 20

        # Deep subdomains (e.g. paypal.com.verify.evil.xyz)
        subdomain_levels = len([p for p in subdomain.split(".") if p and p != "www"])
        if subdomain_levels >= 3:
            findings.append("URL contains an unusually large number of subdomains.")
            risk_score += 10

        # URL shortener
        if registered in self.SHORTENERS:
            findings.append("URL uses a link-shortening service that hides the destination.")
            risk_score += 10

        # Page hosted on free/cloud hosting often abused for phishing
        if any(hostname == h or hostname.endswith("." + h) for h in self.ABUSED_HOSTING):
            if re.search(r"\.(s?html?|php|aspx?)$", path, re.I) or "#" in url or path in ("", "/"):
                findings.append("Link opens a page on free cloud hosting that is often abused for phishing.")
                risk_score += 20

        # Embedded redirect to another URL
        decoded_query = unquote(query).lower()
        if "http://" in decoded_query or "https://" in decoded_query:
            informational_findings.append("URL contains an embedded redirect target.")

        # Authentication keywords (only risky together with other signs)
        url_text = (path + "?" + query).lower()
        matched_keywords = sorted({k for k in self.LOGIN_KEYWORDS if k in url_text})

        if matched_keywords:
            informational_findings.append(
                "URL contains authentication or account-related keywords: "
                f"{', '.join(matched_keywords)}."
            )

            suspicious_context = (
                direct_ip_detected or at_symbol_detected or punycode_detected
                or registered in self.SHORTENERS
                or bool(tld_findings) or subdomain_levels >= 3
            )

            if suspicious_context:
                risk_score += 10
                findings.append(
                    "Authentication or account-related keywords occur together "
                    "with other suspicious URL characteristics."
                )

        # Brand checks (skip for the brand's own domains)
        typosquatting_detected = False
        brand_impersonation_detected = False

        legit_labels = set().union(*self.LEGIT_BRAND_LABELS.values())

        if domain and domain not in legit_labels and not direct_ip_detected:

            # Typosquatting: paypa1, rnicrosoft, gooogle ...
            if domain not in self.COMMON_WORDS:
                for trusted in self.TRUSTED_DOMAINS:
                    similarity = fuzz.ratio(domain, trusted)
                    distance = Levenshtein.distance(domain, trusted)
                    if similarity >= 80 and 0 < distance <= 2 and len(domain) >= 4:
                        typosquatting_detected = True
                        findings.append(f"Possible typosquatting of {trusted}.")
                        risk_score += 30
                        break

            # Brand name inside an unrelated domain: paypal-secure-login.xyz
            for trusted in self.TRUSTED_DOMAINS:
                if trusted in domain:
                    brand_impersonation_detected = True
                    findings.append(f"Brand impersonation of {trusted}.")
                    risk_score += 25
                    break

            # Brand used as a subdomain of an unrelated domain,
            # e.g. paypal.com.account-check.net
            if not brand_impersonation_detected:
                for trusted in self.TRUSTED_DOMAINS:
                    if trusted in subdomain.split(".") or f"{trusted}-" in subdomain:
                        brand_impersonation_detected = True
                        findings.append(
                            f"Brand name '{trusted}' used as a subdomain of an unrelated domain."
                        )
                        risk_score += 25
                        break

        # Final score and status
        findings = list(dict.fromkeys(findings))
        informational_findings = list(dict.fromkeys(informational_findings))
        risk_score = min(max(risk_score, 0), 100)

        if risk_score == 0:
            status = "Safe"
        elif risk_score < 15:
            status = "Low"
        elif risk_score < 45:
            status = "Medium"
        elif risk_score < 70:
            status = "High"
        else:
            status = "Critical"

        if verbose:
            print(
                f"[URL] {url} | domain={registered} | risk={risk_score} "
                f"| typosquat={typosquatting_detected} "
                f"| brand={brand_impersonation_detected}"
            )

        return {
            "url": url,
            "domain": registered,
            "risk_score": risk_score,
            "status": status,
            "findings": findings,
            "informational_findings": informational_findings,
        }
