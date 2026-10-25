import re

from email.utils import parseaddr

from app.services import domain_utils


def parseaddr_safe(value):
    try:
        return parseaddr(str(value or ""))
    except Exception:
        return ("", "")


def looks_random(local):
    """
    Heuristic for machine-generated mailbox names: 8+ characters, no
    separators, and either upper-case letters mixed with 2+ digits
    (AD8XWZK55Q) or 3+ lower-to-upper case switches (drwaTdStM).
    Names such as john.smith, noreply, newsletter2024 do not match.
    """
    if not local or len(local) < 8 or len(local) > 24 or re.search(r"[._+-]", local):
        return False
    digits = sum(c.isdigit() for c in local)
    letters = sum(c.isalpha() for c in local)
    if local.isupper() and digits >= 2 and letters >= 3:
        return True
    switches = sum(1 for a, b in zip(local, local[1:]) if a.isalpha() and b.isalpha() and a.islower() and b.isupper())
    return switches >= 3


class HeaderAnalyzer:
    """
    Sender and header anomaly checks.

    - Reply-To on a different registered domain (mailing lists are exempt),
      with extra points when replies go to a free webmail inbox
    - display-name spoofing, e.g. "PayPal <x@unrelated.com>"
    - a fake reply: "RE:" subject without In-Reply-To or References
    - SPF / DKIM / DMARC failures from Authentication-Results
    """

    MAX_SCORE = 60

    def extract_domain(self, email_address):
        return domain_utils.address_domain(email_address)

    def is_mailing_list(self, email_data):
        precedence = (email_data.get("precedence") or "").lower()
        return bool(
            email_data.get("list_id")
            or email_data.get("list_unsubscribe")
            or precedence in {"list", "bulk"}
        )

    def analyze(self, email_data):

        findings = []
        notes = []
        score = 0

        from_value = email_data.get("from", "")
        reply_value = email_data.get("reply_to", "")
        subject = (email_data.get("subject") or "").strip()

        from_domain = self.extract_domain(from_value)
        reply_domain = self.extract_domain(reply_value)
        mailing_list = self.is_mailing_list(email_data)

        reply_to_status = "Not Present"

        # Sender domain missing
        if not from_domain:
            findings.append("Sender domain could not be determined.")
            score += 15

        # Reply-To mismatch
        if reply_domain:
            reply_to_status = "Present"

            if from_domain and not domain_utils.same_organisation(from_domain, reply_domain):
                reply_to_status = "Mismatch"

                if mailing_list:
                    notes.append(
                        "Reply-To differs from sender, but the message is "
                        "mailing-list traffic (normal for lists)."
                    )
                else:
                    findings.append("Reply-To domain differs from sender domain.")
                    score += 20

                    reply_registered = domain_utils.registered_domain(reply_domain)
                    from_registered = domain_utils.registered_domain(from_domain)

                    if (
                        reply_registered in domain_utils.FREE_MAIL_DOMAINS
                        and from_registered not in domain_utils.FREE_MAIL_DOMAINS
                    ):
                        findings.append(
                            "Replies are redirected to a free webmail address."
                        )
                        score += 10

        # Display-name spoofing: the visible name contains an address
        # on a different domain than the real sender.
        name = domain_utils.display_name(from_value)
        embedded = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
        if embedded and from_domain and not domain_utils.same_organisation(
            embedded.group(1), from_domain
        ):
            findings.append(
                "Sender display name shows a different email address than the real sender."
            )
            score += 25

        # Randomly generated sender address (e.g. AD8XWZK55Q@..., drwaTdStM@...)
        local = ""
        _, addr = parseaddr_safe(from_value)
        if "@" in addr:
            local = addr.split("@", 1)[0]
        if looks_random(local):
            findings.append("Sender address looks randomly generated.")
            score += 10

        # Fake reply / forward
        if re.match(r"^(re|fw|fwd)\s*:", subject, re.I) and not (
            email_data.get("in_reply_to") or email_data.get("references")
        ):
            findings.append(
                "Subject looks like a reply or forward, but the message is not part of a thread."
            )
            score += 10

        # Authentication results (present in modern mail)
        auth = " ".join([
            email_data.get("authentication_results") or "",
            email_data.get("received_spf") or "",
        ]).lower()

        auth_failures = []
        for mechanism in ("spf", "dkim", "dmarc"):
            if re.search(rf"\b{mechanism}\s*=\s*(fail|permerror)", auth):
                auth_failures.append(mechanism.upper())

        if auth.startswith("fail") or "received-spf: fail" in auth:
            if "SPF" not in auth_failures:
                auth_failures.append("SPF")

        auth_score = 0
        if auth_failures:
            findings.append(
                f"Sender authentication failed: {', '.join(auth_failures)}."
            )
            auth_score = 25 if len(auth_failures) == 1 else 40
            score += auth_score

        elif re.search(r"\bspf\s*=\s*softfail", auth):
            findings.append("SPF soft-fail for the sender domain.")
            score += 10

        return {
            "risk_score": min(score, self.MAX_SCORE),
            "sender_domain": from_domain,
            "reply_domain": reply_domain,
            "reply_to_status": reply_to_status,
            "mailing_list": mailing_list,
            "auth_failures": auth_failures,
            "auth_score": auth_score,
            "findings": findings,
            "notes": notes,
        }
