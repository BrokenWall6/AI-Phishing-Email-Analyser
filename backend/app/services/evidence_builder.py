"""
Combines the analyzer results into one evidence record and a risk score.

Rules of thumb used here:
- Each component score is capped, so one area cannot decide the verdict alone.
- URL risk is the worst link plus a small bonus for extra suspicious links,
  not a sum (a newsletter with 80 harmless links should stay low).
- WHOIS and DNS are supporting evidence. A failed lookup scores 0 and is
  listed in unavailable_checks, never treated as risky or as clean.
- count_signals() is shared with VerdictEngine so the two always agree on
  what counts as an independent signal.
"""

SUSPICIOUS_URL_THRESHOLD = 15

# lowest score that gives a Suspicious verdict
SUSPICIOUS_FLOOR = 45

CAPS = {
    "url": 40,
    "whois": 30,
    "dns": 20,
    "header": 40,
    "brand": 50,
    "content": 40,
    "threat_intelligence": 40,
}


def count_signals(scores):
    """
    Independent evidence categories that are strong enough to count.

    `scores` needs: suspicious_url_count, brand, header, content,
    threat_intelligence, whois, dns. Optional: auth (sender authentication
    failed) and header_other (header points that are not from auth).
    """
    signals = []

    if scores.get("suspicious_url_count", 0) > 0:
        signals.append("url")
    if scores.get("brand", 0) > 0:
        signals.append("brand")
    if scores.get("header_other", scores.get("header", 0)) >= 20:
        signals.append("header")
    if scores.get("auth"):
        signals.append("auth")
    if scores.get("content", 0) >= 20:
        signals.append("content")
    if scores.get("threat_intelligence", 0) >= 20:
        signals.append("threat_intelligence")

    # Infrastructure counts only for strong findings.
    if scores.get("whois", 0) >= 30:
        signals.append("whois")
    if scores.get("dns", 0) >= 20 and "url" not in signals:
        signals.append("dns")

    return signals


class EvidenceBuilder:

    def build(self, email):

        url_analysis = email.get("url_analysis", []) or []
        whois_analysis = email.get("whois_analysis", []) or []
        dns_analysis = email.get("dns_analysis", []) or []
        header_analysis = email.get("header_analysis", {}) or {}
        brand_analysis = email.get("brand_analysis", {}) or {}
        content_analysis = email.get("content_analysis", {}) or {}
        threat_intelligence = email.get("threat_intelligence", {}) or {}

        findings = []

        # ------------------------------------------------------------
        # Component scores
        # ------------------------------------------------------------

        url_scores = sorted(
            (item.get("risk_score", 0) for item in url_analysis), reverse=True
        )
        suspicious_url_count = sum(
            1 for score in url_scores if score >= SUSPICIOUS_URL_THRESHOLD
        )

        url_score = url_scores[0] if url_scores else 0
        if suspicious_url_count > 1:
            url_score += 5 * min(suspicious_url_count - 1, 3)

        whois_score = max((i.get("risk_score", 0) for i in whois_analysis), default=0)
        dns_score = max((i.get("risk_score", 0) for i in dns_analysis), default=0)

        header_score = header_analysis.get("risk_score", 0)
        auth_failed = bool(header_analysis.get("auth_failures"))
        header_other_score = max(header_score - header_analysis.get("auth_score", 0), 0)
        brand_score = brand_analysis.get("risk_score", 0)
        sender_claim = bool(brand_analysis.get("sender_claim"))
        content_score = content_analysis.get("risk_score", 0)
        threat_intelligence_score = threat_intelligence.get("risk_score", 0)

        # ------------------------------------------------------------
        # Findings (only from scored items, so the report matches the score)
        # ------------------------------------------------------------

        for item in url_analysis:
            if item.get("risk_score", 0) >= SUSPICIOUS_URL_THRESHOLD:
                findings.extend(item.get("findings", []))

        for item in whois_analysis + dns_analysis:
            findings.extend(item.get("findings", []))

        for component in (brand_analysis, header_analysis, content_analysis, threat_intelligence):
            findings.extend(component.get("findings", []))

        findings = list(dict.fromkeys(findings))

        # ------------------------------------------------------------
        # Capped base score
        # ------------------------------------------------------------

        capped = {
            "url": min(url_score, CAPS["url"]),
            "whois": min(whois_score, CAPS["whois"]),
            "dns": min(dns_score, CAPS["dns"]),
            "header": min(header_score, CAPS["header"]),
            "brand": min(brand_score, CAPS["brand"]),
            "content": min(content_score, CAPS["content"]),
            "threat_intelligence": min(threat_intelligence_score, CAPS["threat_intelligence"]),
        }

        base_score = sum(capped.values())

        signals = count_signals({
            "suspicious_url_count": suspicious_url_count,
            "brand": brand_score,
            "header": header_score,
            "header_other": header_other_score,
            "auth": auth_failed,
            "content": content_score,
            "threat_intelligence": threat_intelligence_score,
            "whois": whois_score,
            "dns": dns_score,
        })
        signal_count = len(signals)

        contextual_reasons = []
        contextual_bonus = min(10 * max(signal_count - 1, 0), 20)

        if contextual_bonus:
            contextual_reasons.append(
                f"{signal_count} independent evidence categories agree "
                f"({', '.join(signals)})."
            )

        overall_risk_score = base_score + contextual_bonus

        if signal_count >= 3:
            overall_risk_score = max(overall_risk_score, 70)
            contextual_reasons.append("Multiple independent security signals detected.")

        if brand_score >= 30 and (
            header_score >= 20 or suspicious_url_count > 0
            or content_score >= 20 or whois_score >= 30
        ):
            overall_risk_score = max(overall_risk_score, 70)
            contextual_reasons.append(
                "Brand impersonation is supported by additional security evidence."
            )

        if brand_score > 0 and header_score >= 30:
            overall_risk_score = max(overall_risk_score, 75)
            contextual_reasons.append(
                "Brand impersonation combined with a strong sender anomaly."
            )

        if threat_intelligence_score >= 40:
            overall_risk_score = max(overall_risk_score, 75)
            contextual_reasons.append("Threat intelligence identified high-risk indicators.")

        # Pretending to be a known brand is suspicious even without other evidence.
        if sender_claim:
            overall_risk_score = max(overall_risk_score, SUSPICIOUS_FLOOR)
            contextual_reasons.append("The sender pretends to be a brand it does not belong to.")

        # Failed authentication alone happens with legitimate mail (forwarding,
        # misconfigured senders). Together with another real finding it is
        # worth a closer look. Plain HTTP (5 points) is too weak to count.
        other_evidence = max(
            url_score, content_score, brand_score, header_other_score,
            whois_score, dns_score, threat_intelligence_score,
        )
        if auth_failed and other_evidence >= 10:
            overall_risk_score = max(overall_risk_score, SUSPICIOUS_FLOOR)
            contextual_reasons.append("Sender authentication failed and other evidence agrees.")

        infrastructure_only = (
            (whois_score > 0 or dns_score > 0)
            and suspicious_url_count == 0 and url_score == 0
            and brand_score == 0 and header_score == 0
            and content_score == 0 and threat_intelligence_score == 0
        )
        if infrastructure_only:
            overall_risk_score = min(overall_risk_score, 30)

        overall_risk_score = min(max(overall_risk_score, 0), 100)

        # ------------------------------------------------------------
        # Human-readable summary
        # ------------------------------------------------------------

        evidence_summary = []
        labels = [
            ("URL analysis", url_score), ("Brand analysis", brand_score),
            ("Header analysis", header_score), ("Content analysis", content_score),
            ("WHOIS analysis", whois_score), ("DNS analysis", dns_score),
            ("Threat intelligence", threat_intelligence_score),
        ]
        for label, score in labels:
            if score > 0:
                evidence_summary.append(f"{label} contributed {score} risk points.")
        evidence_summary.extend(contextual_reasons)
        evidence_summary = list(dict.fromkeys(evidence_summary))

        # What could not be checked (so "no finding" is not read as "safe").
        unavailable_checks = []
        if any(i.get("status") == "unavailable" for i in whois_analysis):
            unavailable_checks.append("WHOIS")
        if any(i.get("status") == "unavailable" for i in dns_analysis):
            unavailable_checks.append("DNS")
        if threat_intelligence.get("status") in {"Unavailable", "Partial", "Not Configured", "Disabled"}:
            unavailable_checks.append(f"Threat intelligence ({threat_intelligence.get('status')})")

        score_breakdown = dict(capped)
        score_breakdown["contextual_bonus"] = contextual_bonus
        score_breakdown["final_score"] = overall_risk_score

        return {
            "overall_risk_score": overall_risk_score,
            "url_count": len(url_analysis),
            "suspicious_url_count": suspicious_url_count,
            "header_risk_score": header_score,
            "header_other_risk_score": header_other_score,
            "auth_failed": auth_failed,
            "brand_sender_claim": sender_claim,
            "whois_risk_score": whois_score,
            "dns_risk_score": dns_score,
            "brand_risk_score": brand_score,
            "content_risk_score": content_score,
            "threat_intelligence_risk_score": threat_intelligence_score,
            "url_risk_score": url_score,
            "findings": findings,
            "signal_count": signal_count,
            "signals": signals,
            "contextual_bonus": contextual_bonus,
            "score_breakdown": score_breakdown,
            "evidence_summary": evidence_summary,
            "unavailable_checks": unavailable_checks,
        }
