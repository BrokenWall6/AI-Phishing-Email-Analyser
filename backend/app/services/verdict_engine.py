from app.services.evidence_builder import SUSPICIOUS_FLOOR, count_signals


class VerdictEngine:
    """Turns the evidence record into a verdict, a score and a confidence level."""

    def calculate(self, evidence):

        score = evidence.get("overall_risk_score", 0)

        brand_risk = evidence.get("brand_risk_score", 0)
        suspicious_urls = evidence.get("suspicious_url_count", 0)
        whois_risk = evidence.get("whois_risk_score", 0)
        dns_risk = evidence.get("dns_risk_score", 0)
        header_risk = evidence.get("header_risk_score", 0)
        content_risk = evidence.get("content_risk_score", 0)
        threat_intelligence_risk = evidence.get("threat_intelligence_risk_score", 0)
        url_risk = evidence.get("url_risk_score", 0)

        reasons = []

        if brand_risk > 0:
            reasons.append("Brand impersonation or brand-domain mismatch detected.")
        if suspicious_urls > 0:
            reasons.append("One or more URLs contain suspicious characteristics.")
        if content_risk > 0:
            reasons.append("Message content uses social-engineering or scam techniques.")
        if whois_risk > 0:
            reasons.append("WHOIS analysis identified a recently registered domain.")
        if dns_risk > 0:
            reasons.append("DNS analysis found a link domain that does not exist.")
        if header_risk > 0:
            reasons.append("Email authentication or sender-header anomalies detected.")
        if threat_intelligence_risk > 0:
            reasons.append("Threat intelligence identified risk indicators for extracted IOCs.")

        if brand_risk >= 30 and (
            header_risk >= 20 or whois_risk >= 30 or suspicious_urls > 0 or content_risk >= 20
        ):
            score = max(score, 70)
            reasons.append(
                "Brand impersonation is supported by additional email, domain, "
                "content or infrastructure risk indicators."
            )

        if brand_risk > 0 and header_risk >= 30:
            score = max(score, 75)
            reasons.append("Brand impersonation combined with sender authentication anomalies.")

        if threat_intelligence_risk >= 40:
            score = max(score, 75)
            reasons.append(
                "Threat intelligence identified malicious indicators associated "
                "with the email infrastructure."
            )

        auth_failed = evidence.get("auth_failed", False)

        signals = count_signals({
            "suspicious_url_count": suspicious_urls,
            "brand": brand_risk,
            "header": header_risk,
            "header_other": evidence.get("header_other_risk_score", header_risk),
            "auth": auth_failed,
            "content": content_risk,
            "threat_intelligence": threat_intelligence_risk,
            "whois": whois_risk,
            "dns": dns_risk,
        })
        signal_count = len(signals)

        if signal_count >= 3:
            score = max(score, 70)
            reasons.append("Multiple independent security signals support the classification.")

        if evidence.get("brand_sender_claim"):
            score = max(score, SUSPICIOUS_FLOOR)
            reasons.append("The sender pretends to be a brand it does not belong to.")

        other_evidence = max(
            url_risk, content_risk, brand_risk, whois_risk, dns_risk,
            threat_intelligence_risk, evidence.get("header_other_risk_score", 0),
        )
        if auth_failed and other_evidence >= 10:
            score = max(score, SUSPICIOUS_FLOOR)
            reasons.append("Sender authentication failed and other evidence agrees.")

        infrastructure_only = (
            (whois_risk > 0 or dns_risk > 0)
            and brand_risk == 0 and suspicious_urls == 0 and url_risk == 0
            and header_risk == 0 and content_risk == 0
            and threat_intelligence_risk == 0
        )
        if infrastructure_only:
            score = min(score, 30)

        score = min(max(score, 0), 100)

        if score >= 70:
            verdict, confidence = "Phishing", "High"
        elif score >= 45:
            verdict, confidence = "Suspicious", "Medium"
        elif score >= 20:
            verdict, confidence = "Low Risk", "Low"
        else:
            verdict, confidence = "Benign", "High"

        # Lower confidence when key checks could not run.
        unavailable = evidence.get("unavailable_checks", [])
        if unavailable and confidence == "High" and verdict == "Benign" and score > 0:
            confidence = "Medium"

        return {
            "verdict": verdict,
            "risk_score": score,
            "confidence": confidence,
            "signal_count": signal_count,
            "reasons": list(dict.fromkeys(reasons)),
        }
