class AttackNarrativeBuilder:
    """
    Short, rule-based description of what the evidence shows.
    Emails with no findings get a plain "nothing suspicious" sentence.
    """

    def build(self, email, evidence):

        url_count = evidence.get("url_count", 0)
        suspicious = evidence.get("suspicious_url_count", 0)
        brand = evidence.get("brand_risk_score", 0)
        header = evidence.get("header_risk_score", 0)
        content = evidence.get("content_risk_score", 0)
        whois = evidence.get("whois_risk_score", 0)
        dns = evidence.get("dns_risk_score", 0)
        indicators = email.get("content_analysis", {}).get("indicators", {})

        if brand > 0 and (suspicious or indicators.get("credential_request")):
            attack_type = "Credential Phishing"
        elif indicators.get("credential_request") or indicators.get("account_threat"):
            attack_type = "Account Takeover / Credential Request"
        elif indicators.get("financial_lure"):
            attack_type = "Scam / Financial Lure"
        elif suspicious:
            attack_type = "Malicious or Suspicious Link"
        elif header > 0:
            attack_type = "Sender Spoofing / Header Anomaly"
        else:
            attack_type = "No Clear Attack Pattern"

        narrative = []

        if url_count:
            if suspicious:
                narrative.append(
                    f"The email contains {url_count} URL(s), {suspicious} of which "
                    "show suspicious characteristics."
                )
            else:
                narrative.append(
                    f"The email contains {url_count} URL(s); none were rated suspicious."
                )
        else:
            narrative.append("The email contains no web links.")

        if brand > 0:
            narrative.append("It references a trusted brand that does not match the sender or link destinations.")
        if header > 0:
            narrative.append("The sender headers show anomalies (for example Reply-To redirection or failed authentication).")
        if content > 0:
            narrative.append("The message text uses social-engineering techniques such as pressure, credential requests or financial lures.")
        if whois > 0:
            narrative.append("At least one link domain was registered very recently.")
        if dns > 0:
            narrative.append("At least one link domain does not exist in DNS.")

        return {
            "attack_type": attack_type,
            "narrative": " ".join(narrative),
        }
