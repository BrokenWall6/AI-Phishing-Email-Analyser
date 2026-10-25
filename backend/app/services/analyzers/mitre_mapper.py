class MitreMapper:

    def analyze(self, email):

        techniques = []

        evidence = email.get("evidence", {})

        suspicious_url_count = evidence.get(
            "suspicious_url_count",
            0
        )

        brand_risk = evidence.get(
            "brand_risk_score",
            0
        )

        whois_risk = evidence.get(
            "whois_risk_score",
            0
        )

        dns_risk = evidence.get(
            "dns_risk_score",
            0
        )

        url_risk = evidence.get(
            "url_risk_score",
            0
        )

        content_indicators = (
            email.get("content_analysis", {}).get("indicators", {})
        )

        # ==================================================
        # T1566.002 - Spearphishing Link
        # ==================================================

        if suspicious_url_count > 0:

            techniques.append({
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "reason": (
                    "The email contains a URL with suspicious "
                    "characteristics."
                )
            })

        # ==================================================
        # T1036 - Masquerading
        # ==================================================

        if brand_risk > 0:

            techniques.append({
                "id": "T1036",
                "name": "Masquerading",
                "reason": (
                    "The email references a trusted brand while "
                    "directing the recipient to an unrelated domain."
                )
            })

        # ==================================================
        # T1204.001 - User Execution: Malicious Link
        # ==================================================

        if (
            suspicious_url_count > 0
            and (
                url_risk >= 20
                or brand_risk > 0
            )
        ):

            techniques.append({
                "id": "T1204.001",
                "name": "User Execution: Malicious Link",
                "reason": (
                    "The phishing scenario relies on the recipient "
                    "interacting with a suspicious link."
                )
            })

        # ==================================================
        # T1598 - Phishing for Information
        # (asks the victim to send credentials / personal data)
        # ==================================================

        if content_indicators.get("credential_request"):

            techniques.append({
                "id": "T1598",
                "name": "Phishing for Information",
                "reason": (
                    "The message asks the recipient to provide or verify "
                    "credentials or personal information."
                )
            })

        # ==================================================
        # Infrastructure Evidence
        # ==================================================
        #
        # Do NOT automatically map T1583.001 from a failed WHOIS
        # lookup. WHOIS/DNS anomalies are supporting evidence but
        # do not prove that the attacker acquired infrastructure.
        #
        # We only map the technique when there is stronger
        # infrastructure evidence available.
        # ==================================================

        infrastructure_evidence = (
            whois_risk >= 30
            and (dns_risk > 0 or suspicious_url_count > 0)
        )

        if infrastructure_evidence:

            techniques.append({
                "id": "T1583.001",
                "name": "Acquire Infrastructure: Domains",
                "reason": (
                    "The destination domain exhibits multiple "
                    "infrastructure risk indicators."
                )
            })

        return techniques