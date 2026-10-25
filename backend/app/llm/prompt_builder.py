import json


class PromptBuilder:
    """
    Builds a short prompt for the AI report.

    Only the verdict, the top findings and the score breakdown are sent,
    which keeps the prompt small enough for a 4 GB GPU. The model is told
    that the verdict is final.
    """

    MAX_FINDINGS = 12

    def build(self, evidence, verdict, mitre=None):

        facts = {
            "verdict": verdict.get("verdict"),
            "risk_score": verdict.get("risk_score"),
            "confidence": verdict.get("confidence"),
            "reasons": verdict.get("reasons", [])[:6],
            "key_findings": evidence.get("findings", [])[: self.MAX_FINDINGS],
            "score_breakdown": evidence.get("score_breakdown", {}),
            "checks_unavailable": evidence.get("unavailable_checks", []),
            "mitre_attack": [
                f"{t.get('id')} {t.get('name')}" for t in (mitre or [])
            ],
        }

        prompt = f"""You are a cybersecurity analyst writing a short report for a non-expert.

A deterministic rules engine has ALREADY analysed an email. Its verdict is final.
Do NOT change the verdict or risk score and do NOT invent findings that are not listed.
If some checks were unavailable, say that their result is unknown.

Analysis facts:
{json.dumps(facts, indent=2, default=str)}

Respond with ONLY a JSON object in exactly this format:
{{
  "summary": "2-4 sentences explaining the verdict in plain language",
  "recommendations": ["3 to 5 short, concrete actions for the recipient"]
}}
"""

        return prompt
