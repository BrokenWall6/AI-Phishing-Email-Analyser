import json
import re

from app.llm.ollama_client import OllamaClient, OllamaError
from app.llm.prompt_builder import PromptBuilder
from app.logger import logger


class LLMService:
    """
    Produces the AI-written summary and recommendations.

    Always returns the same shape, so the dashboard can tell a real answer
    from a fallback:
        {"status": "generated" | "unavailable" | "unparseable",
         "summary": str, "recommendations": [str], "error": str (optional)}
    """

    def __init__(self):
        self.builder = PromptBuilder()
        self.client = OllamaClient()

    def analyze(self, evidence, verdict, mitre=None):

        prompt = self.builder.build(evidence, verdict, mitre=mitre)

        try:
            response = self.client.generate(prompt)
        except OllamaError as exc:
            logger.warning("AI report unavailable: %s", exc)
            return self._fallback(
                "unavailable",
                "AI report unavailable because the local LLM could not generate a response.",
                str(exc),
            )
        except Exception as exc:  # never let the AI layer break the analysis
            logger.exception("Unexpected LLM failure")
            return self._fallback(
                "unavailable",
                "AI report unavailable because of an unexpected error.",
                str(exc),
            )

        parsed = self._parse(response)

        if parsed is None:
            logger.warning("Could not parse LLM output: %s", response[:500])
            return self._fallback(
                "unparseable",
                "The local LLM answered, but its output could not be parsed.",
                response[:500],
            )

        return parsed

    # ------------------------------------------------------------------

    @staticmethod
    def _parse(response):

        if not response:
            return None

        # Some models wrap JSON in <think> blocks or ``` fences.
        cleaned = re.sub(r"(?s)<think>.*?</think>", "", response)
        cleaned = re.sub(r"```(?:json)?", "", cleaned).strip()

        data = None
        try:
            data = json.loads(cleaned)
        except ValueError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except ValueError:
                    data = None

        if not isinstance(data, dict):
            return None

        summary = data.get("summary")
        recommendations = data.get("recommendations", [])

        if isinstance(recommendations, str):
            recommendations = [recommendations]

        if not isinstance(summary, str) or not summary.strip():
            return None

        return {
            "status": "generated",
            "summary": summary.strip(),
            "recommendations": [str(r).strip() for r in recommendations if str(r).strip()][:6],
        }

    @staticmethod
    def _fallback(status, summary, error):
        return {
            "status": status,
            "summary": summary,
            "recommendations": [
                "Use the security verdict and evidence as the primary assessment.",
                "Check that Ollama is running and the configured model can load (see /llm-health).",
            ],
            "error": error,
        }
