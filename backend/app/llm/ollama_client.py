import requests

from app.config import settings
from app.logger import logger


class OllamaError(RuntimeError):
    """Raised with a readable message when Ollama cannot answer."""


class OllamaClient:
    """
    Small client for Ollama's /api/chat endpoint.

    num_ctx and num_gpu are sent with every request, so memory use can be
    tuned from .env without restarting the Ollama server (OLLAMA_NUM_GPU=0
    runs the model on the CPU).
    """

    def _options(self):
        options = {"num_ctx": settings.OLLAMA_NUM_CTX, "temperature": 0.2}
        if settings.OLLAMA_NUM_GPU is not None:
            options["num_gpu"] = settings.OLLAMA_NUM_GPU
        return options

    def generate(self, prompt, json_mode=True):

        url = f"{settings.OLLAMA_HOST}/api/chat"

        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": False,
            "keep_alive": settings.OLLAMA_KEEP_ALIVE,
            "options": self._options(),
        }

        if json_mode:
            payload["format"] = "json"

        logger.info(
            "Ollama request: model=%s host=%s options=%s",
            settings.OLLAMA_MODEL, settings.OLLAMA_HOST, payload["options"],
        )

        try:
            response = requests.post(url, json=payload, timeout=settings.OLLAMA_TIMEOUT)
        except requests.ConnectionError as exc:
            raise OllamaError(
                f"Cannot connect to Ollama at {settings.OLLAMA_HOST}. Is 'ollama serve' running?"
            ) from exc
        except requests.Timeout as exc:
            raise OllamaError(
                f"Ollama did not answer within {settings.OLLAMA_TIMEOUT}s."
            ) from exc

        logger.info("Ollama HTTP status: %s", response.status_code)

        if not response.ok:
            detail = response.text.strip()
            try:
                detail = response.json().get("error", detail)
            except ValueError:
                pass

            logger.error("Ollama error response: %s", detail)

            hint = ""
            if "out of memory" in detail.lower() or "mem_buffer" in detail:
                hint = (
                    " Hint: free RAM/VRAM (close other apps) or set OLLAMA_NUM_GPU=0 "
                    "in backend/.env to run on CPU, and keep OLLAMA_NUM_CTX at 2048."
                )
            elif "not found" in detail.lower():
                hint = f" Hint: run 'ollama pull {settings.OLLAMA_MODEL}'."

            raise OllamaError(f"Ollama returned HTTP {response.status_code}: {detail}{hint}")

        data = response.json()
        return data.get("message", {}).get("content", "")

    def health(self):
        """Return a dict describing whether Ollama and the model are available."""
        try:
            response = requests.get(f"{settings.OLLAMA_HOST}/api/tags", timeout=5)
            response.raise_for_status()
        except requests.RequestException as exc:
            return {"ollama_reachable": False, "model_installed": False, "error": str(exc)}

        models = [m.get("name", "") for m in response.json().get("models", [])]
        return {
            "ollama_reachable": True,
            "model": settings.OLLAMA_MODEL,
            "model_installed": settings.OLLAMA_MODEL in models,
            "installed_models": models,
            "options": self._options(),
        }
