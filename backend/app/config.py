import os

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Settings:

    # ------------------------------------------------------------------
    # Local LLM (Ollama)
    # ------------------------------------------------------------------

    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:4b")

    OLLAMA_TIMEOUT = _env_int("OLLAMA_TIMEOUT", 180)

    # Smaller context = less memory. 2048 tokens is enough for the
    # compact prompt built by PromptBuilder and fits a 4 GB GPU.
    OLLAMA_NUM_CTX = _env_int("OLLAMA_NUM_CTX", 2048)

    # Number of model layers to put on the GPU.
    #   unset -> let Ollama decide (default)
    #   0     -> CPU only (use this if you get "cudaMalloc failed: out of memory")
    #   e.g. 20 -> partial GPU offload
    OLLAMA_NUM_GPU = _env_int("OLLAMA_NUM_GPU", None)

    OLLAMA_KEEP_ALIVE = os.getenv("OLLAMA_KEEP_ALIVE", "5m")

    # Turn the AI narrative off completely (e.g. for batch evaluation).
    ENABLE_AI_REPORT = _env_bool("ENABLE_AI_REPORT", True)

    # ------------------------------------------------------------------
    # Network enrichment
    # ------------------------------------------------------------------

    ENABLE_NETWORK_LOOKUPS = _env_bool("ENABLE_NETWORK_LOOKUPS", True)

    WHOIS_TIMEOUT = _env_int("WHOIS_TIMEOUT", 5)

    DNS_TIMEOUT = _env_int("DNS_TIMEOUT", 3)

    # Only look up this many distinct link domains per email (the most
    # suspicious first). Newsletters can contain 100+ links.
    MAX_DOMAIN_LOOKUPS = _env_int("MAX_DOMAIN_LOOKUPS", 5)

    # ------------------------------------------------------------------
    # Threat intelligence (VirusTotal free tier: 4 requests/minute)
    # ------------------------------------------------------------------

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

    ENABLE_THREAT_INTEL = _env_bool("ENABLE_THREAT_INTEL", True)

    MAX_TI_LOOKUPS = _env_int("MAX_TI_LOOKUPS", 4)

    # Free tier: 4 requests/minute. Raise this if you have a paid key.
    VT_REQUESTS_PER_MINUTE = _env_int("VT_REQUESTS_PER_MINUTE", 4)

    # Longest a single lookup may wait for a free slot before it is
    # reported as "unknown" (keeps one email from hanging for minutes).
    VT_MAX_WAIT_SECONDS = _env_int("VT_MAX_WAIT_SECONDS", 65)

    # After HTTP 429 (quota reached) stop calling VirusTotal for this long.
    VT_PAUSE_AFTER_429 = _env_int("VT_PAUSE_AFTER_429", 120)


settings = Settings()
