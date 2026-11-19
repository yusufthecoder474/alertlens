"""Configuration: the ONE place that reads environment variables.

Every other module reads settings through ``api.config.settings`` — no
``os.environ`` reads elsewhere in ``api/``. ``ENV`` defaults to ``dev``;
in any other environment the API key is mandatory and the process fails
fast at import time rather than starting with a guessable default key.
"""
import os

_PLACEHOLDER_KEYS = {"", "change-me", "dev-api-key-change-me", "your-api-key-here",
                     "change-me-in-production"}


def _int(name: str, default: int) -> int:
    """Read an int env var, falling back to ``default`` on bad input."""
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    """Read a float env var, falling back to ``default`` on bad input."""
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class Settings:
    """All runtime settings, read from the environment on each access.

    Properties (not import-time constants) so tests can override env vars
    with ``monkeypatch.setenv`` and the change takes effect immediately.
    """

    @property
    def env(self) -> str:
        return os.environ.get("ENV", "dev").lower()

    @property
    def api_key(self) -> str:
        return os.environ.get("API_KEY", "")

    @property
    def database_url(self) -> str:
        return os.environ.get("DATABASE_URL", "sqlite:///./alertlens.db")

    @property
    def dedup_window_seconds(self) -> int:
        return _int("DEDUP_WINDOW_SECONDS", 300)

    @property
    def correlation_window_seconds(self) -> int:
        return _int("CORRELATION_WINDOW_SECONDS", 3600)

    @property
    def recall_target(self) -> float:
        return _float("RECALL_TARGET", 0.95)

    @property
    def rate_limit_per_minute(self) -> int:
        return _int("RATE_LIMIT_PER_MINUTE", 60)

    @property
    def llm_enabled(self) -> bool:
        return os.environ.get("LLM_ENABLED", "false").lower() == "true"

    @property
    def openai_api_key(self) -> str:
        return os.environ.get("OPENAI_API_KEY", "")

    @property
    def model_path(self) -> str:
        return os.environ.get("MODEL_PATH", "models/model.pkl")

    @property
    def threshold_path(self) -> str:
        return os.environ.get("THRESHOLD_PATH", "models/threshold.json")

    def validate(self) -> None:
        """Fail fast: a non-dev environment without a real API key is an error."""
        if self.env != "dev" and self.api_key.strip().lower() in _PLACEHOLDER_KEYS:
            raise RuntimeError(
                "API_KEY is unset (or still a placeholder) and ENV != 'dev'. "
                "Set a real API_KEY in the environment before starting."
            )


settings = Settings()
settings.validate()
