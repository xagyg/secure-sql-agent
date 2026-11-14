# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Runtime settings: config/settings/*.yaml
#
#   databases.yaml   which databases exist and how to reach them
#                    (loaded by sqlagent/databases.py)
#   llm.yaml         the Ollama server and model
#   api.yaml         public demo API: CORS, rate limits, concurrency, timeouts
#   query.yaml       limits applied to every generated query
#   retrieval.yaml   which authorised tables are shown to the LLM per
#                    question: Domain of Discourse routing, table matching
#   repl.yaml        the local command-line REPL (main.py)
#
# Precedence, highest first:
#   1. an environment variable (the names in ENV_OVERRIDES below - the
#      same names the project always used, so run scripts and deployments
#      keep working)
#   2. the YAML file
#   3. the default in the model below
#
# An environment variable that is set but empty counts as unset.
#
# Secrets are never stored in these files. A setting ending in _env names
# the environment variable that holds the secret (e.g. password_env:
# PG_PASSWORD), and a literal password/username key is rejected, so the
# file documents where the secret comes from without being able to hold
# it.
#
# Fail closed: a missing or invalid file, an unknown key, a value out of
# range or an override that doesn't parse raises SettingsError and
# startup stops. The folder can be moved with SQLAGENT_SETTINGS_DIR.

import os
from functools import lru_cache
from pathlib import Path

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from sqlagent.config_files import (
    CONFIG_DIR,
    ConfigFileError,
    format_validation_error,
    load_yaml,
)


DEFAULT_SETTINGS_DIR = CONFIG_DIR / "settings"

# Keys that would hold a secret. Rejected anywhere in a settings file.
SECRET_KEYS = {"password", "username", "secret", "token", "api_key"}


class SettingsError(ConfigFileError):
    """A settings file is missing or invalid, or an override doesn't parse."""


def settings_dir():
    return Path(os.environ.get("SQLAGENT_SETTINGS_DIR") or DEFAULT_SETTINGS_DIR)


def reject_secret_keys(data, where=""):
    """Raise ValueError if a mapping (at any depth) has a secret key."""
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{where}.{key}" if where else str(key)
            if str(key).lower() in SECRET_KEYS:
                raise ValueError(
                    f"{path}: secrets are never stored in configuration files; "
                    f"name the environment variable instead ({key}_env: VAR_NAME)")
            reject_secret_keys(value, path)
    elif isinstance(data, list):
        for i, value in enumerate(data):
            reject_secret_keys(value, f"{where}[{i}]")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _env_secret(name):
    return os.environ.get(name) if name else None


# ---------------------------------------------------------------------------
# llm.yaml
# ---------------------------------------------------------------------------

class LlmSettings(_Strict):
    host: str = Field("http://localhost:11434", min_length=1)
    model: str = Field(..., min_length=1)
    # Basic auth for a tunnelled Ollama (e.g. ngrok). The values come from
    # these environment variables; with either unset, no auth is sent.
    username_env: str | None = "OLLAMA_USERNAME"
    password_env: str | None = "OLLAMA_PASSWORD"
    connect_timeout: float = Field(10, gt=0, le=300)
    read_timeout: float = Field(120, gt=0, le=3600)
    # Earlier questions/answers sent with each new question.
    history_turns: int = Field(3, ge=0, le=50)
    # Each earlier turn carries a compact summary of its result, not the
    # full answer: this many sample rows, values cut to history_value_chars
    # and the whole summary to history_summary_chars.
    history_sample_rows: int = Field(3, ge=0, le=20)
    history_value_chars: int = Field(40, ge=8, le=500)
    history_summary_chars: int = Field(400, ge=50, le=4000)
    # How many of those turns (the most recent) also carry their SQL.
    # 0 sends none; a value above history_turns just means all of them.
    history_sql_turns: int = Field(1, ge=0, le=50)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("headers")
    @classmethod
    def _no_auth_header(cls, value):
        for name in value:
            if name.lower() in ("authorization", "proxy-authorization", "cookie"):
                raise ValueError(
                    f"header '{name}' would hold a secret; use username_env/password_env")
        return value

    def username(self):
        return _env_secret(self.username_env)

    def password(self):
        return _env_secret(self.password_env)


# ---------------------------------------------------------------------------
# api.yaml
# ---------------------------------------------------------------------------

class RateLimits(_Strict):
    session_per_minute: int = Field(4, ge=1)
    session_per_day: int = Field(40, ge=1)
    ip_per_minute: int = Field(10, ge=1)
    ip_per_day: int = Field(150, ge=1)


class ApiSettings(_Strict):
    allowed_origins: list[str] = Field(default_factory=list)
    trusted_proxy_hops: int = Field(1, ge=0, le=5)
    max_question_chars: int = Field(300, ge=1, le=5000)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    max_concurrency: int = Field(1, ge=1, le=64)
    agent_timeout: float = Field(120, gt=0, le=3600)
    queue_wait: float = Field(5, ge=0, le=600)
    max_slot_hold: float = Field(150, gt=0, le=7200)
    max_sessions: int = Field(2000, ge=1)
    audit_log: Path = Path("audit.log")

    @field_validator("allowed_origins")
    @classmethod
    def _origins(cls, value):
        cleaned = [o.strip() for o in value if o and o.strip()]
        for origin in cleaned:
            if origin == "*" or "*" in origin:
                raise ValueError("wildcard origins are not allowed; list each origin")
            if not origin.startswith(("http://", "https://")):
                raise ValueError(f"'{origin}' must start with http:// or https://")
        return cleaned

    @model_validator(mode="after")
    def _slot_hold(self):
        if self.max_slot_hold < self.agent_timeout:
            raise ValueError("max_slot_hold must be at least agent_timeout")
        return self


# ---------------------------------------------------------------------------
# query.yaml
# ---------------------------------------------------------------------------

class QuerySettings(_Strict):
    statement_timeout_seconds: int = Field(10, ge=1, le=300)
    max_rows: int = Field(1000, ge=1, le=100_000)
    max_result_bytes: int = Field(5_000_000, ge=1_000, le=100_000_000)
    # Most values one row-scope dimension may resolve to for one user
    # (security_policy.py). Above it the user's context isn't built.
    max_scope_values: int = Field(1000, ge=1, le=10_000)


# ---------------------------------------------------------------------------
# retrieval.yaml
# ---------------------------------------------------------------------------

class Weights(_Strict):
    what: float = Field(0.45, ge=0, le=1)
    where: float = Field(0.35, ge=0, le=1)
    who: float = Field(0.20, ge=0, le=1)

    @model_validator(mode="after")
    def _sum(self):
        total = self.what + self.where + self.who
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"weights must add up to 1 (they add up to {total:g})")
        return self


class TableMatch(_Strict):
    full_name: int = Field(20, ge=1)
    partial_name: int = Field(5, ge=0)
    column: int = Field(3, ge=0)

    @model_validator(mode="after")
    def _order(self):
        if not self.full_name > self.partial_name >= self.column:
            raise ValueError("expected full_name > partial_name >= column")
        return self


class TypoCorrection(_Strict):
    enabled: bool = True
    min_score: int = Field(85, ge=50, le=100)
    min_length: int = Field(5, ge=3)
    margin: int = Field(3, ge=0, le=50)


class DomainRouting(_Strict):
    weights: Weights = Field(default_factory=Weights)
    sticky_bonus: float = Field(0.10, ge=0, le=1)
    weak_evidence_follow_up: bool = True
    explicit_domain_points: int = Field(40, ge=0)
    where_phrase_points: int = Field(10, ge=0)
    min_domain_score: float = Field(0.25, ge=0, le=1)
    blend_margin: float = Field(0.15, ge=0, le=1)
    allow_who_tag: bool = False


class RetrievalSettings(_Strict):
    domains: DomainRouting = Field(default_factory=DomainRouting)
    table_match: TableMatch = Field(default_factory=TableMatch)
    typo_correction: TypoCorrection = Field(default_factory=TypoCorrection)


# ---------------------------------------------------------------------------
# repl.yaml
# ---------------------------------------------------------------------------

class ReplSettings(_Strict):
    user: str = Field("local", min_length=1)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

SECTIONS = {
    "llm": LlmSettings,
    "api": ApiSettings,
    "query": QuerySettings,
    "retrieval": RetrievalSettings,
    "repl": ReplSettings,
}


def _comma_list(text):
    return [part.strip() for part in text.split(",") if part.strip()]


# Environment variable -> (section, dotted key[, parser]).
ENV_OVERRIDES = {
    "OLLAMA_HOST":                  ("llm", "host"),
    "OLLAMA_MODEL":                 ("llm", "model"),
    "OLLAMA_CONNECT_TIMEOUT":       ("llm", "connect_timeout"),
    "OLLAMA_READ_TIMEOUT":          ("llm", "read_timeout"),
    "DEMO_ALLOWED_ORIGIN":          ("api", "allowed_origins", _comma_list),
    "DEMO_TRUSTED_PROXY_HOPS":      ("api", "trusted_proxy_hops"),
    "DEMO_MAX_QUESTION_CHARS":      ("api", "max_question_chars"),
    "DEMO_SESSION_RPM":             ("api", "rate_limits.session_per_minute"),
    "DEMO_SESSION_RPD":             ("api", "rate_limits.session_per_day"),
    "DEMO_IP_RPM":                  ("api", "rate_limits.ip_per_minute"),
    "DEMO_IP_RPD":                  ("api", "rate_limits.ip_per_day"),
    "DEMO_MAX_CONCURRENCY":         ("api", "max_concurrency"),
    "DEMO_AGENT_TIMEOUT":           ("api", "agent_timeout"),
    "DEMO_QUEUE_WAIT":              ("api", "queue_wait"),
    "DEMO_MAX_SLOT_HOLD":           ("api", "max_slot_hold"),
    "DEMO_MAX_SESSIONS":            ("api", "max_sessions"),
    "DEMO_AUDIT_LOG":               ("api", "audit_log"),
    "PG_STATEMENT_TIMEOUT_SECONDS": ("query", "statement_timeout_seconds"),
    "SQLAGENT_USER":                ("repl", "user"),
}


class Settings(_Strict):
    llm: LlmSettings
    api: ApiSettings
    query: QuerySettings
    retrieval: RetrievalSettings
    repl: ReplSettings
    source: Path
    overridden: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _cross_checks(self):
        # An abandoned request's query keeps running after the API gives
        # up on it, so the database timeout must end it first.
        if self.query.statement_timeout_seconds >= self.api.agent_timeout:
            raise ValueError(
                "query.statement_timeout_seconds must be below api.agent_timeout")
        return self


def _set_dotted(data, dotted, value):
    keys = dotted.split(".")
    for key in keys[:-1]:
        child = data.get(key)
        if not isinstance(child, dict):
            child = data[key] = {}
        data = child
    data[keys[-1]] = value


def _load_section(folder, name):
    path = folder / f"{name}.yaml"
    if not path.is_file():
        raise SettingsError(f"settings file not found: {path}")
    try:
        data = load_yaml(path)
        reject_secret_keys(data)
    except ConfigFileError as ex:
        raise SettingsError(str(ex)) from ex
    except ValueError as ex:
        raise SettingsError(f"{path}: {ex}") from ex
    return path, data


def load_settings(folder=None, environ=None):
    """Read, override and validate every settings file. No caching."""
    folder = Path(folder or settings_dir())
    environ = os.environ if environ is None else environ

    raw, paths = {}, {}
    for name in SECTIONS:
        paths[name], raw[name] = _load_section(folder, name)

    overridden = []
    for var, (section, dotted, *parser) in ENV_OVERRIDES.items():
        value = environ.get(var)
        if value is None or not value.strip():
            continue
        value = parser[0](value) if parser else value.strip()
        _set_dotted(raw[section], dotted, value)
        overridden.append(var)

    sections = {}
    for name, model in SECTIONS.items():
        try:
            sections[name] = model.model_validate(raw[name])
        except ValidationError as ex:
            message = format_validation_error(paths[name], ex)
            if overridden:
                message += ("\n  (environment overrides in effect: "
                            + ", ".join(overridden) + ")")
            raise SettingsError(message) from ex

    try:
        return Settings(source=folder, overridden=tuple(overridden), **sections)
    except ValidationError as ex:
        raise SettingsError(format_validation_error(folder, ex)) from ex


@lru_cache(maxsize=1)
def get_settings():
    """The settings this process runs with, read once and logged."""
    settings = load_settings()
    note = (f"; from environment: {', '.join(settings.overridden)}"
            if settings.overridden else "")
    print(f"[settings] {settings.source}{note}")
    return settings
