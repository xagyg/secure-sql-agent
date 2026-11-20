"""
Secure SQL Agent — public demo API
-----------------------------------
A thin, hardened HTTP wrapper around the existing agent.run_agent().

This does NOT reimplement any of the Agent Behavioural Controls
(structural safety, authorisation, rewriting, limits, result policy) —
those live in sqlagent/controls/ and run exactly as they do for the REPL.
This wrapper adds what public, anonymous traffic needs on top of that:
rate limiting, per-session conversation state (with a memory cap), a
fixed demo-only SecurityContext, request timeouts, concurrency limits,
and audit logging.

Run from the project root:
    uvicorn api:app --host 127.0.0.1 --port 8000 --workers 1

Keep --workers 1 (or move the in-memory rate limiter / session store to
Redis) — neither is shared across worker processes.

Deployment settings are in config/settings/api.yaml; the ones worth
checking first are trusted_proxy_hops (how many reverse proxies sit in
front of this process) and allowed_origins (only needed if the page is
served from a different origin). DEMO_* environment variables override
the file.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlagent.agent import run_agent
from sqlagent.log import request_context
from sqlagent.settings import get_settings
from sqlagent.databases import active_database
from sqlagent.execution.engines import active_engine
from sqlagent.controls.security_context import SecurityContext
from sqlagent.controls.security_policy import load_security_policy
from sqlagent.adaptive.schema_catalog import SchemaCatalog
from sqlagent.adaptive.semantic_model import load_semantic_model
from sqlagent.execution.sql_execution import get_connection, list_tables


# ==========================================================================
# Configuration — config/settings/api.yaml (explains each value). The
# DEMO_* environment variables override it; see sqlagent/settings.py.
# ==========================================================================

_API = get_settings().api

# Empty (the default) means same-origin only: the page calls this API via a
# relative URL, so no CORS is needed and none is enabled.
ALLOWED_ORIGINS = list(_API.allowed_origins)

# Number of reverse proxies in front of this process. See _client_ip().
TRUSTED_PROXY_HOPS = _API.trusted_proxy_hops

MAX_QUESTION_CHARS = _API.max_question_chars

# Per-session limits — a convenience bucket keyed on the browser-generated
# session_id the frontend sends. Not authentication; stops one tab from
# hammering the endpoint. The per-IP limit below is the real backstop.
SESSION_REQUESTS_PER_MINUTE = _API.rate_limits.session_per_minute
SESSION_REQUESTS_PER_DAY = _API.rate_limits.session_per_day

IP_REQUESTS_PER_MINUTE = _API.rate_limits.ip_per_minute
IP_REQUESTS_PER_DAY = _API.rate_limits.ip_per_day

# How many agent runs (i.e. Ollama calls) may be in flight at once, across
# every visitor combined — protects your GPU/CPU.
MAX_CONCURRENT_AGENT_RUNS = _API.max_concurrency

AGENT_TIMEOUT_SECONDS = _API.agent_timeout

# How long a request will wait for a free agent slot before being told the
# demo is busy (instead of queueing behind other visitors indefinitely).
QUEUE_WAIT_SECONDS = _API.queue_wait

# A timed-out request's worker thread can't be killed, so its slot stays
# taken until the thread really finishes. This caps how long a stuck thread
# (e.g. a hung model call) can keep a slot before it is released anyway.
MAX_SLOT_HOLD_SECONDS = _API.max_slot_hold

# How many distinct sessions' conversation history to keep in memory at
# once. Oldest sessions are evicted first — this bounds memory even if
# thousands of anonymous visitors show up. Per-conversation history length
# is history_turns in config/settings/llm.yaml.
MAX_TRACKED_SESSIONS = _API.max_sessions

AUDIT_LOG_PATH = str(_API.audit_log)


# ==========================================================================
# Demo SecurityContext — the active database's demo_roles (config/settings/databases.yaml),
# e.g. the "demo" role in config/databases/northwind/security.yaml.
#
# Every anonymous demo visitor gets this same read-only, narrow view,
# independent of the roles real authenticated users get (see main.py).
# Point the active database profile (config/settings/databases.yaml) at a
# disposable copy of the data — never at anything with real users'
# information.
#
# The policy file is read at import, so a missing or invalid file stops
# the server before it accepts a request (fail closed). The role is
# resolved against the database's tables at startup (wildcards expanded,
# the result printed) and fixed until restart.
# ==========================================================================

DEMO_ROLES = set(active_database().demo_roles)

SECURITY_POLICY = load_security_policy()

DEMO_SECURITY: SecurityContext | None = None


# ==========================================================================
# Rate limiting — sliding-window counters in memory (the timestamps of the
# last minute's / day's requests per key).
#
# Good enough for a single-process demo behind nginx. If you ever run
# more than one uvicorn worker, swap this for Redis (INCR + EXPIRE) so
# limits are shared across processes — the in-memory version otherwise
# under-counts.
# ==========================================================================


@dataclass
class _Window:
    hits: deque = field(default_factory=deque)

    def count_recent(self, now: float, span: float) -> int:
        while self.hits and now - self.hits[0] > span:
            self.hits.popleft()
        return len(self.hits)

    def record(self, now: float) -> None:
        self.hits.append(now)


class RateLimiter:
    PRUNE_INTERVAL_SECONDS = 300

    def __init__(self) -> None:
        self._minute: dict[str, _Window] = defaultdict(_Window)
        self._day: dict[str, _Window] = defaultdict(_Window)
        self._lock = asyncio.Lock()
        self._last_prune = time.time()

    def _prune(self, now: float) -> None:
        """
        Drop keys with no activity in the last 24h. Without this, every
        distinct IP / session id ever seen would stay in memory forever.
        """
        if now - self._last_prune < self.PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now

        for key in list(self._day):
            if self._day[key].count_recent(now, 86400) == 0:
                del self._day[key]
                self._minute.pop(key, None)

    async def check_and_record(self, key: str, per_minute: int, per_day: int) -> tuple[bool, str]:
        now = time.time()
        async with self._lock:
            self._prune(now)
            minute_win = self._minute[key]
            day_win = self._day[key]

            if minute_win.count_recent(now, 60) >= per_minute:
                return False, "Too many requests. Wait a minute and try again."
            if day_win.count_recent(now, 86400) >= per_day:
                return False, "Daily demo limit reached for this session/IP. Try again tomorrow."

            minute_win.record(now)
            day_win.record(now)
            return True, ""


rate_limiter = RateLimiter()


# Which part of the stack an exception came from, by the module that
# defines its class. Wrapped errors are followed through __cause__ /
# __context__, so e.g. ollama's ConnectionError still reads as "ollama".
_ERROR_SOURCES = (
    (("ollama", "httpx", "httpcore"), "model (ollama)"),
    ((active_engine().driver_module,), f"database ({active_engine().name})"),
)


def _error_source(exc: BaseException) -> str:
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        root = type(exc).__module__.split(".")[0]
        for modules, label in _ERROR_SOURCES:
            if root in modules:
                return label
        exc = exc.__cause__ or exc.__context__
    return "agent"


class AgentBusy(Exception):
    """No agent slot became free within QUEUE_WAIT_SECONDS."""


class AgentGate:
    """
    Limits how many agent runs are in flight at once.

    asyncio.wait_for() around asyncio.to_thread() stops WAITING when it
    times out, but the worker thread keeps running (threads can't be
    cancelled). If the slot were released at that point, a burst of
    timeouts would stack up more live runs than the limit allows. Here a
    run keeps its slot until its thread actually finishes, with
    MAX_SLOT_HOLD_SECONDS as a hard cap so a hung call can't take a slot
    forever.
    """

    def __init__(self, limit: int, max_hold: float) -> None:
        self._sem = asyncio.Semaphore(limit)
        self._max_hold = max_hold

    async def run(self, fn, *args, queue_timeout: float, run_timeout: float):
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=queue_timeout)
        except asyncio.TimeoutError:
            raise AgentBusy() from None

        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._sem.release()

        try:
            task = asyncio.ensure_future(asyncio.to_thread(fn, *args))
        except BaseException:
            release()
            raise

        watchdog = asyncio.get_running_loop().call_later(self._max_hold, release)

        abandoned = False  # set once the caller has given up waiting

        def on_done(finished: "asyncio.Future") -> None:
            watchdog.cancel()
            release()
            if finished.cancelled():
                return
            exc = finished.exception()  # mark retrieved; the caller sees it if still waiting
            if exc is not None and abandoned:
                # The request already got its 504; one line, not a traceback.
                log.warning(
                    f"[timeout] abandoned agent run failed in {_error_source(exc)}: "
                    f"{type(exc).__name__}: {exc}"
                )

        task.add_done_callback(on_done)

        # asyncio.wait(), not wait_for(shield(task)): it stops waiting without
        # cancelling the task, so the slot is freed by on_done. shield() would
        # also work, but logs a full traceback ("exception in shielded future")
        # when the abandoned run later fails, e.g. on an Ollama ReadTimeout.
        try:
            done, _ = await asyncio.wait({task}, timeout=run_timeout)
        except asyncio.CancelledError:
            abandoned = True  # client went away; let the thread finish quietly
            raise
        if not done:
            abandoned = True
            raise asyncio.TimeoutError()
        return task.result()


agent_gate = AgentGate(MAX_CONCURRENT_AGENT_RUNS, MAX_SLOT_HOLD_SECONDS)


def _client_ip(request: Request) -> str:
    """
    Best-effort client address, hashed before it touches logs or rate-limit
    keys.

    X-Forwarded-For is a list: each proxy appends the address it saw. Only
    the entries added by YOUR proxies can be trusted; everything to their
    left is whatever the client chose to send. So we count TRUSTED_PROXY_HOPS
    entries from the right rather than taking the first one, which a visitor
    could set to a fresh random value on every request to dodge the per-IP
    limit.

    If the header is missing or shorter than expected the request didn't
    come through the proxy chain we expect, so we fall back to the direct
    peer address (which, behind a proxy, is the proxy itself — everyone
    shares one bucket, which fails safe).
    """
    ip = request.client.host if request.client else "unknown"

    if TRUSTED_PROXY_HOPS > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(parts) >= TRUSTED_PROXY_HOPS:
            ip = parts[-TRUSTED_PROXY_HOPS]

    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# ==========================================================================
# Session-scoped conversation history.
#
# agent.run_agent() expects a mutable `history` list it appends to, per
# the real conversational flow (follow-up questions like "now by month").
# Each visitor needs their own list — a single shared list would leak
# one visitor's questions into another's context. Bounded with an LRU
# eviction so memory can't grow unboundedly.
#
# A run works on a COPY of the session's history, written back only when
# it finishes in time (ask()). A timed-out run's thread keeps going and
# would otherwise append to the list the next request is using, and two
# requests from one session would edit the same list at once.
# ==========================================================================


class SessionStore:
    def __init__(self, max_sessions: int) -> None:
        self._sessions: "OrderedDict[str, list]" = OrderedDict()
        self._max_sessions = max_sessions
        self._lock = asyncio.Lock()

    async def get(self, session_id: str) -> list:
        async with self._lock:
            history = self._sessions.get(session_id)
            if history is None:
                history = []
                self._sessions[session_id] = history
            self._sessions.move_to_end(session_id)

            while len(self._sessions) > self._max_sessions:
                self._sessions.popitem(last=False)

            return history


session_store = SessionStore(MAX_TRACKED_SESSIONS)


# ==========================================================================
# Schema catalog — built once at startup against the demo SecurityContext,
# not per request. Schema discovery hits the database; there's no reason
# to repeat it for every question when the security context never changes
# for the demo user.
# ==========================================================================

demo_catalog: SchemaCatalog | None = None


# ==========================================================================
# Logging
#
# The console log (sqlagent/log.py) is what the REPL prints. Inside a
# request every line carries the request's id - the same id= as its
# audit lines - so concurrent requests can be told apart.
# ==========================================================================

log = logging.getLogger("sqlagent.api")

audit_logger = logging.getLogger("secure_sql_agent.demo")
audit_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(AUDIT_LOG_PATH)
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit_logger.addHandler(_handler)


def audit(event: str, **fields) -> None:
    parts = " ".join(f"{k}={v!r}" for k, v in fields.items())
    audit_logger.info("%s %s", event, parts)


# ==========================================================================
# API
# ==========================================================================


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await load_schema_catalog()
    yield


app = FastAPI(
    title="Secure SQL Agent — demo API",
    root_path="/sqlagent",
    lifespan=lifespan,
)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["POST", "GET"],
        allow_headers=["*"],
        allow_credentials=False,
    )


async def load_schema_catalog():
    global demo_catalog, DEMO_SECURITY
    # Any failure here (database, policy, semantic model, or a catalog with
    # no tables - EmptyCatalogError) aborts startup: the API never runs
    # without its SecurityContext or with nothing to ground the model in.
    DEMO_SECURITY = SECURITY_POLICY.build_context(
        "demo", DEMO_ROLES, list_tables(get_connection))
    demo_catalog = SchemaCatalog(
        get_connection, DEMO_SECURITY, semantic=load_semantic_model())
    demo_catalog.refresh()
    audit(
        "startup",
        database=active_database().name,
        tables=len(demo_catalog.tables),
        foreign_keys=len(demo_catalog.foreign_keys),
    )


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=MAX_QUESTION_CHARS)
    session_id: str = Field(..., min_length=8, max_length=64)


class AskResponse(BaseModel):
    answer: str
    blocked: bool = False
    # "policy" (a guardrail stopped it), "error" (technical failure) or
    # None (ran normally). rule / rule_label are set for policy blocks
    # only and are generic, so they're safe to show in the browser.
    reason: str | None = None
    rule: str | None = None
    rule_label: str | None = None
    # Domain of Discourse the question was routed to, e.g. "Sales" or
    # "Sales + Financials". A business label only; never table names.
    domain: str | None = None


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "tables_loaded": len(demo_catalog.tables) if demo_catalog else 0,
    }


# api.yaml unavailable_message
DEMO_UNAVAILABLE_MSG = _API.unavailable_message

# Resolve relative to this file so it doesn't depend on the working directory
ENABLE_FLAG = Path(__file__).parent / "demo_enabled.flag"


def require_demo_enabled() -> None:
    if not ENABLE_FLAG.exists():
        raise HTTPException(status_code=503, detail=DEMO_UNAVAILABLE_MSG)


@app.get("/api/status")
async def status(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return {"enabled": ENABLE_FLAG.exists()}


@app.post("/api/ask", response_model=AskResponse, dependencies=[Depends(require_demo_enabled)])
async def ask(payload: AskRequest, request: Request):
    if demo_catalog is None or DEMO_SECURITY is None:
        # Not 503: the page treats a 503 from this endpoint as "demo disabled".
        raise HTTPException(status_code=500, detail="Demo is still starting up — try again shortly.")

    ip_key = _client_ip(request)
    session_key = f"s:{payload.session_id}"

    ip_ok, ip_msg = await rate_limiter.check_and_record(ip_key, IP_REQUESTS_PER_MINUTE, IP_REQUESTS_PER_DAY)
    if not ip_ok:
        audit("rate_limited", scope="ip", ip=ip_key, session=payload.session_id)
        raise HTTPException(status_code=429, detail=ip_msg)

    session_ok, session_msg = await rate_limiter.check_and_record(
        session_key, SESSION_REQUESTS_PER_MINUTE, SESSION_REQUESTS_PER_DAY
    )
    if not session_ok:
        audit("rate_limited", scope="session", ip=ip_key, session=payload.session_id)
        raise HTTPException(status_code=429, detail=session_msg)

    question = payload.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    history = await session_store.get(payload.session_id)
    working_history = list(history)   # see "Session-scoped conversation history"

    request_id = uuid.uuid4().hex[:12]
    audit("request_received", id=request_id, ip=ip_key, session=payload.session_id, question=question)

    # Every console line from here on - including the agent's, in its
    # worker thread (asyncio.to_thread copies the context) - carries
    # request_id.
    with request_context(request_id):
        return await _answer(payload, question, request_id, history, working_history)


async def _answer(payload: AskRequest, question: str, request_id: str,
                  history: list, working_history: list) -> AskResponse:
    """The rest of ask(): run the agent and turn its result into the
    response. Runs with request_id set for the console log."""
    log.info(f"\n[question] {question}")

    try:
        result = await agent_gate.run(
            run_agent, question, demo_catalog, working_history, DEMO_SECURITY,
            queue_timeout=QUEUE_WAIT_SECONDS,
            run_timeout=AGENT_TIMEOUT_SECONDS,
        )
    except AgentBusy:
        audit("busy", id=request_id, session=payload.session_id)
        # 429, not 503: the page treats a 503 as "demo disabled".
        raise HTTPException(
            status_code=429,
            detail="The demo is busy right now — try again in a few seconds.",
            headers={"Retry-After": "5"},
        ) from None
    except asyncio.TimeoutError:
        audit("timeout", id=request_id, session=payload.session_id)
        log.warning(f"[timeout] no answer within {AGENT_TIMEOUT_SECONDS}s — returned 504")
        raise HTTPException(
            status_code=504,
            detail=(
                "That took too long — the model may have been idle and is "
                "waking up. Ask the question again and you should get a response."
            ),
        ) from None
    except Exception as exc:  # noqa: BLE001 — never leak internals to a public endpoint
        audit("error", id=request_id, session=payload.session_id, error=type(exc).__name__)
        raise HTTPException(
            status_code=500, detail="Something went wrong answering that question.",
        ) from None

    # Finished in time: this run's turn becomes the session's history.
    history[:] = working_history

    # run_agent() returns the dict described in its docstring (agent.py).
    # The SQL is logged for the audit trail but deliberately NOT returned
    # to the browser.
    answer = result["answer"]
    blocked = result["blocked"]
    reason = result.get("reason")
    rule = result.get("rule")
    rule_label = result.get("rule_label")

    audit(
        "request_completed",
        id=request_id,
        session=payload.session_id,
        blocked=blocked,
        reason=reason,
        rule=rule,
        domain=result.get("domain"),
        sql=result.get("sql"),
    )
    return AskResponse(
        answer=answer,
        blocked=blocked,
        reason=reason,
        rule=rule,
        rule_label=rule_label,
        domain=result.get("domain"),
    )
