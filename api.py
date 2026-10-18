"""
Secure SQL Agent — public demo API
-----------------------------------
A thin, hardened HTTP wrapper around the existing agent.run_agent().

This does NOT reimplement any of the Agent Behavioural Controls
(structural safety, authorisation, rewriting, limits, result policy) —
those live in sql_policy.py, result_policy.py and question_policy.py
and run exactly as before. This
wrapper adds what public, anonymous traffic needs on top of that: rate
limiting, per-session conversation state (with a memory cap), a fixed
demo-only SecurityContext, request timeouts, concurrency limits, and
audit logging.

Run from the project root (alongside agent.py, sql_policy.py, etc):
    uvicorn api:app --host 127.0.0.1 --port 8000 --workers 1

Keep --workers 1 (or move the in-memory rate limiter / session store to
Redis) — neither is shared across worker processes.

Deployment settings worth checking (all environment variables):
    DEMO_TRUSTED_PROXY_HOPS  how many reverse proxies sit in front of this
                             process (default 1). The client IP is read that
                             many entries from the RIGHT of X-Forwarded-For,
                             i.e. the entry your own proxy added, which a
                             visitor can't forge. Use 0 if nothing is in
                             front (the header is then ignored), 2 for e.g.
                             Cloudflare + nginx.
    DEMO_ALLOWED_ORIGIN      only needed if the page is served from a
                             different origin than this API (comma-separated
                             list). Unset = same-origin only, no CORS.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sqlagent.agent import run_agent
from sqlagent.databases import active_database
from sqlagent.controls.security_context import SecurityContext
from sqlagent.controls.security_policy import load_security_policy
from sqlagent.adaptive.schema_catalog import SchemaCatalog
from sqlagent.adaptive.semantic_model import load_semantic_model
from sqlagent.execution.sql_execution import get_connection, list_tables

from pathlib import Path


# ==========================================================================
# Configuration
# ==========================================================================

# Unset (the default) means same-origin only: the page calls this API via a
# relative URL, so no CORS is needed and none is enabled. Set it only if the
# page is hosted on a different origin.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("DEMO_ALLOWED_ORIGIN", "").split(",")
    if origin.strip()
]

# Number of reverse proxies in front of this process. See _client_ip().
TRUSTED_PROXY_HOPS = int(os.environ.get("DEMO_TRUSTED_PROXY_HOPS", "1"))

MAX_QUESTION_CHARS = int(os.environ.get("DEMO_MAX_QUESTION_CHARS", "300"))

# Per-session limits — a convenience bucket keyed on the browser-generated
# session_id the frontend sends. Not authentication; stops one tab from
# hammering the endpoint. The per-IP limit below is the real backstop.
SESSION_REQUESTS_PER_MINUTE = int(os.environ.get("DEMO_SESSION_RPM", "4"))
SESSION_REQUESTS_PER_DAY = int(os.environ.get("DEMO_SESSION_RPD", "40"))

IP_REQUESTS_PER_MINUTE = int(os.environ.get("DEMO_IP_RPM", "10"))
IP_REQUESTS_PER_DAY = int(os.environ.get("DEMO_IP_RPD", "150"))

# How many agent runs (i.e. Ollama calls) may be in flight at once, across
# every visitor combined — protects your GPU/CPU.
MAX_CONCURRENT_AGENT_RUNS = int(os.environ.get("DEMO_MAX_CONCURRENCY", "2"))

AGENT_TIMEOUT_SECONDS = float(os.environ.get("DEMO_AGENT_TIMEOUT", "25"))

# How long a request will wait for a free agent slot before being told the
# demo is busy (instead of queueing behind other visitors indefinitely).
QUEUE_WAIT_SECONDS = float(os.environ.get("DEMO_QUEUE_WAIT", "5"))

# A timed-out request's worker thread can't be killed, so its slot stays
# taken until the thread really finishes. This caps how long a stuck thread
# (e.g. a hung model call) can keep a slot before it is released anyway.
MAX_SLOT_HOLD_SECONDS = float(os.environ.get("DEMO_MAX_SLOT_HOLD", "90"))

# How many distinct sessions' conversation history to keep in memory at
# once. Oldest sessions are evicted first — this bounds memory even if
# thousands of anonymous visitors show up.
MAX_TRACKED_SESSIONS = int(os.environ.get("DEMO_MAX_SESSIONS", "2000"))
# Per-conversation history length is capped by MAX_HISTORY_TURNS inside
# llm.py, not here — this store only caps how many sessions total are
# kept in memory.

AUDIT_LOG_PATH = os.environ.get("DEMO_AUDIT_LOG", "audit.log")


# ==========================================================================
# Demo SecurityContext — the active database's demo_roles (config/databases.yaml),
# e.g. the "demo" role in config/security/northwind.yaml.
#
# Every anonymous demo visitor gets this same read-only, narrow view,
# independent of the roles real authenticated users get (see main.py).
# Point this process's PGHOST/PGDATABASE/etc at a disposable copy of the
# data — never at anything with real users' information.
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
# Rate limiting — simple fixed-window counters in memory.
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
    (("psycopg2",), "database (postgres)"),
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
            raise AgentBusy()

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
                print(
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
# Audit logging
# ==========================================================================

logger = logging.getLogger("secure_sql_agent.demo")
logger.setLevel(logging.INFO)
_handler = logging.FileHandler(AUDIT_LOG_PATH)
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_handler)


def audit(event: str, **fields) -> None:
    parts = " ".join(f"{k}={v!r}" for k, v in fields.items())
    logger.info("%s %s", event, parts)


# ==========================================================================
# API
# ==========================================================================


app = FastAPI(
    title="Secure SQL Agent — demo API",
    root_path="/sqlagent"
)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["POST", "GET"],
        allow_headers=["*"],
        allow_credentials=False,
    )


@app.on_event("startup")
async def load_schema_catalog():
    global demo_catalog, DEMO_SECURITY
    # Any failure here (database, policy, semantic model) aborts startup:
    # the API never runs without its SecurityContext.
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
    reason: Optional[str] = None
    rule: Optional[str] = None
    rule_label: Optional[str] = None
    # Domain of Discourse the question was routed to, e.g. "Sales" or
    # "Sales + Financials". A business label only; never table names.
    domain: Optional[str] = None


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "tables_loaded": len(demo_catalog.tables) if demo_catalog else 0,
    }


DEMO_UNAVAILABLE_MSG = (
    "The demo is not currently available. "
    "Contact bradlongphd@gmail.com to enable the demo."
)

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

    request_id = uuid.uuid4().hex[:12]
    audit("request_received", id=request_id, ip=ip_key, session=payload.session_id, question=question)
    print(f"\n[question] {question}")

    try:
        result = await agent_gate.run(
            run_agent, question, demo_catalog, history, DEMO_SECURITY,
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
        )
    except asyncio.TimeoutError:
        audit("timeout", id=request_id, session=payload.session_id)
        print(f"[timeout] no answer within {AGENT_TIMEOUT_SECONDS}s — returned 504")
        raise HTTPException(
            status_code=504,
            detail=(
                "That took too long — the model may have been idle and is "
                "waking up. Ask the question again and you should get a response."
            ),
        )
#    except Exception as exc:  # noqa: BLE001 — never leak internals to a public endpoint
#        audit(
#            "error",
#            id=request_id,
#            session=payload.session_id,
#            error=type(exc).__name__,
#            detail=str(exc),
#        )
#        raise HTTPException(status_code=500, detail="Something went wrong answering that question.")
    except Exception as exc:  # noqa: BLE001 — never leak internals to a public endpoint
        audit("error", id=request_id, session=payload.session_id, error=type(exc).__name__)
        raise HTTPException(status_code=500, detail="Something went wrong answering that question.")

    # run_agent() returns {"answer", "blocked", "reason", "rule",
    # "rule_label", "sql"} — see agent.py. The SQL is logged for the audit
    # trail but deliberately NOT returned to the browser.
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
