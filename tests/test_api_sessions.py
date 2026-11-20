# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for api.py's per-session conversation history: a run works on a
# copy, written back only when it finishes in time, so a timed-out run's
# thread can't change the history later requests use. No database or LLM:
# run_agent is replaced and the startup (lifespan) isn't run.
#
#     python -m unittest tests.test_api_sessions -v

import asyncio
import contextlib
import io
import logging
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import api


def _answer(history, text):
    history.append({"question": text, "answer": text})
    return {"answer": text, "blocked": False}


class SessionHistory(unittest.TestCase):

    def setUp(self):
        flag = tempfile.NamedTemporaryFile(delete=False)
        flag.close()
        self.addCleanup(Path(flag.name).unlink)
        patches = [
            mock.patch.object(api, "ENABLE_FLAG", Path(flag.name)),
            mock.patch.object(api, "demo_catalog", object()),
            mock.patch.object(api, "DEMO_SECURITY", object()),
            mock.patch.object(api, "session_store", api.SessionStore(10)),
            mock.patch.object(api, "rate_limiter", api.RateLimiter()),
            mock.patch.object(api, "agent_gate", api.AgentGate(4, 10)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.client = TestClient(api.app)

    def ask(self, question, session="session-one"):
        return self.client.post("/api/ask", json={"question": question,
                                                  "session_id": session})

    def history(self, session="session-one"):
        return asyncio.run(api.session_store.get(session))

    def test_finished_run_is_kept(self):
        def run_agent(question, catalog, history, security):
            return _answer(history, question)

        with mock.patch.object(api, "run_agent", run_agent):
            self.assertEqual(self.ask("first").status_code, 200)
            self.assertEqual(self.ask("second").status_code, 200)
        self.assertEqual([t["question"] for t in self.history()], ["first", "second"])

    def test_timed_out_run_does_not_change_history(self):
        finished = threading.Event()

        def slow_agent(question, catalog, history, security):
            time.sleep(0.3)
            result = _answer(history, question)
            finished.set()
            return result

        with mock.patch.object(api, "run_agent", slow_agent), \
                mock.patch.object(api, "AGENT_TIMEOUT_SECONDS", 0.05):
            self.assertEqual(self.ask("too slow").status_code, 504)
            self.assertTrue(finished.wait(2))
        self.assertEqual(self.history(), [])



class RequestIdInLog(unittest.TestCase):
    """The agent's console lines carry the request's id, the same id as
    its audit lines; outside a request nothing is added."""

    def setUp(self):
        SessionHistory.setUp(self)

    def test_agent_lines_carry_the_audit_id(self):
        def run_agent(question, catalog, history, security):
            logging.getLogger("sqlagent.agent").info("\n[agent] Generating SQL...")
            return {"answer": "ok", "blocked": False}

        audited = []
        with mock.patch.object(api, "run_agent", run_agent), \
                mock.patch.object(api, "audit", lambda event, **f: audited.append((event, f))), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(SessionHistory.ask(self, "q").status_code, 200)

        rid = dict(audited)["request_received"]["id"]
        lines = out.getvalue().splitlines()
        self.assertIn(f"[{rid}] [question] q", lines)
        self.assertIn(f"[{rid}] [agent] Generating SQL...", lines)
        self.assertTrue(all(line.startswith(f"[{rid}] ") for line in lines))

    def test_no_prefix_outside_a_request(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            logging.getLogger("sqlagent.agent").info("\n[agent] Generating SQL...")
        self.assertEqual(out.getvalue(), "\n[agent] Generating SQL...\n")

    def test_concurrent_requests_keep_their_own_id(self):
        def run_agent(question, catalog, history, security):
            for _ in range(5):
                logging.getLogger("sqlagent.agent").info(f"[agent] {question}")
                time.sleep(0.01)
            return {"answer": question, "blocked": False}

        audited = []

        async def both():
            import httpx
            transport = httpx.ASGITransport(app=api.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                await asyncio.gather(*(
                    c.post("/sqlagent/api/ask",
                           json={"question": q, "session_id": f"session-{q}"})
                    for q in ("alpha", "bravo")))

        with mock.patch.object(api, "run_agent", run_agent), \
                mock.patch.object(api, "audit", lambda event, **f: audited.append((event, f))), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            asyncio.run(both())

        ids = {f["question"]: f["id"] for event, f in audited if event == "request_received"}
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 12)          # [question] + 5 [agent] each
        for line in lines:
            rid, question = re.fullmatch(r"\[(\w+)\] \[\w+\] (\w+)", line).groups()
            self.assertEqual(rid, ids[question])


if __name__ == "__main__":
    unittest.main()
