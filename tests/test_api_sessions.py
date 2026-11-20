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


if __name__ == "__main__":
    unittest.main()
