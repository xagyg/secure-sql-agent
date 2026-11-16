# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the Ollama request options (llm.temperature / seed / num_ctx)
# and the per-call token line (llm.token_report). No Ollama needed.
#
#     python -m unittest tests.test_ollama_options -v

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest import mock

from sqlagent.adaptive import llm
from sqlagent.settings import LlmSettings


def reply(prompt=None, out=None, prompt_ns=None, out_ns=None, text="ok"):
    return SimpleNamespace(prompt_eval_count=prompt, eval_count=out,
                           prompt_eval_duration=prompt_ns, eval_duration=out_ns,
                           message=SimpleNamespace(content=text))


class Options(unittest.TestCase):

    def test_options_are_sent(self):
        settings = LlmSettings(model="m", temperature=0, seed=42, num_ctx=16384)
        with mock.patch.object(llm, "_LLM", settings), \
             mock.patch.object(llm, "OLLAMA_OPTIONS", None):
            options = llm._ollama_options()
        self.assertEqual(options, {"temperature": 0, "seed": 42, "num_ctx": 16384})

    def test_unset_options_are_left_out(self):
        with mock.patch.object(llm, "_LLM", LlmSettings(model="m")):
            self.assertEqual(llm._ollama_options(), {})

    def test_temperature_zero_is_kept(self):
        # 0 is a real setting, not "unset".
        with mock.patch.object(llm, "_LLM", LlmSettings(model="m", temperature=0)):
            self.assertEqual(llm._ollama_options(), {"temperature": 0})

    def test_ask_ollama_passes_them(self):
        client = mock.Mock()
        client.chat.return_value = reply(100, 10)
        with mock.patch.object(llm, "ollama_client", client), \
             mock.patch.object(llm, "OLLAMA_OPTIONS", {"temperature": 0, "num_ctx": 8192}), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(llm.ask_ollama([{"role": "user", "content": "x"}]), "ok")
        self.assertEqual(client.chat.call_args.kwargs["options"],
                         {"temperature": 0, "num_ctx": 8192})

    def test_shipped_settings(self):
        from sqlagent.settings import get_settings
        settings = get_settings().llm
        self.assertEqual(settings.temperature, 0)
        self.assertIsNotNone(settings.seed)
        # num_ctx may be empty (the Ollama app's setting is used), or a size.
        self.assertTrue(settings.num_ctx is None or settings.num_ctx >= 512)


class TokenReport(unittest.TestCase):

    def test_counts_and_times(self):
        self.assertEqual(llm.token_report(reply(6850, 120, 9.8e9, 3.1e9)),
                         "6,850 prompt tokens (9.8s), 120 out (3.1s)")

    def test_warns_near_the_context_limit(self):
        text = llm.token_report(reply(7900, 50), num_ctx=8192)
        self.assertIn("WARNING: 96% of num_ctx 8,192", text)

    def test_no_warning_well_under_the_limit(self):
        self.assertNotIn("WARNING", llm.token_report(reply(4000, 50), num_ctx=16384))

    def test_cut_prompt_is_flagged_without_num_ctx(self):
        # The beta-feature run: ~4,915 sent, 2,050 counted at a 4K context.
        text = llm.token_report(reply(2050, 53), num_ctx=None, estimate=4915)
        self.assertIn("WARNING: the prompt was cut to fit Ollama's context", text)
        self.assertIn("about 4,100 tokens", text)

    def test_uncut_prompt_without_num_ctx(self):
        self.assertFalse(llm.prompt_was_cut(2589, None, 2564))
        self.assertFalse(llm.prompt_was_cut(11521, None, 11605))
        self.assertFalse(llm.prompt_was_cut(300, None, 900))     # too small to judge
        self.assertNotIn("WARNING", llm.token_report(reply(2589, 54), estimate=2564))

    def test_cut_prompt_is_flagged(self):
        # ~9,000 tokens sent, Ollama counted 4,098: half an 8K context.
        text = llm.token_report(reply(4098, 50), num_ctx=8192, estimate=9000)
        self.assertIn("~9,000 sent", text)
        self.assertIn("WARNING: the prompt was cut", text)

    def test_cut_at_16k(self):
        self.assertTrue(llm.prompt_was_cut(8194, 16384, 17400))

    def test_fitting_prompt_is_not_flagged(self):
        # The 02:15 run: 13,746 counted of ~14,000 sent fits in 16K.
        text = llm.token_report(reply(13746, 90), num_ctx=16384, estimate=14000)
        self.assertNotIn("WARNING", text)

    def test_small_prompt_near_half_is_not_flagged(self):
        # A prompt that really is ~4,100 tokens is not a cut.
        self.assertFalse(llm.prompt_was_cut(4098, 8192, 4000))

    def test_whole_prompt_is_not_flagged(self):
        text = llm.token_report(reply(430, 40), num_ctx=8192, estimate=410)
        self.assertNotIn("WARNING", text)

    def test_estimate(self):
        self.assertEqual(llm.estimated_tokens([{"content": "x" * 400}]), 100)

    def test_breakdown(self):
        text = llm.prompt_breakdown("x" * 4000, schema="s" * 2000, examples="e" * 400,
                                    history="")
        self.assertEqual(text, "[llm] SQL prompt ~1,000 tokens: schema ~500, "
                               "examples ~100, history ~0, rules ~400")

    def test_reply_without_counts(self):
        self.assertIsNone(llm.token_report(reply()))

    def test_ask_ollama_prints_the_line(self):
        client = mock.Mock()
        client.chat.return_value = reply(500, 20)
        with mock.patch.object(llm, "ollama_client", client), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            llm.ask_ollama([{"role": "user", "content": "x"}])
        self.assertIn("[llm] 500 prompt tokens, 20 out", out.getvalue())


if __name__ == "__main__":
    unittest.main()
