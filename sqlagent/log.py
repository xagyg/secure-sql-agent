# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# The agent's console log. Every module logs through a child of the
# "sqlagent" logger (logging.getLogger(__name__)), which writes to stdout
# exactly what the REPL has always printed: the message alone, no level or
# timestamp. stdout is looked up for every line, so batch mode's Tee and
# contextlib.redirect_stdout (tests, tools/) still see it.
#
# Request IDs: while request_id is set (the API sets it for each request,
# see request_context()), every line of a message is prefixed with it,
#
#     [3f2a9c1b7e04] [agent] Generating SQL...
#
# so the log of concurrent requests can be told apart and matched to the
# audit log's id=. Outside a request (the REPL, startup) nothing is added.
# asyncio.to_thread() copies the context, so the ID follows the request
# into its worker thread.

import contextlib
import contextvars
import logging
import sys

ROOT = "sqlagent"

request_id = contextvars.ContextVar("sqlagent_request_id", default=None)


@contextlib.contextmanager
def request_context(rid):
    """Log with request ID `rid` inside the block."""
    token = request_id.set(rid)
    try:
        yield
    finally:
        request_id.reset(token)


class _CurrentStdoutHandler(logging.StreamHandler):
    """A StreamHandler for whatever sys.stdout is at the time of each line."""

    def __init__(self):
        super().__init__(sys.stdout)

    @property
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, _value):
        pass


class ConsoleFormatter(logging.Formatter):
    """The message as printed; with a request ID, each line prefixed by it
    (the blank lines that separate steps on the console are dropped)."""

    def format(self, record):
        message = super().format(record)
        rid = request_id.get()
        if rid is None:
            return message
        lines = [line for line in message.split("\n") if line.strip()]
        return "\n".join(f"[{rid}] {line}" for line in lines)


def _configure():
    logger = logging.getLogger(ROOT)
    if any(isinstance(h, _CurrentStdoutHandler) for h in logger.handlers):
        return
    handler = _CurrentStdoutHandler()
    handler.setFormatter(ConsoleFormatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    # Not passed on to the root logger: uvicorn or an application that
    # configures logging would print every line twice.
    logger.propagate = False


_configure()
