# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Unit tests. No database or LLM needed. Run from the project root:
#
#     python -m unittest discover tests -v

import os

# The tests use a static copy of Northwind (tests/fixtures.py) and the
# shipped Northwind configuration, whichever database this shell has
# selected for running the agent.
os.environ["SQLAGENT_DATABASE"] = "northwind"
os.environ.pop("SQLAGENT_SECURITY_FILE", None)
os.environ.pop("SQLAGENT_SEMANTIC_PATH", None)
