# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Adaptive layer: conversational interpretation by the LLM (llm.py: model
# client and prompts for SQL generation, correction and explanation),
# schema discovery (schema_catalog.py), the semantic model from
# config/semantic/<database>/ (semantic_model.py), Domain of Discourse routing
# (domains.py) and shared text matching (text_match.py).
# Nothing here grants access: everything the LLM produces passes through
# the controls, and what it is shown comes from the security-filtered
# catalog.
