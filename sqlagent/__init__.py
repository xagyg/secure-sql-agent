# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Secure SQL Agent. The packages follow the IBAAM layers:
#
#   adaptive/   conversational interpretation by the LLM (llm.py), schema
#               discovery and Domain of Discourse routing (what the LLM
#               may see and where it starts)
#   controls/   the Agent Behavioural Controls (ABCs): deterministic
#               validation, authorisation, rewriting and result policy
#   execution/  controlled execution against PostgreSQL
#
# agent.py orchestrates the pipeline across the three layers.
