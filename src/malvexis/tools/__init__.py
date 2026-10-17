"""Wrappers around external analyzers (Detect It Easy, ClamAV, capa, FLOSS).

All of them are optional: a missing tool yields status "unavailable", never a crash. They run locally
and never execute the sample. Every wrapper returns intel.base.make_result(...).
"""
from . import capa_tool, clamav_tool, die_tool, floss_tool

# Opt-in tools (slow or need extra setup). Detect It Easy is cheap and always attempted.
OPTIONAL_TOOLS = {"clamav": clamav_tool, "capa": capa_tool, "floss": floss_tool}
