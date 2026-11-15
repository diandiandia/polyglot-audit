"""Test package bootstrap (DSR-023 / SWR-024).

Makes the suite runnable through the standard entry points -- ``python3 -m
unittest discover tests`` from the repository root, and pytest -- by putting
``skill/scripts`` (the ``auditkit`` package home) on ``sys.path`` before any
test module imports it. ``tools/run_all_tests.py`` performs the same insert
for the orchestrated path; this module covers standalone runs.
"""

import sys
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parent.parent / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))
