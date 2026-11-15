"""Pytest bootstrap (DSR-023 / SWR-024).

Standalone pytest runs need ``skill/scripts`` on ``sys.path`` for the
``auditkit`` imports; pytest reads this conftest before collecting tests.
"""

import sys
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parent / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))
