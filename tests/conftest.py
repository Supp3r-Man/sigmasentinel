import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.engine import load_rules  # noqa: E402


@pytest.fixture(scope="session")
def rules():
    return {r.id: r for r in load_rules(ROOT / "rules")}
