from pathlib import Path

import pytest

from pipeline.config import load

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def cfg():
    return load(ROOT / "config" / "rules.yml")
