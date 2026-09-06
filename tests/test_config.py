"""Policy lives in config/rules.yml and nowhere else."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "pipeline"


def test_config_is_versioned(cfg):
    assert cfg.version >= 1


def test_thresholds_are_not_duplicated_in_python():
    """Regression: MIN_AGE, MAX_AGE and INCOME_CAP existed in both YAML and two
    modules, so a rules change could leave cleaning and profiling disagreeing."""
    offenders = []
    for path in SRC.glob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"\s*(MIN_AGE|MAX_AGE|INCOME_CAP|MAX_PLAUSIBLE_AGE)\s*=", line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"policy hardcoded in Python: {offenders}"


def test_every_masking_strategy_resolves(cfg):
    from pipeline.mask import build_maskers

    maskers = build_maskers(cfg)
    assert set(maskers) == {r.column for r in cfg.mask_rules}


def test_unknown_masking_strategy_raises(cfg):
    from pipeline.config import Config
    from pipeline.mask import build_maskers

    raw = dict(cfg._raw)
    raw["masking"] = dict(raw["masking"])
    raw["masking"]["rules"] = {"email": {"strategy": "invent", "description": "x", "rationale": "y"}}
    try:
        build_maskers(Config(raw))
    except ValueError as exc:
        assert "unknown strategy" in str(exc)
    else:
        raise AssertionError("a masking rule that does nothing must not pass silently")


def test_released_columns_are_covered_by_the_risk_assessment(cfg):
    """Every column shared must be either masked or explicitly listed as
    released unmasked - nothing leaves the pipeline unclassified."""
    accounted = {r.column for r in cfg.mask_rules} | set(cfg.unmasked_columns)
    assert set(cfg.schema) - accounted == set()
