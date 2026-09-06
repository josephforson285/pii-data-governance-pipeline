"""config/rules.yml is rejected at load time if the pipeline cannot honour it.

Each case here would otherwise surface as a confusing downstream error or, in
the masking cases, as silence.
"""
from __future__ import annotations

import copy

import pytest

from pipeline.config import Config, validate_config


def broken(cfg, mutate):
    raw = copy.deepcopy(cfg._raw)
    mutate(raw)
    return Config(raw)


def test_valid_config_passes(cfg):
    validate_config(cfg)


@pytest.mark.parametrize("mutate,expected", [
    (lambda r: r.update(version=0), "version must be"),
    (lambda r: r["thresholds"].update(min_age=200), "min_age"),
    (lambda r: r["thresholds"].update(income_cap=-1), "income_cap"),
    (lambda r: r["masking"].update(income_band_width=0), "income_band_width"),
    (lambda r: r["schema"]["income"].update(dtype="decimal"), "dtype"),
    (lambda r: r["dataframe_checks"][0].update(op="sideways"), "unknown"),
    (lambda r: r["dataframe_checks"][0].update(left="nope"), "unknown column"),
    (lambda r: r["masking"]["rules"]["email"].update(strategy="invent"), "unknown"),
    (lambda r: r["masking"]["rules"].update(nope={"strategy": "initial",
                                                  "description": "", "rationale": ""}),
     "unknown column"),
    (lambda r: r["release"]["quasi_identifiers_after"].append("nope"), "neither a"),
    (lambda r: r["reporting"]["sensitive_columns"].append("nope"), "unknown column"),
    (lambda r: r["remediation"]["status_aliases"].update(zzz="deleted"),
     "not a permitted status"),
    (lambda r: r["schema_policy"].update(unexpected_columns="maybe"), "warn"),
])
def test_broken_config_is_rejected(cfg, mutate, expected):
    with pytest.raises(ValueError, match=expected):
        validate_config(broken(cfg, mutate))


def test_every_column_is_masked_or_declared_released(cfg):
    """A column that is neither would leave the pipeline silently."""
    def drop_masking_and_release(raw):
        raw["masking"]["rules"].pop("email")
    with pytest.raises(ValueError, match="neither masked nor declared"):
        validate_config(broken(cfg, drop_masking_and_release))


def test_reference_date_accepts_a_yaml_date_object(cfg):
    from datetime import date

    pinned = broken(cfg, lambda r: r.update(reference_date=date(2021, 6, 1)))
    assert pinned.reference_date == date(2021, 6, 1)
    assert pinned.reference_date_is_pinned


def test_generation_is_reproducible_from_the_seed(cfg):
    """The generator used date.today(), so the same seed produced different
    data on different days - and the committed reports described a dataset a
    later regenerate would not reproduce."""
    from pipeline.generate import generate

    first, _ = generate(200, 7, cfg.reference_date)
    second, _ = generate(200, 7, cfg.reference_date)
    assert first.equals(second)


def test_reference_date_is_pinned_for_submission(cfg):
    assert cfg.reference_date_is_pinned, (
        "an unpinned reference date makes both the generated data and the "
        "age checks drift over time"
    )
