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


def test_empty_yaml_is_rejected_clearly(tmp_path):
    from pipeline.config import load

    bad = tmp_path / "rules.yml"
    bad.write_text("")
    with pytest.raises(ValueError, match="non-empty YAML mapping"):
        load(bad)


def test_missing_sections_are_listed_not_crashed_through(cfg, tmp_path):
    """Property access raises KeyError on a missing section, which would abort
    before a single problem could be collected."""
    import yaml

    from pipeline.config import load

    raw = copy.deepcopy(cfg._raw)
    del raw["masking"], raw["release"]
    bad = tmp_path / "rules.yml"
    bad.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError) as exc:
        load(bad)
    assert "masking" in str(exc.value) and "release" in str(exc.value)


@pytest.mark.parametrize("mutate,expected", [
    (lambda r: r["thresholds"].update(min_age=-1), "must not be negative"),
    (lambda r: r["schema"]["first_name"]["checks"].update(min_len=100), "exceeds max_len"),
    (lambda r: r.update(reference_date="banana"), "not an ISO date"),
    (lambda r: r["masking"]["rules"]["email"].pop("rationale"), "missing 'rationale'"),
])
def test_further_structural_problems_are_rejected(cfg, mutate, expected):
    from pipeline.config import validate_config

    with pytest.raises(ValueError, match=expected):
        validate_config(broken(cfg, mutate))


@pytest.mark.parametrize("section,key", [
    ("thresholds", "income_cap"),
    ("masking", "rules"),
    ("release", "unmasked_columns"),
    ("reporting", "sensitive_columns"),
    ("remediation", "date_formats"),
])
def test_missing_nested_keys_are_reported_not_raised(cfg, section, key):
    """A present section with a missing key raised KeyError from a property
    before a single problem could be collected."""
    from pipeline.config import validate_config

    raw = copy.deepcopy(cfg._raw)
    del raw[section][key]
    with pytest.raises(ValueError, match=f"{section}.{key}"):
        validate_config(Config(raw))


def test_missing_permitted_statuses_is_reported(cfg):
    from pipeline.config import validate_config

    raw = copy.deepcopy(cfg._raw)
    del raw["schema"]["account_status"]["checks"]["isin"]
    with pytest.raises(ValueError, match="account_status.checks.isin"):
        validate_config(Config(raw))
