"""Gates and robustness: the pipeline must refuse to publish non-compliant
data, and the profiler must survive input bad enough to be worth reporting."""
from __future__ import annotations

import pandas as pd
import pytest

from pipeline.config import Config
from pipeline.privacy import income_band, k_buckets, signatures
from pipeline.profile import profile
from pipeline.validate import validate

COLS = ["customer_id", "first_name", "last_name", "email", "phone",
        "date_of_birth", "address", "income", "account_status", "created_date"]


def row(**over):
    base = {
        "customer_id": "1", "first_name": "Ann", "last_name": "Lee",
        "email": "ann.lee@corp.com", "phone": "555-123-4567",
        "date_of_birth": "1985-03-15", "address": "12 High Street, Springfield",
        "income": "52000", "account_status": "active", "created_date": "2024-01-01",
    }
    base.update(over)
    return base


# --- profiler robustness ---------------------------------------------------

def test_profile_survives_malformed_customer_ids(cfg):
    """Regression: int() on a non-numeric id crashed duplicate profiling."""
    df = pd.DataFrame([row(customer_id="ABC"), row(customer_id="ABC")])
    assert profile(df, cfg).duplicate_ids == {"ABC": 2}


def test_profile_reports_missing_columns_instead_of_raising(cfg):
    """Regression: a KeyError fired before missing_columns could be returned."""
    df = pd.DataFrame([row()]).drop(columns=["income"])
    assert profile(df, cfg).missing_columns == ["income"]


def test_profile_handles_zero_rows(cfg):
    assert profile(pd.DataFrame(columns=COLS), cfg).n_rows == 0


def test_profiler_and_validator_agree_on_age(cfg):
    """Regression: the profiler checked only the upper bound, so a 10-year-old
    was invisible to it while the validator rejected the row."""
    young = pd.DataFrame([row(date_of_birth="2016-01-01")])
    assert profile(young, cfg).invalid_values["age_outside_policy"]["count"] == 1
    assert any("age" in f.check for f in validate(young, cfg, "t").failures)


# --- validation robustness -------------------------------------------------

@pytest.mark.parametrize("value", ["12.9", "abc", "1.5"])
def test_non_integer_ids_report_a_coercion_failure_not_a_crash(cfg, value):
    """Regression: pandas raised 'cannot safely cast non-equivalent object'."""
    result = validate(pd.DataFrame([row(customer_id=value)]), cfg, "t")
    assert any(f.column == "customer_id" for f in result.coercion)


def test_dataframe_check_on_a_missing_column_raises(cfg):
    df = pd.DataFrame([row()]).drop(columns=["created_date"])
    with pytest.raises(ValueError, match="dataframe check"):
        validate(df, cfg, "t")


def test_account_opened_on_date_of_birth_is_allowed(cfg):
    """op is 'le': the rule is 'not created before birth', not 'strictly after'."""
    same_day = pd.DataFrame([row(date_of_birth="1985-03-15", created_date="1985-03-15")])
    assert not any(f.check == "dob_before_created"
                   for f in validate(same_day, cfg, "t").failures)


# --- shared privacy logic --------------------------------------------------

def test_income_band_is_idempotent(cfg):
    """Regression: re-banding masked income failed to parse and collapsed every
    row onto '?', which read as a large privacy improvement."""
    once = income_band("52000", cfg.income_band_width)
    assert income_band(once, cfg.income_band_width) == once


def test_unknown_quasi_identifier_raises(cfg):
    """Silently skipping one would drop a dimension and understate risk."""
    with pytest.raises(ValueError, match="quasi-identifier"):
        signatures(pd.DataFrame([row()]), ["not_a_column"], cfg)


def test_masking_measurably_reduces_uniqueness(cfg):
    from pipeline.mask import mask

    df = pd.DataFrame([row(customer_id=str(i), income=str(50000 + i),
                           date_of_birth=f"19{60 + i % 30}-01-0{1 + i % 9}")
                       for i in range(60)])
    result = mask(df, cfg)
    assert result.unique_after < result.unique_before


def test_k_buckets_count_rows_not_groups():
    # one group of 4 contributes 4 rows to the k=3-5 band
    assert k_buckets([("a",)] * 4) == {"k=3-5": 4}


# --- scoring ---------------------------------------------------------------

def test_specificity_penalises_over_quarantining():
    from pipeline.clean import CleaningLog, Rejection
    from pipeline.score import score

    truth = {"n_rows": 10, "defects": {"x": {"column": "email", "count": 1, "rows": [0]}}}
    log = CleaningLog(rows_in=10, rows_out=0)
    log.rejections = [Rejection(i, str(i), "missing_required_field", "email", "")
                      for i in range(10)]

    class _NoLeaks:
        leaks: list = []

    card = score(truth, log, _NoLeaks())
    assert card.recall == 1.0, "quarantining everything still scores perfect recall"
    assert card.specificity == 0.0, "specificity is what catches it"


def test_config_reference_date_is_reported(cfg):
    assert cfg.reference_date is not None
    raw = dict(cfg._raw)
    raw["reference_date"] = "2021-06-01"
    assert Config(raw).reference_date_is_pinned


# --- release verification --------------------------------------------------

def test_release_verification_passes_a_correctly_masked_extract(cfg):
    from pipeline.mask import mask
    from pipeline.pii import verify_release

    leaky = pd.DataFrame([row(address="12 High St, contact a@b.com, SSN 123-45-6789")])
    assert verify_release(mask(leaky, cfg).masked) == []


def test_release_verification_catches_an_unmasked_column(cfg):
    """Regression: the check scanned only columns the policy claimed to mask,
    so removing a masking rule removed the check with it."""
    from pipeline.config import Config
    from pipeline.mask import mask
    from pipeline.pii import verify_release

    raw = dict(cfg._raw)
    raw["masking"] = {**raw["masking"], "rules": {
        k: v for k, v in raw["masking"]["rules"].items() if k != "address"}}
    weakened = Config(raw)

    leaky = pd.DataFrame([row(address="12 High St, contact a@b.com, SSN 123-45-6789")])
    residual = verify_release(mask(leaky, weakened).masked)
    assert residual, "an unsuppressed address carrying an SSN must be caught"
    assert {f.detector for f in residual} >= {"us_ssn", "email"}


def test_containment_counts_defects_reaching_the_extract():
    """Recall says the row was acted on; containment says it did not survive."""
    from pipeline.clean import CleaningLog, Repair
    from pipeline.score import score

    truth = {"n_rows": 4, "defects": {
        "phone_nonstandard_format": {"column": "phone", "count": 2, "rows": [0, 1]}}}
    log = CleaningLog(rows_in=4, rows_out=4)
    log.repaired = [Repair(0, "phone", "phone_normalised")]  # row 1 untouched

    class _NoLeaks:
        leaks: list = []

    card = score(truth, log, _NoLeaks())
    assert card.escaped == 1
    assert card.containment == 0.5
