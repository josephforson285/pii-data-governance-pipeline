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


def test_pre_mask_containment_counts_defects_reaching_the_extract():
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
    assert card.pre_mask_containment == 0.5


def test_verify_release_ignores_suppressions():
    """Suppressions cut noise while triaging raw data. On a released extract
    they would let a real identifier through because a rule said that shape is
    usually benign."""
    from pipeline.pii import suppression_for, verify_release

    assert suppression_for("postal_code", "income"), "fixture assumes a suppression exists"
    leaky = pd.DataFrame([{"income": "contact a@b.com", "customer_id": "1"}])
    assert any(f.detector == "email" for f in verify_release(leaky))


def test_blank_ids_are_not_reported_as_duplicates(cfg):
    """Two rows with no id are two missing values, not a duplicate."""
    df = pd.DataFrame([row(customer_id=""), row(customer_id=""),
                       row(customer_id="N/A"), row(customer_id="N/A")])
    assert profile(df, cfg).duplicate_ids == {}


def test_unexpected_columns_fail_under_the_configured_policy(cfg, tmp_path):
    import subprocess
    import sys

    assert cfg.unexpected_column_policy == "fail"
    src = tmp_path / "extra.csv"
    frame = pd.DataFrame([row()])
    frame["mystery_column"] = "x"
    frame.to_csv(src, index=False)

    proc = subprocess.run(
        [sys.executable, "-m", "pipeline", "run", "--input", str(src),
         "--reports", str(tmp_path / "rep"), "--processed", str(tmp_path / "proc"),
         "--rejects", str(tmp_path / "rej")],
        capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 1
    assert "mystery_column" in proc.stderr


def test_raw_and_masked_income_bands_share_one_label(cfg):
    """The two sides of the k-anonymity comparison must read alike."""
    from pipeline.mask import make_bander
    from pipeline.privacy import income_band

    raw = income_band("52000", cfg.income_band_width)
    masked = make_bander(cfg.income_band_width)("52000")
    assert raw == masked == "50000-74999"


def test_income_band_rejects_a_non_positive_width():
    from pipeline.privacy import income_band

    with pytest.raises(ValueError, match="must be positive"):
        income_band("52000", 0)


def test_standalone_mask_refuses_unvalidated_input(tmp_path):
    """Regression: the standalone command wrote a masked file without
    validating its input or verifying its output, bypassing the gates the
    full pipeline enforces."""
    import subprocess
    import sys

    src = tmp_path / "dirty.csv"
    pd.DataFrame([row(email="not-an-email", phone="nope")]).to_csv(src, index=False)

    proc = subprocess.run(
        [sys.executable, "-m", "pipeline", "mask", "--input", str(src),
         "--processed", str(tmp_path / "proc"), "--reports", str(tmp_path / "rep")],
        capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 1
    assert not (tmp_path / "proc" / "customers_masked.csv").exists()
    assert not (tmp_path / "rep" / "masked_sample.txt").exists()


def test_profile_separates_repairable_formats_from_unrepairable_values(cfg):
    """'04/15/2020' needs a parser; 'invalid_date' needs a decision. Calling
    both unparseable told you nothing about what to do next."""
    df = pd.DataFrame([row(date_of_birth="04/15/2020"), row(date_of_birth="invalid_date"),
                       row(income="75k"), row(income="not disclosed")])
    v = profile(df, cfg).invalid_values
    assert v["date_of_birth_repairable_format"]["count"] == 1
    assert v["date_of_birth_unrepairable"]["count"] == 1
    assert v["income_repairable_format"]["count"] == 1
    # 'not disclosed' is a sentinel, so it is missing rather than unrepairable
    assert v["income_unrepairable"]["count"] == 0


def test_repairable_income_forms_are_classified_as_repairable(cfg):
    """'$52,000' parsed fine, so the repairable branch never fired and it was
    reported as already canonical."""
    df = pd.DataFrame([row(income="$52,000"), row(income="75k"),
                       row(income="60,000.00"), row(income="52000")])
    v = profile(df, cfg).invalid_values
    assert v["income_repairable_format"]["count"] == 3
    assert v["income_unrepairable"]["count"] == 0


def test_semantic_checks_cover_repairable_dates(cfg):
    """A 10-year-old written as 01/01/2016 escaped the profiler's age check
    while the validator rejected the row."""
    df = pd.DataFrame([row(date_of_birth="01/01/2016")])
    assert profile(df, cfg).invalid_values["age_outside_policy"]["count"] == 1


def test_cleaning_never_emits_an_unclassified_column(cfg):
    """Building the frame from the input's columns invented an empty column
    for anything unexpected, silently blanking whatever it held."""
    from pipeline.clean import clean

    df = pd.DataFrame([row()])
    df["marketing_note"] = "call john@example.com"
    cleaned, _ = clean(df, cfg)
    assert list(cleaned.columns) == list(cfg.schema)
    assert "marketing_note" not in cleaned.columns


def test_validation_report_reflects_coercion_only_failures(cfg, tmp_path):
    """The narrative keyed off rule failures alone, so a run blocked purely by
    coercion still read 'every row satisfies the schema'."""
    import copy

    from pipeline.config import Config
    from pipeline.report import render_validation_report

    raw = copy.deepcopy(cfg._raw)
    raw["schema"]["income"]["nullable"] = True
    nullable = Config(raw)

    src = tmp_path / "in.csv"
    clean_frame = pd.DataFrame([row()])
    clean_frame.to_csv(src, index=False)
    dirty = pd.DataFrame([row(income="abc")])
    pre = validate(clean_frame, nullable, "pre-clean")
    post = validate(dirty, nullable, "post-clean")
    assert len(post.failures) == 0 and post.coercion and not post.passed

    text = render_validation_report(pre, src, nullable, post=post)
    assert "Publication is blocked" in text
    assert "Every row remaining after cleaning satisfies" not in text


def test_failure_detail_shows_pre_clean_when_post_is_empty(cfg, tmp_path):
    """Rendering post unconditionally left an empty table under a heading
    promising 'First 40 failures'."""
    from pipeline.report import render_validation_report

    src = tmp_path / "in.csv"
    dirty = pd.DataFrame([row(email="bad"), row(customer_id="2", phone="nope")])
    dirty.to_csv(src, index=False)
    clean_frame = pd.DataFrame([row(), row(customer_id="2")])

    pre = validate(dirty, cfg, "pre-clean")
    post = validate(clean_frame, cfg, "post-clean")
    assert pre.failures and not post.failures

    text = render_validation_report(pre, src, cfg, post=post)
    assert "FAILURE DETAIL - PRE-CLEAN" in text
    assert "pre-clean failures, sampled across checks" in text


def test_failure_detail_prefers_post_when_post_fails(cfg, tmp_path):
    """When rows survive cleaning and still fail, those are the blocking ones."""
    from pipeline.report import render_validation_report

    src = tmp_path / "in.csv"
    dirty = pd.DataFrame([row(email="bad")])
    dirty.to_csv(src, index=False)

    pre = validate(dirty, cfg, "pre-clean")
    post = validate(pd.DataFrame([row(phone="nope")]), cfg, "post-clean")
    assert post.failures

    assert "FAILURE DETAIL - POST-CLEAN" in render_validation_report(pre, src, cfg, post=post)
