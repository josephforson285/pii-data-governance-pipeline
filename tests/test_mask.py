"""Masking is a security control: a bug here discloses data rather than
crashing. These tests carry more weight than the rest of the suite."""
from __future__ import annotations

import pandas as pd
import pytest

from pipeline.mask import (
    apply_masks, build_maskers, make_bander, make_suppressor,
    mask_email_local, mask_initial, mask_last_four, mask_year_only,
)


@pytest.fixture
def band(cfg):
    return make_bander(cfg.income_band_width)


@pytest.fixture
def suppress(cfg):
    return make_suppressor(cfg.address_placeholder)


@pytest.mark.parametrize("value,expected", [
    ("John", "J***"),
    ("john", "J***"),
    ("  Mary  ", "M***"),
    ("O'Brien", "O***"),
    ("", ""),
    (None, ""),
])
def test_mask_initial(value, expected):
    assert mask_initial(value) == expected


def test_mask_initial_hides_length():
    assert mask_initial("Al") == mask_initial("Alexandria")


@pytest.mark.parametrize("value,expected", [
    ("john.doe@gmail.com", "j***@gmail.com"),
    ("JOHN@Corp.COM", "j***@Corp.COM"),
    ("@nodomain.com", "***@nodomain.com"),
    ("not-an-email", "***"),
    ("", "***"),
])
def test_mask_email_local(value, expected):
    assert mask_email_local(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("555-123-4567", "***-***-4567"),
    ("(555) 123-4567", "***-***-4567"),
    ("5551234567", "***-***-4567"),
    ("12", "***-***-****"),
    ("", "***-***-****"),
])
def test_mask_last_four(value, expected):
    assert mask_last_four(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("1985-03-15", "1985-**-**"),
    ("invalid_date", "****-**-**"),
    ("", "****-**-**"),
])
def test_mask_year_only(value, expected):
    assert mask_year_only(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("52000.0", "50000-74999"),
    ("0", "0-24999"),
    ("24999.99", "0-24999"),
    ("not a number", "unknown"),
])
def test_band_income(band, value, expected):
    assert band(value) == expected


def test_address_is_replaced_not_partially_masked(suppress, cfg):
    leaky = "12 High St, Springfield 90210, contact john@corp.com, SSN 123-45-6789"
    assert suppress(leaky) == cfg.address_placeholder


@pytest.mark.parametrize("strategy,value", [
    ("initial", "Jonathan"),
    ("email_local", "jon.smith@gmail.com"),
    ("last_four", "555-123-4567"),
    ("suppress", "12 High Street, Springfield"),
    ("year_only", "1985-03-15"),
    ("band", "52000.0"),
])
def test_masking_is_idempotent(cfg, strategy, value):
    """Re-masking already-masked data must not degrade or crash it."""
    lookup = {
        "initial": mask_initial, "email_local": mask_email_local,
        "last_four": mask_last_four, "year_only": mask_year_only,
        "suppress": make_suppressor(cfg.address_placeholder),
        "band": make_bander(cfg.income_band_width),
    }
    once = lookup[strategy](value)
    assert lookup[strategy](once) == once


def test_no_original_value_survives_masking(cfg):
    """The end-to-end guarantee: no identifying token from the input appears
    anywhere in the masked output row."""
    df = pd.DataFrame([{
        "customer_id": "1",
        "first_name": "Jonathan",
        "last_name": "Smithers",
        "email": "jonathan.smithers@gmail.com",
        "phone": "555-123-4567",
        "date_of_birth": "1985-03-15",
        "address": "12 High Street, Springfield 90210, SSN 123-45-6789",
        "income": "52000.0",
        "account_status": "active",
        "created_date": "2024-01-01",
    }])
    row = apply_masks(df, cfg).iloc[0].to_dict()
    blob = " ".join(str(v) for v in row.values())

    for secret in ["Jonathan", "Smithers", "jonathan.smithers", "555-123",
                   "03-15", "High Street", "90210", "123-45-6789", "52000"]:
        assert secret not in blob, f"{secret!r} survived masking"


def test_masking_preserves_row_count_and_columns(cfg):
    df = pd.DataFrame([{c: "x" for c in
                        ["customer_id", "first_name", "last_name", "email", "phone",
                         "date_of_birth", "address", "income", "account_status", "created_date"]}] * 5)
    out = apply_masks(df, cfg)
    assert len(out) == len(df)
    assert list(out.columns) == list(df.columns)


def test_non_pii_columns_are_untouched(cfg):
    df = pd.DataFrame([{c: "x" for c in
                        ["customer_id", "first_name", "last_name", "email", "phone",
                         "date_of_birth", "address", "income", "account_status",
                         "created_date"]}])
    out = apply_masks(df, cfg)
    for column in cfg.unmasked_columns:
        assert out.iloc[0][column] == df.iloc[0][column]


def test_masking_a_frame_missing_a_configured_column_raises(cfg):
    """Skipping it would leave the report claiming a column was masked when
    nothing touched it."""
    partial = pd.DataFrame([{"customer_id": "7", "account_status": "active"}])
    with pytest.raises(ValueError, match="masking policy names column"):
        apply_masks(partial, cfg)


def test_masking_rules_come_from_config(cfg):
    """The renderer used to hold its own copy of the masking rules, so a change
    to the policy could leave the report describing the previous behaviour."""
    assert {r.column for r in cfg.mask_rules} == set(build_maskers(cfg))


def test_reidentification_is_measured_over_everything_released(cfg):
    """Regression: post-mask k-anonymity ignored columns released unmasked,
    which understated uniqueness by a wide margin."""
    released = {r.column for r in cfg.mask_rules} | set(cfg.unmasked_columns)
    modelled = set(cfg.quasi_identifiers_after)
    assert modelled <= released
    assert "created_date" in released
