"""Masking is a security control: a bug here discloses data rather than
crashing. These tests carry more weight than the rest of the suite."""
from __future__ import annotations

import pandas as pd
import pytest

from pipeline.mask import (
    MASKED_ADDRESS, apply_masks, band_income,
    mask_address, mask_dob, mask_email, mask_name, mask_phone,
)


@pytest.mark.parametrize("value,expected", [
    ("John", "J***"),
    ("john", "J***"),
    ("  Mary  ", "M***"),
    ("O'Brien", "O***"),
    ("", ""),
    (None, ""),
])
def test_mask_name(value, expected):
    assert mask_name(value) == expected


def test_mask_name_hides_length():
    assert mask_name("Al") == mask_name("Alexandria")


@pytest.mark.parametrize("value,expected", [
    ("john.doe@gmail.com", "j***@gmail.com"),
    ("JOHN@Corp.COM", "j***@Corp.COM"),
    ("@nodomain.com", "***@nodomain.com"),
    ("not-an-email", "***"),
    ("", "***"),
])
def test_mask_email(value, expected):
    assert mask_email(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("555-123-4567", "***-***-4567"),
    ("(555) 123-4567", "***-***-4567"),
    ("5551234567", "***-***-4567"),
    ("12", "***-***-****"),
    ("", "***-***-****"),
])
def test_mask_phone(value, expected):
    assert mask_phone(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("1985-03-15", "1985-**-**"),
    ("invalid_date", "****-**-**"),
    ("", "****-**-**"),
])
def test_mask_dob(value, expected):
    assert mask_dob(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("52000.0", "50000-74999"),
    ("0", "0-24999"),
    ("24999.99", "0-24999"),
    ("not a number", "unknown"),
])
def test_band_income(value, expected):
    assert band_income(value) == expected


def test_address_is_replaced_not_partially_masked():
    leaky = "12 High St, Springfield 90210, contact john@corp.com, SSN 123-45-6789"
    assert mask_address(leaky) == MASKED_ADDRESS


@pytest.mark.parametrize("masker,value", [
    (mask_name, "Jonathan"),
    (mask_email, "jon.smith@gmail.com"),
    (mask_phone, "555-123-4567"),
    (mask_address, "12 High Street, Springfield"),
    (mask_dob, "1985-03-15"),
    (band_income, "52000.0"),
])
def test_masking_is_idempotent(masker, value):
    """Re-masking already-masked data must not degrade or crash it."""
    once = masker(value)
    assert masker(once) == once


def test_no_original_value_survives_masking():
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
    row = apply_masks(df).iloc[0].to_dict()
    blob = " ".join(str(v) for v in row.values())

    for secret in ["Jonathan", "Smithers", "jonathan.smithers", "555-123",
                   "03-15", "High Street", "90210", "123-45-6789", "52000"]:
        assert secret not in blob, f"{secret!r} survived masking"


def test_masking_preserves_row_count_and_columns():
    df = pd.DataFrame([{c: "x" for c in
                        ["customer_id", "first_name", "last_name", "email", "phone",
                         "date_of_birth", "address", "income", "account_status", "created_date"]}] * 5)
    out = apply_masks(df)
    assert len(out) == len(df)
    assert list(out.columns) == list(df.columns)


def test_non_pii_columns_are_untouched():
    df = pd.DataFrame([{"customer_id": "7", "account_status": "active", "created_date": "2024-01-01"}])
    out = apply_masks(df)
    assert out.iloc[0].to_dict() == df.iloc[0].to_dict()
