"""Cleaning must never produce a plausible value that is not the one given."""
from __future__ import annotations

import pandas as pd
import pytest

from pipeline.clean import (
    clean, clean_address, clean_customer_id, clean_email, clean_income,
    clean_name, clean_phone, clean_status, policy_sensitivity, quarantine_frame,
)


@pytest.mark.parametrize("value", ["José", "Müller", "Nguyễn", "Zoë", "Łukasz", "Ana"])
def test_names_in_any_script_survive_cleaning(value):
    """Regression: stripping non-ASCII silently turned Jose into Jos."""
    out, tag = clean_name(value)
    assert out == value.title(), f"{value!r} was corrupted to {out!r}"


@pytest.mark.parametrize("value", ["J0hn", "John123", "N/A@", "***", "12345"])
def test_malformed_names_are_rejected_not_repaired(value):
    out, reason = clean_name(value)
    assert out is None
    assert reason in {"malformed_name", "missing_required_field"}


@pytest.mark.parametrize("value,expected", [
    ("  john   smith ", "John Smith"),
    ("o'brien", "O'Brien"),
    ("ANNE-MARIE", "Anne-Marie"),
])
def test_name_normalisation(value, expected):
    assert clean_name(value)[0] == expected


def test_name_length_bounds():
    assert clean_name("X")[1] == "name_too_short"
    assert clean_name("A" * 60, max_len=50)[1] == "name_too_long"


@pytest.mark.parametrize("value,expected", [
    ("42", 42),
    ("007", 7),
    (" 42 ", 42),
])
def test_customer_id_accepts_integers(value, expected):
    assert clean_customer_id(value)[0] == expected


@pytest.mark.parametrize("value", ["12.9", "1e3", "12.0", "-5", "0", "abc", "4,2"])
def test_customer_id_rejects_anything_not_an_exact_positive_integer(value):
    """Regression: int(float(x)) turned '12.9' into 12 and '1e3' into 1000."""
    out, reason = clean_customer_id(value)
    assert out is None, f"{value!r} was silently accepted as {out}"
    assert reason in {"invalid_customer_id", "missing_required_field"}


def test_address_length_bounds_both_enforced():
    assert clean_address("x" * 250, max_len=200)[1] == "address_too_long"
    assert clean_address("PO Box")[1] == "address_too_short"
    assert clean_address("12 High Street, Springfield")[0] == "12 High Street, Springfield"


def test_income_suffix_and_cap(cfg):
    assert clean_income("75k", cfg.income_cap)[0] == 75000.0
    assert clean_income("$52,000", cfg.income_cap)[0] == 52000.0
    assert clean_income("-1", cfg.income_cap)[1] == "income_out_of_range"
    assert clean_income("99999999999", cfg.income_cap)[1] == "income_out_of_range"


def test_status_alias_and_rejection(cfg):
    permitted, aliases = cfg.permitted_statuses, cfg.status_aliases
    assert clean_status("  ACTIVE ", permitted, aliases)[0] == "active"
    assert clean_status("actv", permitted, aliases)[0] == "active"
    assert clean_status("closed", permitted, aliases)[1] == "unmappable_account_status"


def test_email_lowercased_and_validated():
    assert clean_email("John.Doe@Gmail.com")[0] == "john.doe@gmail.com"
    assert clean_email("john@@corp.com")[1] == "malformed_email"


def _frame(rows):
    cols = ["customer_id", "first_name", "last_name", "email", "phone",
            "date_of_birth", "address", "income", "account_status", "created_date"]
    return pd.DataFrame(rows, columns=cols)


def _row(**over):
    base = {
        "customer_id": "1", "first_name": "Ann", "last_name": "Lee",
        "email": "ann.lee@corp.com", "phone": "555-123-4567",
        "date_of_birth": "1985-03-15", "address": "12 High Street, Springfield",
        "income": "52000", "account_status": "active", "created_date": "2024-01-01",
    }
    base.update(over)
    return base


def test_reconciliation_holds(cfg):
    df = _frame([_row(customer_id=str(i)) for i in range(1, 6)] + [_row(email="bad")])
    cleaned, log = clean(df, cfg)
    assert log.reconciles()
    assert log.rows_in == len(cleaned) + log.rows_quarantined


def test_duplicate_detection_does_not_depend_on_quarantine_order(cfg):
    """Regression: duplicates were derived from surviving rows, so a duplicate
    went undetected when its twin was rejected for an unrelated reason."""
    df = _frame([
        _row(customer_id="7", email="broken"),   # rejected for the email
        _row(customer_id="7"),                   # its twin - still a duplicate id
        _row(customer_id="8"),
    ])
    cleaned, log = clean(df, cfg)
    assert "duplicate_customer_id" in log.reasons
    assert cleaned["customer_id"].is_unique


def test_created_before_birth_is_rejected(cfg):
    df = _frame([_row(date_of_birth="1990-01-01", created_date="1985-01-01")])
    cleaned, log = clean(df, cfg)
    assert log.reasons.get("created_before_birth") == 1
    assert len(cleaned) == 0


def test_quarantine_redacts_sensitive_values(cfg):
    df = _frame([_row(email="jane.doe.secret@corp.com", phone="bad")])
    _, log = clean(df, cfg)
    frame = quarantine_frame(log, cfg.sensitive_columns)
    blob = " ".join(frame["sample_values"])
    assert "jane.doe.secret" not in blob


def test_policy_sensitivity_counts_only_optional_field_failures(cfg):
    df = _frame([_row(income=""), _row(email="broken")])
    _, log = clean(df, cfg)
    s = policy_sensitivity(log, cfg.non_critical)
    assert s["recoverable_under_tiered_policy"] == 1
