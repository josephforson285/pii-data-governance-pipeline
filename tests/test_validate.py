"""Validation must execute every rule the config declares."""
from __future__ import annotations

from datetime import date

import pandas as pd
import pytest

from pipeline.config import Config
from pipeline.validate import build_schema, validate


def _frame(rows):
    cols = ["customer_id", "first_name", "last_name", "email", "phone",
            "date_of_birth", "address", "income", "account_status", "created_date"]
    return pd.DataFrame(rows, columns=cols)


def _row(**over):
    base = {
        "customer_id": "1", "first_name": "Ann", "last_name": "Lee",
        "email": "ann.lee@corp.com", "phone": "555-123-4567",
        "date_of_birth": "1985-03-15", "address": "12 High Street, Springfield",
        "income": "52000.0", "account_status": "active", "created_date": "2024-01-01",
    }
    base.update(over)
    return base


def test_clean_row_passes(cfg):
    assert validate(_frame([_row()]), cfg, "test").passed


def test_declared_dataframe_checks_actually_run(cfg):
    """Regression: dob_before_created was declared in YAML and never executed,
    so the config advertised a guarantee the pipeline did not provide."""
    assert cfg.dataframe_checks, "config declares no cross-column checks"
    result = validate(_frame([_row(date_of_birth="1990-01-01", created_date="1985-01-01")]),
                      cfg, "test")
    assert any(f.check == "dob_before_created" for f in result.failures)


def test_unknown_dataframe_op_raises_rather_than_skipping(cfg):
    raw = dict(cfg._raw)
    raw["dataframe_checks"] = [{"name": "bogus", "left": "income", "right": "income",
                                "op": "sideways", "description": "x"}]
    with pytest.raises(ValueError, match="unknown op"):
        validate(_frame([_row()]), Config(raw), "test")


def test_lazy_collects_every_failure_not_just_the_first(cfg):
    result = validate(_frame([_row(email="bad", phone="nope", account_status="closed")]),
                      cfg, "test")
    columns = {f.column for f in result.failures}
    assert {"email", "phone", "account_status"} <= columns


def test_uncoercible_values_counted_apart_from_absent_ones(cfg):
    result = validate(_frame([_row(date_of_birth="invalid_date"), _row(date_of_birth="")]),
                      cfg, "test")
    assert len(result.coercion) == 1
    assert result.coercion[0].column == "date_of_birth"


def test_age_bounds_come_from_config(cfg):
    schema = build_schema(cfg)
    names = [c.name for c in schema.columns["date_of_birth"].checks]
    assert f"age_{cfg.min_age}_{cfg.max_age}" in names


def test_reference_date_makes_results_deterministic(cfg):
    """Regression: date.today() meant the same input produced different
    results as time passed."""
    raw = dict(cfg._raw)
    raw["reference_date"] = "2020-01-01"
    pinned = Config(raw)
    assert pinned.reference_date == date(2020, 1, 1)
    assert pinned.reference_date_is_pinned

    # Someone born in 1905 is 115 at the pinned date and over the cap today.
    row = _frame([_row(date_of_birth="1905-01-01", created_date="2019-01-01")])
    assert validate(row, pinned, "test").passed
