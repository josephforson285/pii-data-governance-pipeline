"""Part 3: validate the dataset against the schema declared in config/rules.yml.

Runs twice - once on the raw data and once after cleaning. The delta between
the two is the evidence that remediation worked; a single post-clean run only
proves the clean data is clean.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import pandas as pd
import yaml
from pandera.errors import SchemaErrors
from pandera.pandas import Check, Column, DataFrameSchema

PANDERA_DTYPES = {
    "int64": "Int64", "float64": "float64", "str": "str", "date": "datetime64[ns]",
}


@dataclass
class Failure:
    column: str
    check: str
    failure_case: Any
    index: int | None


@dataclass
class ValidationResult:
    stage: str
    n_rows: int
    failures: list[Failure] = field(default_factory=list)
    coercion: list[Failure] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def by_rule(self) -> dict[str, int]:
        return dict(Counter(f"{f.column}.{f.check}" for f in self.failures).most_common())

    @property
    def failing_rows(self) -> set[int]:
        return {f.index for f in self.failures if f.index is not None}

    @property
    def coercion_by_column(self) -> dict[str, int]:
        return dict(Counter(f.column for f in self.coercion).most_common())


def load_rules(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _checks_for(column: str, spec: dict) -> list[Check]:
    """Translate the YAML check vocabulary into Pandera checks."""
    checks: list[Check] = []
    c = spec.get("checks") or {}

    if "gt" in c:
        checks.append(Check.gt(c["gt"], name="positive"))
    if "ge" in c:
        checks.append(Check.ge(c["ge"], name="not_negative"))
    if "le" in c:
        checks.append(Check.le(c["le"], name="within_cap"))
    if "isin" in c:
        checks.append(Check.isin(c["isin"], name="permitted_value"))
    if "min_len" in c or "max_len" in c:
        lo, hi = c.get("min_len", 0), c.get("max_len", 10**6)
        checks.append(Check(
            lambda s, lo=lo, hi=hi: s.astype(str).str.len().between(lo, hi),
            name=f"length_{lo}_{hi}",
        ))
    if "pattern" in c:
        checks.append(Check.str_matches(c["pattern"], name="format"))
    if "min_age" in c or "max_age" in c:
        lo, hi = c.get("min_age", 0), c.get("max_age", 150)
        checks.append(Check(
            lambda s, lo=lo, hi=hi: _age_years(s).between(lo, hi),
            name=f"age_{lo}_{hi}",
        ))
    if c.get("not_future"):
        checks.append(Check(
            lambda s: s <= pd.Timestamp(date.today()),
            name="not_in_future",
        ))
    return checks


def _age_years(s: pd.Series) -> pd.Series:
    today = pd.Timestamp(date.today())
    return ((today - s).dt.days / 365.25).round(1)


def build_schema(rules: dict) -> DataFrameSchema:
    columns = {}
    for name, spec in rules["schema"].items():
        columns[name] = Column(
            PANDERA_DTYPES[spec["dtype"]],
            checks=_checks_for(name, spec),
            nullable=spec.get("nullable", True),
            unique=spec.get("unique", False),
            coerce=True,
            required=True,
        )
    return DataFrameSchema(columns, strict=False, name="customers")


def _coerce_for_validation(df: pd.DataFrame, rules: dict) -> pd.DataFrame:
    """Best-effort typing so checks see values, not strings.

    Anything that will not convert becomes NaN/NaT and is caught by the
    nullable=False rule, so a bad value is reported rather than crashing
    the run before any other rule gets to fire.
    """
    out = df.copy()
    for name, spec in rules["schema"].items():
        if name not in out.columns:
            continue
        kind = spec["dtype"]
        if kind == "int64":
            out[name] = pd.to_numeric(out[name], errors="coerce").astype("Int64")
        elif kind == "float64":
            out[name] = pd.to_numeric(
                out[name].astype(str).str.replace(r"[$,]", "", regex=True).str.strip(),
                errors="coerce",
            )
        elif kind == "date":
            out[name] = pd.to_datetime(out[name], format="%Y-%m-%d", errors="coerce")
        else:
            out[name] = out[name].astype("string").replace({pd.NA: None})
    return out


def _coercion_failures(raw: pd.DataFrame, typed: pd.DataFrame, rules: dict) -> list[Failure]:
    """Values that were present but would not convert.

    Pandera sees these as nulls once coerced, so they land under not_nullable
    alongside genuinely absent values. Two different defects needing two
    different fixes, so they are counted apart.
    """
    from pipeline.profile import is_missing

    out: list[Failure] = []
    for name, spec in rules["schema"].items():
        if spec["dtype"] == "str" or name not in raw.columns:
            continue
        for idx, value in raw[name].items():
            if not is_missing(value) and pd.isna(typed.at[idx, name]):
                out.append(Failure(name, "uncoercible_value", str(value), int(idx)))
    return out


def validate(df: pd.DataFrame, rules: dict, stage: str) -> ValidationResult:
    schema = build_schema(rules)
    typed = _coerce_for_validation(df, rules)
    result = ValidationResult(stage=stage, n_rows=len(df))
    result.coercion = _coercion_failures(df, typed, rules)

    try:
        schema.validate(typed, lazy=True)
    except SchemaErrors as exc:
        for row in exc.failure_cases.itertuples():
            idx = getattr(row, "index", None)
            result.failures.append(Failure(
                column=str(getattr(row, "column", "?")),
                check=re.sub(r"\(.*\)", "", str(row.check)).strip(),
                failure_case=getattr(row, "failure_case", None),
                index=int(idx) if pd.notna(idx) else None,
            ))
    return result
