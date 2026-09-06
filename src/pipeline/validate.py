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
from typing import Any

import pandas as pd
from pandera.errors import SchemaErrors
from pandera.pandas import Check, Column, DataFrameSchema

from pipeline.config import Config

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


DF_CHECK_OPS = {
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
}


def _checks_for(spec: dict, cfg: Config) -> list[Check]:
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
    if c.get("income_cap"):
        checks.append(Check.le(cfg.income_cap, name="within_cap"))
    if c.get("min_age") or c.get("max_age"):
        lo, hi = cfg.min_age, cfg.max_age
        checks.append(Check(
            lambda s, lo=lo, hi=hi, ref=cfg.reference_date:
                _age_years(s, ref).between(lo, hi),
            name=f"age_{lo}_{hi}",
        ))
    if c.get("not_future"):
        checks.append(Check(
            lambda s, ref=cfg.reference_date: s <= pd.Timestamp(ref),
            name="not_in_future",
        ))
    return checks


def _age_years(s: pd.Series, reference: date) -> pd.Series:
    return ((pd.Timestamp(reference) - s).dt.days / 365.25).round(1)


def build_schema(cfg: Config) -> DataFrameSchema:
    """Build the column schema.

    strict=False: unexpected columns do not fail the schema here, because an
    unexpected column in a PII pipeline needs reporting rather than dropping -
    it may be schema drift carrying new sensitive data. The loader surfaces
    it; see run.py.
    """
    columns = {}
    for name, spec in cfg.schema.items():
        columns[name] = Column(
            PANDERA_DTYPES[spec["dtype"]],
            checks=_checks_for(spec, cfg),
            nullable=spec.get("nullable", True),
            unique=spec.get("unique", False),
            coerce=True,
            required=True,
        )
    return DataFrameSchema(columns, strict=False, name="customers")


def _dataframe_check_failures(typed: pd.DataFrame, cfg: Config) -> list[Failure]:
    """Execute the cross-column rules declared in config.

    An earlier version declared dob_before_created in YAML and never ran it,
    which is worse than omitting it: the config advertised a guarantee the
    pipeline did not provide. An unknown op now raises rather than skipping.
    """
    failures: list[Failure] = []
    for check in cfg.dataframe_checks:
        op = DF_CHECK_OPS.get(check.op)
        if op is None:
            raise ValueError(
                f"dataframe check {check.name!r} uses unknown op {check.op!r}; "
                f"known ops: {', '.join(sorted(DF_CHECK_OPS))}"
            )
        missing = [c for c in (check.left, check.right) if c not in typed.columns]
        if missing:
            # Skipping quietly would let a declared guarantee disappear the
            # moment a column is renamed.
            raise ValueError(
                f"dataframe check {check.name!r} needs column(s) "
                f"{', '.join(missing)}, which the input does not have"
            )
        left, right = typed[check.left], typed[check.right]
        comparable = left.notna() & right.notna()
        violated = comparable & ~op(left, right)
        for idx in typed.index[violated]:
            failures.append(Failure(
                column=check.right,
                check=check.name,
                failure_case=str(typed.at[idx, check.right])[:24],
                index=int(idx),
            ))
    return failures


def _coerce_for_validation(df: pd.DataFrame, cfg: Config) -> pd.DataFrame:
    """Best-effort typing so checks see values, not strings.

    Anything that will not convert becomes NaN/NaT and is caught by the
    nullable=False rule, so a bad value is reported rather than crashing
    the run before any other rule gets to fire.
    """
    out = df.copy()
    for name, spec in cfg.schema.items():
        if name not in out.columns:
            continue
        kind = spec["dtype"]
        if kind == "int64":
            # Round-trip through float would silently truncate "12.9" to 12.
            # Anything that is not an exact integer becomes NA and is reported
            # as a coercion failure instead of crashing the cast.
            numeric = pd.to_numeric(out[name], errors="coerce")
            exact = numeric.notna() & (numeric % 1 == 0)
            out[name] = numeric.where(exact).astype("Int64")
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


def _coercion_failures(raw: pd.DataFrame, typed: pd.DataFrame, cfg: Config) -> list[Failure]:
    """Values that were present but would not convert.

    Pandera sees these as nulls once coerced, so they land under not_nullable
    alongside genuinely absent values. Two different defects needing two
    different fixes, so they are counted apart.
    """
    from pipeline.profile import is_missing

    out: list[Failure] = []
    for name, spec in cfg.schema.items():
        if spec["dtype"] == "str" or name not in raw.columns:
            continue
        for idx, value in raw[name].items():
            if not is_missing(value) and pd.isna(typed.at[idx, name]):
                out.append(Failure(name, "uncoercible_value", str(value), int(idx)))
    return out


def validate(df: pd.DataFrame, cfg: Config, stage: str) -> ValidationResult:
    schema = build_schema(cfg)
    typed = _coerce_for_validation(df, cfg)
    result = ValidationResult(stage=stage, n_rows=len(df))
    result.coercion = _coercion_failures(df, typed, cfg)

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
    result.failures.extend(_dataframe_check_failures(typed, cfg))
    return result
