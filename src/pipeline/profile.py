"""Part 1: profile the raw dataset to establish what is broken, before any cleaning."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from typing import Any

import pandas as pd

from pipeline.config import Config

# Values that mean "missing" without being null. Counted separately from true
# nulls because they survive dropna() and silently pollute downstream stats.
SENTINELS = {"", "null", "n/a", "na", "none", "nan", "unknown", "-", "not disclosed"}

# Human-readable expected types, for the report's schema-conformance section.
# The authoritative types are in config/rules.yml.
EXPECTED_DTYPES = {
    "customer_id": "integer", "first_name": "string", "last_name": "string",
    "email": "string", "phone": "string", "date_of_birth": "date",
    "address": "string", "income": "numeric", "account_status": "string",
    "created_date": "date",
}




@dataclass
class ColumnProfile:
    name: str
    dtype_actual: str
    dtype_expected: str
    null_count: int
    sentinel_count: int
    unique_count: int
    sample_values: list[str] = field(default_factory=list)

    @property
    def missing_count(self) -> int:
        return self.null_count + self.sentinel_count


@dataclass
class QualityProfile:
    n_rows: int
    columns: list[ColumnProfile]
    missing_columns: list[str]
    unexpected_columns: list[str]
    duplicate_ids: dict[int, int]
    format_inventory: dict[str, list[tuple[str, int, str]]]
    invalid_values: dict[str, dict[str, Any]]
    status_counts: dict[str, int]
    permitted_statuses: list[str]

    @property
    def pct_missing(self) -> dict[str, float]:
        return {c.name: 100 * c.missing_count / self.n_rows for c in self.columns}


def is_missing(v: Any) -> bool:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return True
    return str(v).strip().lower() in SENTINELS


def _signature(value: str) -> str:
    """Collapse a value to a shape: 555-123-4567 -> 999-999-9999."""
    return re.sub(r"[A-Za-z]", "A", re.sub(r"\d", "9", value.strip()))


def _format_inventory(series: pd.Series, top: int = 8) -> list[tuple[str, int, str]]:
    """Distinct shapes present in a column, most common first, with an example."""
    shapes: Counter = Counter()
    examples: dict[str, str] = {}
    for v in series:
        if is_missing(v):
            continue
        sig = _signature(str(v))
        shapes[sig] += 1
        examples.setdefault(sig, str(v).strip())
    return [(sig, n, examples[sig]) for sig, n in shapes.most_common(top)]


def _examples(values, k: int = 5) -> list:
    """First k distinct values, order preserved - repeats say nothing extra."""
    seen, out = set(), []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) == k:
            break
    return out


def _as_number(v: Any) -> float | None:
    try:
        return float(str(v).replace(",", "").replace("$", "").strip())
    except (ValueError, AttributeError):
        return None


def _as_date(v: Any) -> date | None:
    try:
        return date.fromisoformat(str(v).strip())
    except ValueError:
        return None


def profile(df: pd.DataFrame, cfg: Config) -> QualityProfile:
    n = len(df)
    today = cfg.reference_date
    max_age, cap = cfg.max_age, cfg.income_cap
    columns = []
    for name in df.columns:
        s = df[name]
        sentinels = sum(1 for v in s if v is not None and not pd.isna(v) and str(v).strip().lower() in SENTINELS)
        columns.append(ColumnProfile(
            name=name,
            dtype_actual=str(s.dtype),
            dtype_expected=EXPECTED_DTYPES.get(name, "?"),
            null_count=int(s.isna().sum()),
            sentinel_count=sentinels,
            unique_count=int(s.nunique(dropna=True)),
            sample_values=[str(v) for v in s.dropna().head(3)],
        ))

    dup_counts = df["customer_id"].value_counts()
    duplicates = {int(k): int(v) for k, v in dup_counts[dup_counts > 1].items()}

    ages = [(today.year - d.year) for d in (_as_date(v) for v in df["date_of_birth"]) if d]
    incomes = [x for x in (_as_number(v) for v in df["income"]) if x is not None]

    invalid = {
        "unparseable_date_of_birth": {
            "count": sum(1 for v in df["date_of_birth"] if not is_missing(v) and _as_date(v) is None),
            "examples": _examples(str(v) for v in df["date_of_birth"] if not is_missing(v) and _as_date(v) is None),
        },
        "unparseable_created_date": {
            "count": sum(1 for v in df["created_date"] if not is_missing(v) and _as_date(v) is None),
            "examples": _examples(str(v) for v in df["created_date"] if not is_missing(v) and _as_date(v) is None),
        },
        "non_numeric_income": {
            "count": sum(1 for v in df["income"] if not is_missing(v) and _as_number(v) is None),
            "examples": _examples(str(v) for v in df["income"] if not is_missing(v) and _as_number(v) is None),
        },
        "negative_income": {"count": sum(1 for x in incomes if x < 0), "examples": _examples(x for x in incomes if x < 0)},
        "income_above_cap": {"count": sum(1 for x in incomes if x > cap), "examples": _examples((x for x in incomes if x > cap), 3)},
        "implausible_age": {"count": sum(1 for a in ages if a > max_age or a < 0), "examples": _examples(sorted(a for a in ages if a > max_age))},
        "future_created_date": {
            "count": sum(1 for v in df["created_date"] if (d := _as_date(v)) and d > today),
            "examples": _examples((str(v) for v in df["created_date"] if (d := _as_date(v)) and d > today), 3),
        },
    }

    status_counts = Counter(str(v) for v in df["account_status"])

    expected = set(cfg.schema)
    return QualityProfile(
        n_rows=n,
        columns=columns,
        missing_columns=sorted(expected - set(df.columns)),
        unexpected_columns=sorted(set(df.columns) - expected),
        duplicate_ids=duplicates,
        format_inventory={
            "phone": _format_inventory(df["phone"]),
            "date_of_birth": _format_inventory(df["date_of_birth"]),
            "created_date": _format_inventory(df["created_date"]),
        },
        invalid_values=invalid,
        status_counts=dict(status_counts.most_common()),
        permitted_statuses=cfg.permitted_statuses,
    )
