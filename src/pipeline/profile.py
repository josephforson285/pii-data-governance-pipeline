"""Part 1: profile the raw dataset to establish what is broken, before any cleaning."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import pandas as pd

from pipeline.config import Config

# Values that mean "missing" without being null. Counted separately from true
# nulls because they survive dropna() and silently pollute downstream stats.
SENTINELS = {"", "null", "n/a", "na", "none", "nan", "unknown", "-", "not disclosed"}

# Presentation labels for the config's dtype names. The authoritative types
# live in config/rules.yml; this only makes them readable in a report.
DTYPE_LABELS = {"int64": "integer", "float64": "numeric", "str": "string", "date": "date"}




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
    duplicate_ids: dict[str, int]
    format_inventory: dict[str, list[tuple[str, int, str]]]
    invalid_values: dict[str, dict[str, Any]]
    status_counts: dict[str, int]
    permitted_statuses: list[str]


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
    """Semantic value, accepting the forms the cleaner recovers."""
    text = str(v).strip()
    if re.fullmatch(r"\d+(\.\d+)?[kK]", text):
        return float(text[:-1]) * 1000
    try:
        return float(text.replace(",", "").replace("$", ""))
    except (ValueError, AttributeError):
        return None


def _is_canonical_number(v: Any) -> bool:
    """A bare decimal, which needs no repair."""
    return re.fullmatch(r"-?\d+(\.\d+)?", str(v).strip()) is not None


def _as_date(v: Any) -> date | None:
    """Canonical ISO only. Other formats are repairable, not invalid."""
    try:
        return date.fromisoformat(str(v).strip())
    except ValueError:
        return None


def _repairable_date(v: Any, formats: list[str]) -> bool:
    for fmt in formats:
        try:
            datetime.strptime(str(v).strip(), fmt)
            return True
        except ValueError:
            continue
    return False


def _repairable_number(v: Any) -> bool:
    """Non-canonical but recoverable: '$52,000', '60,000.00', '75k'."""
    return not _is_canonical_number(v) and _as_number(v) is not None


def profile(df: pd.DataFrame, cfg: Config) -> QualityProfile:
    """Profile the raw dataset.

    Tolerates a missing or malformed column: reporting that the input is
    unusable is the profiler's job, so it must not raise on the way to saying
    so. Every column access below goes through `col()`.
    """
    n = len(df)
    today = cfg.reference_date
    cap = cfg.income_cap
    formats = cfg.date_formats
    columns = []
    for name in df.columns:
        s = df[name]
        sentinels = sum(1 for v in s if v is not None and not pd.isna(v) and str(v).strip().lower() in SENTINELS)
        columns.append(ColumnProfile(
            name=name,
            dtype_actual=str(s.dtype),
            dtype_expected=DTYPE_LABELS.get(
                cfg.schema.get(name, {}).get("dtype", ""), "unexpected column"),
            null_count=int(s.isna().sum()),
            sentinel_count=sentinels,
            unique_count=int(s.nunique(dropna=True)),
            sample_values=[str(v) for v in s.dropna().head(3)],
        ))

    def col(name: str) -> pd.Series:
        """A column, or an empty series when the input does not have it."""
        return df[name] if name in df.columns else pd.Series([], dtype=object)

    # Counted as strings: coercing to int crashes on a malformed id, which is
    # itself a defect worth reporting. Absent ids are excluded - two blank ids
    # are two missing values, not a duplicate.
    ids = [str(v) for v in col("customer_id") if not is_missing(v)]
    dup_counts = pd.Series(ids, dtype=object).value_counts()
    duplicates = {str(k): int(v) for k, v in dup_counts[dup_counts > 1].items()} if ids else {}

    # Semantic checks parse everything the cleaner could parse. Restricting
    # them to canonical ISO let a repairable date carrying an impossible age
    # slip past the profiler while the validator rejected it.
    def parsed_date(v: Any) -> date | None:
        canonical = _as_date(v)
        if canonical:
            return canonical
        for fmt in formats:
            try:
                return datetime.strptime(str(v).strip(), fmt).date()
            except ValueError:
                continue
        return None

    ages = [(today - d).days / 365.25
            for d in (parsed_date(v) for v in col("date_of_birth")) if d]
    incomes = [x for x in (_as_number(v) for v in col("income")) if x is not None]

    invalid = {
        # Split by what remediation can do: a repairable format needs a
        # parser, an unrepairable value needs a decision.
        "date_of_birth_repairable_format": {
            "count": sum(1 for v in col("date_of_birth") if not is_missing(v)
                         and _as_date(v) is None and _repairable_date(v, formats)),
            "examples": _examples(str(v) for v in col("date_of_birth") if not is_missing(v)
                                  and _as_date(v) is None and _repairable_date(v, formats)),
        },
        "date_of_birth_unrepairable": {
            "count": sum(1 for v in col("date_of_birth") if not is_missing(v)
                         and _as_date(v) is None and not _repairable_date(v, formats)),
            "examples": _examples(str(v) for v in col("date_of_birth") if not is_missing(v)
                                  and _as_date(v) is None and not _repairable_date(v, formats)),
        },
        "created_date_repairable_format": {
            "count": sum(1 for v in col("created_date") if not is_missing(v)
                         and _as_date(v) is None and _repairable_date(v, formats)),
            "examples": _examples(str(v) for v in col("created_date") if not is_missing(v)
                                  and _as_date(v) is None and _repairable_date(v, formats)),
        },
        "created_date_unrepairable": {
            "count": sum(1 for v in col("created_date") if not is_missing(v)
                         and _as_date(v) is None and not _repairable_date(v, formats)),
            "examples": _examples(str(v) for v in col("created_date") if not is_missing(v)
                                  and _as_date(v) is None and not _repairable_date(v, formats)),
        },
        "income_repairable_format": {
            "count": sum(1 for v in col("income")
                         if not is_missing(v) and _repairable_number(v)),
            "examples": _examples(str(v) for v in col("income")
                                  if not is_missing(v) and _repairable_number(v)),
        },
        "income_unrepairable": {
            "count": sum(1 for v in col("income") if not is_missing(v)
                         and not _is_canonical_number(v) and not _repairable_number(v)),
            "examples": _examples(str(v) for v in col("income") if not is_missing(v)
                                  and not _is_canonical_number(v)
                                  and not _repairable_number(v)),
        },
        "negative_income": {"count": sum(1 for x in incomes if x < 0), "examples": _examples(x for x in incomes if x < 0)},
        "income_above_cap": {"count": sum(1 for x in incomes if x > cap), "examples": _examples((x for x in incomes if x > cap), 3)},
        # Same bounds and the same date formats the cleaner uses, so profiler,
        # cleaner and validator agree on coverage as well as verdict.
        "age_outside_policy": {
            "count": sum(1 for a in ages if not cfg.min_age <= a <= cfg.max_age),
            "examples": _examples(sorted(f"{a:.1f}y" for a in ages
                                         if not cfg.min_age <= a <= cfg.max_age)),
        },
        "future_created_date": {
            "count": sum(1 for v in col("created_date") if (d := parsed_date(v)) and d > today),
            "examples": _examples((str(v) for v in col("created_date")
                                   if (d := parsed_date(v)) and d > today), 3),
        },
    }

    status_counts = Counter(str(v) for v in col("account_status"))

    expected = set(cfg.schema)
    return QualityProfile(
        n_rows=n,
        columns=columns,
        missing_columns=sorted(expected - set(df.columns)),
        unexpected_columns=sorted(set(df.columns) - expected),
        duplicate_ids=duplicates,
        format_inventory={
            "phone": _format_inventory(col("phone")),
            "date_of_birth": _format_inventory(col("date_of_birth")),
            "created_date": _format_inventory(col("created_date")),
        },
        invalid_values=invalid,
        status_counts=dict(status_counts.most_common()),
        permitted_statuses=cfg.permitted_statuses,
    )
