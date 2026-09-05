"""Part 4: normalise what is unambiguous, quarantine what is not.

No row is dropped silently. Every rejected row is written to the quarantine
file with the reason it failed, and the run asserts

    rows_in == rows_cleaned + rows_quarantined

so data cannot go missing without the pipeline noticing.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import pandas as pd

from pipeline.profile import is_missing

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
NAME_STRIP_RE = re.compile(r"[^A-Za-z '\-]")
MIN_AGE, MAX_AGE = 18, 120
INCOME_CAP = 10_000_000


@dataclass
class Rejection:
    row: int
    customer_id: str
    reason: str
    column: str
    value: str


@dataclass
class Repair:
    row: int
    column: str
    tag: str


@dataclass
class CleaningLog:
    rows_in: int
    rows_out: int = 0
    repairs: Counter = field(default_factory=Counter)
    repaired: list[Repair] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)

    def touched_rows(self, column: str) -> set[int]:
        """Rows this run acted on for a column, whether repaired or rejected."""
        return ({r.row for r in self.rejections if r.column == column}
                | {r.row for r in self.repaired if r.column == column})

    @property
    def rows_quarantined(self) -> int:
        return len({r.row for r in self.rejections})

    @property
    def reasons(self) -> dict[str, int]:
        return dict(Counter(r.reason for r in self.rejections).most_common())

    def reconciles(self) -> bool:
        return self.rows_in == self.rows_out + self.rows_quarantined


# --- field normalisers -----------------------------------------------------
# Each returns (value, repair_tag) on success or (None, reason) on failure.

def clean_name(value: Any) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    stripped = NAME_STRIP_RE.sub("", raw).strip()
    stripped = re.sub(r"\s+", " ", stripped)
    if len(stripped) < 2:
        return None, "name_too_short"
    out = stripped.title()
    if out != raw:
        return out, "name_normalised"
    return out, None


def clean_phone(value: Any) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    digits = re.sub(r"\D", "", str(value))
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return None, "unparseable_phone"
    out = f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return out, None if out == str(value) else "phone_normalised"


def clean_date(value: Any, formats: list[str]) -> tuple[date | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value).strip()
    for fmt in formats:
        try:
            parsed = datetime.strptime(raw, fmt).date()
            return parsed, None if fmt == "%Y-%m-%d" else "date_normalised"
        except ValueError:
            continue
    return None, "unparseable_date"


def clean_income(value: Any) -> tuple[float | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value).strip().replace(",", "").replace("$", "")
    tag = None
    if re.fullmatch(r"\d+(\.\d+)?[kK]", raw):
        raw, tag = str(float(raw[:-1]) * 1000), "income_suffix_expanded"
    try:
        amount = float(raw)
    except ValueError:
        return None, "unparseable_income"
    if amount < 0 or amount > INCOME_CAP:
        return None, "income_out_of_range"
    if tag is None and str(value).strip() != f"{amount}":
        tag = "income_normalised"
    return round(amount, 2), tag


def clean_status(value: Any, aliases: dict[str, str]) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    lowered = raw.strip().lower()
    if lowered in {"active", "inactive", "suspended"}:
        return lowered, None if lowered == raw else "status_normalised"
    if lowered in aliases:
        return aliases[lowered], "status_alias_mapped"
    return None, "unmappable_account_status"


def clean_email(value: Any) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    lowered = raw.strip().lower()
    if not EMAIL_RE.fullmatch(lowered):
        return None, "malformed_email"
    return lowered, None if lowered == raw else "email_normalised"


def clean_address(value: Any) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    collapsed = re.sub(r"\s+", " ", raw).strip()
    if len(collapsed) < 10:
        return None, "address_too_short"
    return collapsed, None if collapsed == raw else "address_normalised"


def clean(df: pd.DataFrame, rules: dict) -> tuple[pd.DataFrame, CleaningLog]:
    policy = rules["remediation"]
    formats = policy["date_formats"]
    aliases = policy["status_aliases"]
    today = date.today()

    log = CleaningLog(rows_in=len(df))
    kept: list[dict] = []
    seen_ids: set[int] = set()

    for idx, row in df.iterrows():
        idx = int(idx)
        cid_raw = str(row["customer_id"])
        reasons: list[Rejection] = []

        def take(column: str, result: tuple[Any, str | None]):
            value, tag = result
            if value is None:
                reasons.append(Rejection(idx, cid_raw, tag or "invalid", column, str(row[column])[:40]))
            elif tag:
                log.repairs[tag] += 1
                log.repaired.append(Repair(idx, column, tag))
            return value

        try:
            cid = int(float(cid_raw))
            if cid <= 0:
                raise ValueError
        except ValueError:
            reasons.append(Rejection(idx, cid_raw, "missing_required_field", "customer_id", cid_raw))
            cid = None

        record = {
            "customer_id": cid,
            "first_name": take("first_name", clean_name(row["first_name"])),
            "last_name": take("last_name", clean_name(row["last_name"])),
            "email": take("email", clean_email(row["email"])),
            "phone": take("phone", clean_phone(row["phone"])),
            "date_of_birth": take("date_of_birth", clean_date(row["date_of_birth"], formats)),
            "address": take("address", clean_address(row["address"])),
            "income": take("income", clean_income(row["income"])),
            "account_status": take("account_status", clean_status(row["account_status"], aliases)),
            "created_date": take("created_date", clean_date(row["created_date"], formats)),
        }

        dob = record["date_of_birth"]
        if dob is not None:
            age = (today - dob).days / 365.25
            if not MIN_AGE <= age <= MAX_AGE:
                reasons.append(Rejection(idx, cid_raw, "implausible_age", "date_of_birth", dob.isoformat()))
        created = record["created_date"]
        if created is not None and created > today:
            reasons.append(Rejection(idx, cid_raw, "future_created_date", "created_date", created.isoformat()))
        if cid is not None and cid in seen_ids:
            reasons.append(Rejection(idx, cid_raw, "duplicate_customer_id", "customer_id", cid_raw))

        if reasons:
            log.rejections.extend(reasons)
            continue

        seen_ids.add(cid)
        record["date_of_birth"] = dob.isoformat()
        record["created_date"] = created.isoformat()
        kept.append(record)

    log.rows_out = len(kept)
    return pd.DataFrame(kept, columns=list(df.columns)), log


# Fields whose absence degrades a record without invalidating it. Used only to
# report what a laxer policy would retain - the pipeline still enforces the
# schema in config/rules.yml as written.
NON_CRITICAL = {"income", "address", "phone"}


def policy_sensitivity(log: CleaningLog) -> dict[str, int]:
    """How much of the quarantine is driven by the strict nullability rule.

    A row failing only because an optional field was blank is a policy
    decision, not a data defect. Quantifying it keeps that decision visible
    instead of hiding it inside a row count.
    """
    grouped: dict[int, list[Rejection]] = {}
    for r in log.rejections:
        grouped.setdefault(r.row, []).append(r)

    recoverable = sum(
        1 for rs in grouped.values()
        if all(r.column in NON_CRITICAL and r.reason == "missing_required_field" for r in rs)
    )
    return {
        "quarantined": len(grouped),
        "recoverable_under_tiered_policy": recoverable,
        "retention_if_relaxed": log.rows_out + recoverable,
    }


def quarantine_frame(log: CleaningLog) -> pd.DataFrame:
    """One row per rejected record, reasons joined - rejections are auditable."""
    grouped: dict[int, list[Rejection]] = {}
    for r in log.rejections:
        grouped.setdefault(r.row, []).append(r)
    return pd.DataFrame([
        {
            "source_row": row,
            "customer_id": rs[0].customer_id,
            "failure_count": len(rs),
            "failure_reason": "; ".join(sorted({r.reason for r in rs})),
            "failing_columns": "; ".join(sorted({r.column for r in rs})),
            "sample_values": " | ".join(f"{r.column}={r.value}" for r in rs)[:180],
        }
        for row, rs in sorted(grouped.items())
    ])
