"""Part 4: normalise what is unambiguous, quarantine what is not.

No row is dropped silently. Every rejected row is written to the quarantine
file with the reason it failed, and the run asserts

    rows_in == rows_cleaned + rows_quarantined

so data cannot go missing without the pipeline noticing.

The rule this module follows throughout: repair only where the intended value
is recoverable without guessing. Stripping a character out of a name or a
digit out of an identifier produces a plausible value that is not the one the
customer gave, which is worse than a rejection because nothing downstream can
tell it happened.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import pandas as pd

from pipeline.config import Config
from pipeline.profile import is_missing

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# A letter in any script, plus the separators a name may legitimately contain.
NAME_ALLOWED = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ '\-])*$")


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

def clean_name(value: Any, min_len: int = 2, max_len: int = 50) -> tuple[str | None, str | None]:
    """Normalise whitespace and case; reject anything else.

    Deliberately does not strip disallowed characters. An earlier version
    removed them, which silently turned 'Jose' into 'Jos' and 'Nguyen' into
    'Nguyn' while reporting the row as successfully repaired - a corrupted
    name that no downstream check could detect.
    """
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    collapsed = re.sub(r"\s+", " ", raw).strip()
    if not collapsed:
        return None, "missing_required_field"
    if not NAME_ALLOWED.fullmatch(collapsed):
        return None, "malformed_name"
    if len(collapsed) < min_len:
        return None, "name_too_short"
    if len(collapsed) > max_len:
        return None, "name_too_long"
    out = collapsed.title()
    return out, None if out == raw else "name_normalised"


def clean_customer_id(value: Any) -> tuple[int | None, str | None]:
    """Accept only an exact positive integer.

    int(float(x)) was silently truncating: '12.9' became 12 and '1e3' became
    1000. An identifier that quietly changes value is worse than one that is
    rejected, because every join downstream then points at the wrong customer.
    """
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value).strip()
    if not re.fullmatch(r"\d+", raw):
        return None, "invalid_customer_id"
    parsed = int(raw)
    if parsed <= 0:
        return None, "invalid_customer_id"
    return parsed, None if raw == str(parsed) else "customer_id_normalised"


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


def clean_income(value: Any, cap: float) -> tuple[float | None, str | None]:
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
    if amount < 0 or amount > cap:
        return None, "income_out_of_range"
    if tag is None and str(value).strip() != f"{amount}":
        tag = "income_normalised"
    return round(amount, 2), tag


def clean_status(value: Any, permitted: list[str],
                 aliases: dict[str, str]) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    lowered = raw.strip().lower()
    if lowered in permitted:
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


def clean_address(value: Any, min_len: int = 10,
                  max_len: int = 200) -> tuple[str | None, str | None]:
    if is_missing(value):
        return None, "missing_required_field"
    raw = str(value)
    collapsed = re.sub(r"\s+", " ", raw).strip()
    if len(collapsed) < min_len:
        return None, "address_too_short"
    if len(collapsed) > max_len:
        return None, "address_too_long"
    return collapsed, None if collapsed == raw else "address_normalised"


def clean(df: pd.DataFrame, cfg: Config) -> tuple[pd.DataFrame, CleaningLog]:
    formats = cfg.date_formats
    aliases = cfg.status_aliases
    permitted = cfg.permitted_statuses
    today = cfg.reference_date
    name_min, name_max = cfg.length_bounds("first_name")
    addr_min, addr_max = cfg.length_bounds("address")

    log = CleaningLog(rows_in=len(df))
    kept: list[dict] = []
    seen_ids: set[int] = set()

    # Duplicate ids are identified over the whole input, before any row is
    # quarantined. Deriving them from surviving rows made detection depend on
    # what the previous checks happened to reject.
    parsed_ids = [clean_customer_id(v)[0] for v in df["customer_id"]]
    id_counts = Counter(i for i in parsed_ids if i is not None)
    duplicated_ids = {i for i, n in id_counts.items() if n > 1}

    for position, (idx, row) in enumerate(df.iterrows()):
        idx = int(idx)
        cid_raw = str(row["customer_id"])
        reasons: list[Rejection] = []

        def take(column: str, result: tuple[Any, str | None]):
            value, tag = result
            if value is None:
                reasons.append(Rejection(idx, cid_raw, tag or "invalid", column,
                                         str(row[column])[:40]))
            elif tag:
                log.repairs[tag] += 1
                log.repaired.append(Repair(idx, column, tag))
            return value

        cid = take("customer_id", clean_customer_id(row["customer_id"]))
        record = {
            "customer_id": cid,
            "first_name": take("first_name", clean_name(row["first_name"], name_min, name_max)),
            "last_name": take("last_name", clean_name(row["last_name"], name_min, name_max)),
            "email": take("email", clean_email(row["email"])),
            "phone": take("phone", clean_phone(row["phone"])),
            "date_of_birth": take("date_of_birth", clean_date(row["date_of_birth"], formats)),
            "address": take("address", clean_address(row["address"], addr_min, addr_max)),
            "income": take("income", clean_income(row["income"], cfg.income_cap)),
            "account_status": take("account_status",
                                   clean_status(row["account_status"], permitted, aliases)),
            "created_date": take("created_date", clean_date(row["created_date"], formats)),
        }

        dob = record["date_of_birth"]
        if dob is not None:
            age = (today - dob).days / 365.25
            if not cfg.min_age <= age <= cfg.max_age:
                reasons.append(Rejection(idx, cid_raw, "implausible_age",
                                         "date_of_birth", dob.isoformat()))
        created = record["created_date"]
        if created is not None and created > today:
            reasons.append(Rejection(idx, cid_raw, "future_created_date",
                                     "created_date", created.isoformat()))
        if dob is not None and created is not None and created < dob:
            reasons.append(Rejection(idx, cid_raw, "created_before_birth",
                                     "created_date", created.isoformat()))

        # First occurrence of a duplicated id is kept, later ones rejected.
        if cid is not None and cid in duplicated_ids:
            if cid in seen_ids:
                reasons.append(Rejection(idx, cid_raw, "duplicate_customer_id",
                                         "customer_id", cid_raw))
            seen_ids.add(cid)

        if reasons:
            log.rejections.extend(reasons)
            continue

        record["date_of_birth"] = dob.isoformat()
        record["created_date"] = created.isoformat()
        kept.append(record)

    log.rows_out = len(kept)
    return pd.DataFrame(kept, columns=list(df.columns)), log


def policy_sensitivity(log: CleaningLog, non_critical: set[str]) -> dict[str, int]:
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
        if all(r.column in non_critical and r.reason == "missing_required_field" for r in rs)
    )
    return {
        "quarantined": len(grouped),
        "recoverable_under_tiered_policy": recoverable,
        "retention_if_relaxed": log.rows_out + recoverable,
    }


def quarantine_frame(log: CleaningLog, sensitive_columns: set[str]) -> pd.DataFrame:
    """One row per rejected record, reasons joined.

    Failing values from identifying columns are redacted. The quarantine file
    is an operational artifact that gets copied around; it should not be the
    one place raw PII escapes the pipeline.
    """
    from pipeline.pii import redact

    grouped: dict[int, list[Rejection]] = {}
    for r in log.rejections:
        grouped.setdefault(r.row, []).append(r)

    def show(r: Rejection) -> str:
        value = redact(r.value) if r.column in sensitive_columns else r.value
        return f"{r.column}={value}"

    return pd.DataFrame([
        {
            "source_row": row,
            "customer_id": rs[0].customer_id,
            "failure_count": len(rs),
            "failure_reason": "; ".join(sorted({r.reason for r in rs})),
            "failing_columns": "; ".join(sorted({r.column for r in rs})),
            "sample_values": " | ".join(show(r) for r in rs)[:180],
        }
        for row, rs in sorted(grouped.items())
    ])
