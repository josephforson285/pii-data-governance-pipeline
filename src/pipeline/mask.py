"""Part 5: mask PII before the dataset is shared.

Masking here is one-way and applied to the cleaned data, never to the raw file.
The rules follow the brief, with two additions that the brief does not ask for
but the k-anonymity result in part 2 demands:

  address is replaced wholesale, not partially - it is free text, and part 2
  found emails, phones and SSNs leaked inside it. Partial masking would leave
  those in place.

  income is banded, because birth year plus postal code plus exact income made
  99.4% of records unique. Masking direct identifiers alone does not fix that.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import pandas as pd

MASKED_ADDRESS = "[MASKED ADDRESS]"
INCOME_BAND_WIDTH = 25_000


def mask_name(value: object) -> str:
    """John -> J***. Initial only; length is not preserved, since a fixed-width
    mask would leak how long the name is."""
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    return f"{s[0].upper()}***"


def mask_email(value: object) -> str:
    """john.doe@gmail.com -> j***@gmail.com. Domain kept: it carries analytic
    value (provider mix) and does not identify an individual."""
    s = "" if value is None else str(value).strip()
    if "@" not in s:
        return "***"
    local, _, domain = s.partition("@")
    return f"{local[0].lower()}***@{domain}" if local else f"***@{domain}"


def mask_phone(value: object) -> str:
    """555-123-4567 -> ***-***-4567. Last four kept for support call
    verification; on their own they do not identify a subscriber."""
    s = "" if value is None else str(value).strip()
    digits = re.sub(r"\D", "", s)
    if len(digits) < 4:
        return "***-***-****"
    return f"***-***-{digits[-4:]}"


def mask_address(value: object) -> str:
    """Replaced entirely. Free text cannot be partially masked safely."""
    return MASKED_ADDRESS


def mask_dob(value: object) -> str:
    """1985-03-15 -> 1985-**-**. Year is retained for age analysis and is the
    residual re-identification risk that banding income is meant to offset."""
    s = "" if value is None else str(value).strip()
    if re.fullmatch(r"\d{4}-\*\*-\*\*", s):
        return s
    m = re.match(r"^(\d{4})-\d{2}-\d{2}$", s)
    return f"{m.group(1)}-**-**" if m else "****-**-**"


def band_income(value: object) -> str:
    """52000.0 -> 50000-74999. Generalisation, not suppression: the band still
    supports segmentation while collapsing a unique value into a group."""
    s = str(value).strip()
    if re.fullmatch(r"\d+-\d+", s) or s == "unknown":
        return s
    try:
        amount = float(s)
    except (TypeError, ValueError):
        return "unknown"
    if pd.isna(amount):
        return "unknown"
    lo = int(amount // INCOME_BAND_WIDTH) * INCOME_BAND_WIDTH
    return f"{lo}-{lo + INCOME_BAND_WIDTH - 1}"


MASKERS = {
    "first_name": mask_name,
    "last_name": mask_name,
    "email": mask_email,
    "phone": mask_phone,
    "address": mask_address,
    "date_of_birth": mask_dob,
    "income": band_income,
}


@dataclass
class MaskResult:
    masked: pd.DataFrame
    columns_masked: list[str]
    columns_untouched: list[str]
    k_before: dict[str, int]
    k_after: dict[str, int]
    unique_before: int
    unique_after: int


def apply_masks(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for column, masker in MASKERS.items():
        if column in out.columns:
            out[column] = out[column].map(masker)
    return out


def _k_buckets(keys: list[tuple]) -> dict[str, int]:
    from collections import Counter

    sizes = Counter(keys)
    buckets: dict[str, int] = {}
    for k in sizes.values():
        label = "k=1 (unique)" if k == 1 else "k=2" if k == 2 else "k=3-5" if k <= 5 else "k>5"
        buckets[label] = buckets.get(label, 0) + k
    return buckets


def _quasi_keys(df: pd.DataFrame, masked: bool) -> list[tuple]:
    """Quasi-identifier signature before and after masking.

    Postal code disappears entirely once the address is replaced, so the masked
    signature is deliberately shorter - that is the control working, not a
    like-for-like comparison being fudged.
    """
    if masked:
        return list(zip(df["date_of_birth"], df["income"]))
    postal = [
        (m.group(1) if (m := re.search(r"\b(\d{5})(?:-\d{4})?\b", str(a))) else "?")
        for a in df["address"]
    ]
    return list(zip(df["date_of_birth"], postal, df["income"]))


def mask(df: pd.DataFrame) -> MaskResult:
    masked = apply_masks(df)
    before = _k_buckets(_quasi_keys(df, masked=False))
    after = _k_buckets(_quasi_keys(masked, masked=True))
    return MaskResult(
        masked=masked,
        columns_masked=[c for c in MASKERS if c in df.columns],
        columns_untouched=[c for c in df.columns if c not in MASKERS],
        k_before=before,
        k_after=after,
        unique_before=before.get("k=1 (unique)", 0),
        unique_after=after.get("k=1 (unique)", 0),
    )
