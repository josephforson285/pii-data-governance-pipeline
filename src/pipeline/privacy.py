"""Shared re-identification measurement.

Part 2 (raw exposure) and Part 5 (post-mask residual risk) both group rows by
quasi-identifier signature. They previously did it with separate code and
separate constants, so a change to the income band width moved one number and
not the other, and the before/after comparison silently stopped being
like-for-like.
"""
from __future__ import annotations

import re
from collections import Counter

import pandas as pd

from pipeline.config import Config

# Derived quasi-identifiers: not columns, but values extracted from one.
DERIVED = {"address_postal"}


def postal_code(value: object) -> str:
    m = re.search(r"\b(\d{5})(?:-\d{4})?\b", str(value))
    return m.group(1) if m else "?"


def income_band(value: object, width: int) -> str:
    """Band a raw income, or pass through one that is already banded.

    The post-mask frame already holds bands. Re-banding them would fail to
    parse, collapse every row onto a shared '?' and make the population look
    far more anonymous than it is.
    """
    text = str(value).strip()
    if re.fullmatch(r"\d+-\d+", text):
        return text
    try:
        amount = float(text.replace(",", "").replace("$", ""))
    except (TypeError, ValueError):
        return "?"
    if pd.isna(amount):
        return "?"
    return f"{int(amount // width) * width}"


def quasi_series(df: pd.DataFrame, name: str, cfg: Config) -> list[str]:
    """One quasi-identifier's contribution to the signature.

    An unknown name raises. Silently skipping it would drop a dimension from
    the assessment and make the population look more anonymous than it is -
    a typo in config would read as a privacy improvement.
    """
    if name == "address_postal":
        if "address" not in df.columns:
            raise ValueError("quasi-identifier 'address_postal' needs an 'address' column")
        return [postal_code(v) for v in df["address"]]
    if name not in df.columns:
        raise ValueError(
            f"quasi-identifier {name!r} is not a column in this frame; "
            f"available: {', '.join(df.columns)}"
        )
    if name == "income":
        return [income_band(v, cfg.income_band_width) for v in df[name]]
    return [str(v) for v in df[name]]


def signatures(df: pd.DataFrame, columns: list[str], cfg: Config) -> list[tuple]:
    if not columns or df.empty:
        return []
    return list(zip(*(quasi_series(df, name, cfg) for name in columns)))


def k_buckets(keys: list[tuple]) -> dict[str, int]:
    """Rows per k-anonymity band, counting rows rather than groups."""
    buckets: dict[str, int] = {}
    for size in Counter(keys).values():
        label = ("k=1 (unique)" if size == 1 else "k=2" if size == 2
                 else "k=3-5" if size <= 5 else "k>5")
        buckets[label] = buckets.get(label, 0) + size
    return buckets


def incomplete_share(keys: list[tuple]) -> float:
    """Fraction of signatures carrying an unknown component.

    Rows whose quasi-identifiers could not be parsed collapse onto a shared
    '?' signature, which groups them together and makes them look protected.
    Reporting the share keeps that read honest.
    """
    if not keys:
        return 0.0
    return sum(1 for k in keys if "?" in k) / len(keys)
