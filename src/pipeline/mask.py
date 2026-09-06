"""Part 5: mask PII before the dataset is shared.

Masking is one-way and applied to the cleaned data, never to the raw file.
Which column gets which strategy is declared in config/rules.yml, so the
policy, the transformation and the report that describes it cannot drift
apart.

Two strategies go beyond the brief, both forced by the part 2 measurement:
address is suppressed wholesale because the free-text field was found to carry
leaked identifiers, and income is banded because exact income was part of what
made every record unique.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

import pandas as pd

from pipeline.config import Config

Masker = "Callable[[object], str]"


def mask_initial(value: object) -> str:
    """John -> J***. Length is not preserved: a fixed-width mask would leak
    how long the name is."""
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    return f"{s[0].upper()}***"


def mask_email_local(value: object) -> str:
    """john.doe@gmail.com -> j***@gmail.com. Domain kept: it carries analytic
    value (provider mix) and does not identify an individual."""
    s = "" if value is None else str(value).strip()
    if "@" not in s:
        return "***"
    local, _, domain = s.partition("@")
    return f"{local[0].lower()}***@{domain}" if local else f"***@{domain}"


def mask_last_four(value: object) -> str:
    """555-123-4567 -> ***-***-4567. The last four retain residual identifying
    power in combination with other attributes; they are not anonymous."""
    s = "" if value is None else str(value).strip()
    digits = re.sub(r"\D", "", s)
    if len(digits) < 4:
        return "***-***-****"
    return f"***-***-{digits[-4:]}"


def mask_year_only(value: object) -> str:
    """1985-03-15 -> 1985-**-**. Year is retained for age analysis and is the
    residual re-identification risk that banding income offsets."""
    s = "" if value is None else str(value).strip()
    if re.fullmatch(r"\d{4}-\*\*-\*\*", s):
        return s
    m = re.match(r"^(\d{4})-\d{2}-\d{2}$", s)
    return f"{m.group(1)}-**-**" if m else "****-**-**"


def make_suppressor(placeholder: str):
    def suppress(_value: object) -> str:
        """Replaced entirely. Free text cannot be partially masked safely."""
        return placeholder
    return suppress


def make_bander(width: int):
    def band(value: object) -> str:
        """52000 -> 50000-74999. Generalisation, not suppression: the band
        still supports segmentation while collapsing a unique value."""
        s = str(value).strip()
        if re.fullmatch(r"\d+-\d+", s) or s == "unknown":
            return s
        try:
            amount = float(s)
        except (TypeError, ValueError):
            return "unknown"
        if pd.isna(amount):
            return "unknown"
        lo = int(amount // width) * width
        return f"{lo}-{lo + width - 1}"
    return band


def build_maskers(cfg: Config) -> dict[str, object]:
    """Resolve the config's strategy names to functions.

    An unknown strategy raises: a masking rule that silently does nothing
    would leave PII in a column the report claims is masked.
    """
    simple = {
        "initial": mask_initial,
        "email_local": mask_email_local,
        "last_four": mask_last_four,
        "year_only": mask_year_only,
    }
    maskers: dict[str, object] = {}
    for rule in cfg.mask_rules:
        if rule.strategy in simple:
            maskers[rule.column] = simple[rule.strategy]
        elif rule.strategy == "suppress":
            maskers[rule.column] = make_suppressor(cfg.address_placeholder)
        elif rule.strategy == "band":
            maskers[rule.column] = make_bander(cfg.income_band_width)
        else:
            raise ValueError(
                f"masking rule for {rule.column!r} uses unknown strategy "
                f"{rule.strategy!r}; known: {', '.join(sorted(simple) + ['suppress', 'band'])}"
            )
    return maskers


@dataclass
class MaskResult:
    masked: pd.DataFrame
    columns_masked: list[str]
    columns_untouched: list[str]
    quasi_before: list[str]
    quasi_after: list[str]
    k_before: dict[str, int]
    k_after: dict[str, int]
    unique_before: int
    unique_after: int


def apply_masks(df: pd.DataFrame, cfg: Config) -> pd.DataFrame:
    out = df.copy()
    for column, masker in build_maskers(cfg).items():
        if column in out.columns:
            out[column] = out[column].map(masker)
    return out


def _k_buckets(keys: list[tuple]) -> dict[str, int]:
    sizes = Counter(keys)
    buckets: dict[str, int] = {}
    for k in sizes.values():
        label = "k=1 (unique)" if k == 1 else "k=2" if k == 2 else "k=3-5" if k <= 5 else "k>5"
        buckets[label] = buckets.get(label, 0) + k
    return buckets


def _postal(value: object) -> str:
    m = re.search(r"\b(\d{5})(?:-\d{4})?\b", str(value))
    return m.group(1) if m else "?"


def _quasi_keys(df: pd.DataFrame, columns: list[str]) -> list[tuple]:
    """Signature over the named quasi-identifiers.

    `address_postal` extracts the postal code from the address rather than
    using the whole string, which is unique per row and would make every
    record look unique for the wrong reason.
    """
    series = []
    for name in columns:
        if name == "address_postal":
            series.append([_postal(v) for v in df["address"]])
        elif name in df.columns:
            series.append(list(df[name]))
    return list(zip(*series)) if series else []


def mask(df: pd.DataFrame, cfg: Config) -> MaskResult:
    masked = apply_masks(df, cfg)
    before = _k_buckets(_quasi_keys(df, cfg.quasi_identifiers_before))
    # Measured over everything actually released, including columns left
    # unmasked - assessing only the masked columns would flatter the result.
    after = _k_buckets(_quasi_keys(masked, cfg.quasi_identifiers_after))
    masked_columns = [r.column for r in cfg.mask_rules if r.column in df.columns]
    return MaskResult(
        masked=masked,
        columns_masked=masked_columns,
        columns_untouched=[c for c in df.columns if c not in masked_columns],
        quasi_before=cfg.quasi_identifiers_before,
        quasi_after=cfg.quasi_identifiers_after,
        k_before=before,
        k_after=after,
        unique_before=before.get("k=1 (unique)", 0),
        unique_after=after.get("k=1 (unique)", 0),
    )
