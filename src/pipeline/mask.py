"""Part 5: mask PII before the dataset is shared.

One-way, applied to cleaned data. Strategies are declared in config/rules.yml
so policy, transformation and report cannot drift apart. Address is suppressed
wholesale and income banded - both beyond the brief, both forced by the part 2
measurement.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

import pandas as pd

from pipeline.config import Config
from pipeline.privacy import incomplete_share, k_buckets, signatures

Masker = Callable[[object], str]


def mask_initial(value: object) -> str:
    """John -> J***. Length is not preserved: a fixed-width mask would leak
    how long the name is."""
    s = "" if value is None else str(value).strip()
    if not s:
        return ""
    return f"{s[0].upper()}***"


def mask_email_local(value: object) -> str:
    """john.doe@gmail.com -> j***@gmail.com. The domain is kept for provider-mix
    analysis; on a rare domain it still narrows the population, so this reduces
    rather than removes identifying power."""
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


def make_suppressor(placeholder: str) -> Masker:
    def suppress(_value: object) -> str:
        """Replaced entirely. Free text cannot be partially masked safely."""
        return placeholder
    return suppress


def make_bander(width: int) -> Masker:
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


def build_maskers(cfg: Config) -> dict[str, Masker]:
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
    if cfg.income_band_width <= 0:
        raise ValueError(f"income_band_width must be positive, got {cfg.income_band_width}")
    maskers: dict[str, Masker] = {}
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
    incomplete_before: float
    incomplete_after: float
    k_before: dict[str, int]
    k_after: dict[str, int]
    unique_before: int
    unique_after: int


def apply_masks(df: pd.DataFrame, cfg: Config) -> pd.DataFrame:
    out = df.copy()
    maskers = build_maskers(cfg)
    missing = [c for c in maskers if c not in out.columns]
    if missing:
        raise ValueError(
            f"masking policy names column(s) {', '.join(missing)}, absent from this "
            f"frame. Skipping them would leave the report claiming a masked column "
            f"that was never masked."
        )
    for column, masker in maskers.items():
        out[column] = out[column].map(masker)
    return out


def mask(df: pd.DataFrame, cfg: Config) -> MaskResult:
    masked = apply_masks(df, cfg)
    # Both sides use the shared signature logic, so the comparison stays
    # like-for-like when a band width or quasi-identifier set changes.
    keys_before = signatures(df, cfg.quasi_identifiers_before, cfg)
    keys_after = signatures(masked, cfg.quasi_identifiers_after, cfg)
    before = k_buckets(keys_before)
    # The after set covers every released attribute designated a
    # quasi-identifier, including columns left unmasked - assessing only the
    # masked columns would flatter the result.
    after = k_buckets(keys_after)
    masked_columns = [r.column for r in cfg.mask_rules if r.column in df.columns]
    return MaskResult(
        masked=masked,
        columns_masked=masked_columns,
        columns_untouched=[c for c in df.columns if c not in masked_columns],
        quasi_before=cfg.quasi_identifiers_before,
        quasi_after=cfg.quasi_identifiers_after,
        incomplete_before=incomplete_share(keys_before),
        incomplete_after=incomplete_share(keys_after),
        k_before=before,
        k_after=after,
        unique_before=before.get("k=1 (unique)", 0),
        unique_after=after.get("k=1 (unique)", 0),
    )
