"""Typed access to config/rules.yml.

Every threshold, pattern and policy value the pipeline uses comes from here.
Modules take a Config rather than importing constants from each other, so a
rule cannot be changed in one place and stay stale in another.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class MaskRule:
    column: str
    strategy: str
    description: str
    rationale: str


@dataclass(frozen=True)
class DataFrameCheck:
    name: str
    left: str
    right: str
    op: str
    description: str


class Config:
    def __init__(self, raw: dict[str, Any], path: Path | None = None):
        self._raw = raw
        self.path = path

    # --- provenance --------------------------------------------------------
    @property
    def version(self) -> int:
        return int(self._raw.get("version", 0))

    @property
    def reference_date(self) -> date:
        """Date age and future-date checks are evaluated against.

        Configuring this freezes a run: with `reference_date: null` the same
        input produces different results as time passes, because a record that
        is 119 years old today is 121 in two years.
        """
        value = self._raw.get("reference_date")
        return date.fromisoformat(value) if value else date.today()

    @property
    def reference_date_is_pinned(self) -> bool:
        return self._raw.get("reference_date") is not None

    # --- policy ------------------------------------------------------------
    @property
    def sentinels(self) -> set[str]:
        return {str(s).strip().lower() for s in self._raw["sentinels"]}

    @property
    def schema(self) -> dict[str, dict]:
        return self._raw["schema"]

    @property
    def min_age(self) -> int:
        return int(self._raw["thresholds"]["min_age"])

    @property
    def max_age(self) -> int:
        return int(self._raw["thresholds"]["max_age"])

    @property
    def income_cap(self) -> float:
        return float(self._raw["thresholds"]["income_cap"])

    @property
    def dataframe_checks(self) -> list[DataFrameCheck]:
        return [DataFrameCheck(**c) for c in self._raw.get("dataframe_checks", [])]

    @property
    def non_critical(self) -> set[str]:
        return set(self._raw["remediation"]["non_critical"])

    @property
    def status_aliases(self) -> dict[str, str]:
        return dict(self._raw["remediation"]["status_aliases"])

    @property
    def date_formats(self) -> list[str]:
        return list(self._raw["remediation"]["date_formats"])

    @property
    def permitted_statuses(self) -> list[str]:
        return list(self._raw["schema"]["account_status"]["checks"]["isin"])

    def length_bounds(self, column: str) -> tuple[int, int]:
        checks = self._raw["schema"][column].get("checks") or {}
        return int(checks.get("min_len", 0)), int(checks.get("max_len", 10**6))

    # --- masking -----------------------------------------------------------
    @property
    def address_placeholder(self) -> str:
        return str(self._raw["masking"]["address_placeholder"])

    @property
    def income_band_width(self) -> int:
        return int(self._raw["masking"]["income_band_width"])

    @property
    def mask_rules(self) -> list[MaskRule]:
        return [MaskRule(column=col, **spec)
                for col, spec in self._raw["masking"]["rules"].items()]

    # --- release / reporting ----------------------------------------------
    @property
    def unmasked_columns(self) -> list[str]:
        return list(self._raw["release"]["unmasked_columns"])

    @property
    def quasi_identifiers_before(self) -> list[str]:
        return list(self._raw["release"]["quasi_identifiers_before"])

    @property
    def quasi_identifiers_after(self) -> list[str]:
        return list(self._raw["release"]["quasi_identifiers_after"])

    @property
    def sensitive_columns(self) -> set[str]:
        return set(self._raw["reporting"]["sensitive_columns"])


def load(path: Path) -> Config:
    return Config(yaml.safe_load(path.read_text(encoding="utf-8")), path)
