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
        return int(self._raw["version"])

    @property
    def unexpected_column_policy(self) -> str:
        return str(self._raw.get("schema_policy", {}).get("unexpected_columns", "warn"))

    @property
    def reference_date(self) -> date:
        """Date age and future-date checks are evaluated against.

        Configuring this freezes a run: with `reference_date: null` the same
        input produces different results as time passes, because a record that
        is 119 years old today is 121 in two years.
        """
        value = self._raw.get("reference_date")
        if not value:
            return date.today()
        # PyYAML parses an unquoted ISO date into a date object already.
        return value if isinstance(value, date) else date.fromisoformat(str(value))

    @property
    def reference_date_is_pinned(self) -> bool:
        return self._raw.get("reference_date") is not None

    # --- policy ------------------------------------------------------------
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


KNOWN_DTYPES = {"int64", "float64", "str", "date"}
KNOWN_DF_OPS = {"lt", "le", "gt", "ge"}
KNOWN_STRATEGIES = {"initial", "email_local", "last_four", "year_only", "suppress", "band"}
DERIVED_QUASI = {"address_postal"}


def validate_config(cfg: Config) -> None:
    """Reject a config the pipeline cannot honour, at load time.

    Every check here corresponds to a failure that would otherwise surface
    later as a confusing error, or - worse - as silence: a masking rule naming
    a column that does not exist simply would not run.
    """
    problems: list[str] = []
    schema = cfg.schema

    if cfg.version < 1:
        problems.append(f"version must be >= 1, got {cfg.version}")
    if cfg.min_age >= cfg.max_age:
        problems.append(f"min_age {cfg.min_age} must be below max_age {cfg.max_age}")
    if cfg.income_cap < 0:
        problems.append(f"income_cap must not be negative, got {cfg.income_cap}")
    if cfg.income_band_width <= 0:
        problems.append(f"income_band_width must be positive, got {cfg.income_band_width}")
    if cfg.unexpected_column_policy not in {"warn", "fail"}:
        problems.append(
            f"schema_policy.unexpected_columns must be 'warn' or 'fail', "
            f"got {cfg.unexpected_column_policy!r}")

    for name, spec in schema.items():
        dtype = spec.get("dtype")
        if dtype not in KNOWN_DTYPES:
            problems.append(f"schema.{name}.dtype {dtype!r} unknown; "
                            f"expected one of {sorted(KNOWN_DTYPES)}")

    for check in cfg.dataframe_checks:
        if check.op not in KNOWN_DF_OPS:
            problems.append(f"dataframe check {check.name!r} op {check.op!r} unknown")
        for side in (check.left, check.right):
            if side not in schema:
                problems.append(f"dataframe check {check.name!r} names unknown column {side!r}")

    for rule in cfg.mask_rules:
        if rule.strategy not in KNOWN_STRATEGIES:
            problems.append(f"masking rule for {rule.column!r} strategy "
                            f"{rule.strategy!r} unknown")
        if rule.column not in schema:
            problems.append(f"masking rule names unknown column {rule.column!r}")

    for group, names in (("release.unmasked_columns", cfg.unmasked_columns),
                         ("remediation.non_critical", cfg.non_critical),
                         ("reporting.sensitive_columns", cfg.sensitive_columns)):
        for name in names:
            if name not in schema:
                problems.append(f"{group} names unknown column {name!r}")

    for group, names in (("quasi_identifiers_before", cfg.quasi_identifiers_before),
                         ("quasi_identifiers_after", cfg.quasi_identifiers_after)):
        for name in names:
            if name not in schema and name not in DERIVED_QUASI:
                problems.append(f"release.{group} names {name!r}, which is neither a "
                                f"schema column nor a known derived value "
                                f"{sorted(DERIVED_QUASI)}")

    permitted = set(cfg.permitted_statuses)
    for alias, target in cfg.status_aliases.items():
        if target not in permitted:
            problems.append(f"status alias {alias!r} maps to {target!r}, "
                            f"which is not a permitted status")

    covered = {r.column for r in cfg.mask_rules} | set(cfg.unmasked_columns)
    unclassified = sorted(set(schema) - covered)
    if unclassified:
        problems.append(f"columns neither masked nor declared released unmasked: "
                        f"{', '.join(unclassified)}")

    if problems:
        raise ValueError("config/rules.yml is not usable:\n  - " + "\n  - ".join(problems))


def load(path: Path) -> Config:
    cfg = Config(yaml.safe_load(path.read_text(encoding="utf-8")), path)
    validate_config(cfg)
    return cfg
