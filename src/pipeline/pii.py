"""Part 2: detect PII and quantify breach exposure.

Runs on raw data, before cleaning, because exposure is a property of what
landed on disk. Two passes: `declared` is what a column holds by design,
`leaked` is a direct identifier found where none was meant to be - which
schema-driven masking never sees. Detectors are US-format by design.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

from pipeline.config import Config
from pipeline.privacy import incomplete_share, k_buckets, signatures
from pipeline.profile import is_missing

DIRECT = "direct identifier"
QUASI = "quasi-identifier"
PSEUDO = "pseudonymous key"


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern
    category: str
    sensitivity: str
    note: str


DETECTORS = [
    Detector("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
             DIRECT, "high", "Directly contactable; common account-recovery vector"),
    Detector("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
             DIRECT, "critical", "National identifier; enables identity theft"),
    Detector("phone", re.compile(r"(?<!\d)(?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)"),
             DIRECT, "high", "Directly contactable; SIM-swap and smishing vector"),
    Detector("postal_code", re.compile(r"\b\d{5}(?:-\d{4})?\b"),
             QUASI, "medium", "Narrows population to a few thousand people"),
    Detector("date_iso", re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b"),
             QUASI, "medium", "Birth date is a strong re-identification signal"),
    Detector("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
             DIRECT, "medium", "Personal data under GDPR (Breyer, C-582/14)"),
]

# What each column is understood to hold. Governance metadata, not inference.
DECLARED = {
    "customer_id":    (PSEUDO, "medium", "Linkage key. Pseudonymised data is still personal data (GDPR Recital 26)"),
    "first_name":     (DIRECT, "high", "Identifies with surname"),
    "last_name":      (DIRECT, "high", "Identifies with forename"),
    "email":          (DIRECT, "high", "Contactable; account identifier"),
    "phone":          (DIRECT, "high", "Contactable"),
    "date_of_birth":  (QUASI, "high", "Strong quasi-identifier with location and financial attributes"),
    "address":        (QUASI, "high", "Precise location; highly identifying when linked with other attributes"),
    "income":         (QUASI, "high", "Financial data; discriminatory if disclosed"),
    "account_status": ("non-PII", "low", "Operational attribute"),
    "created_date":   (QUASI, "medium", "Near-unique when exact; a strong quasi-identifier despite being operational"),
}

# Columns not intended to hold direct identifiers such as an email, phone or
# SSN. Several of these are personal data in their own right; what makes a hit
# here a leak is that a *direct* identifier turned up where none was designed
# to be.
NON_IDENTIFIER_COLUMNS = {"address", "account_status", "created_date", "income"}


# Content regexes match shapes, not meaning, so some hits are structural
# coincidence. Suppressions are declared here rather than folded into the
# patterns: the scan stays recall-first and every discard is on the record.
SUPPRESSIONS: list[tuple[str, set[str], str]] = [
    ("postal_code", {"income", "customer_id"},
     "Numeric field; any 5-digit amount matches the postal shape"),
    ("postal_code", {"phone"},
     "Truncated phone number, not a postal code"),
    ("date_iso", {"created_date"},
     "Account creation timestamp; operational, not a birth date"),
]


def suppression_for(detector: str, column: str) -> str | None:
    for det, columns, reason in SUPPRESSIONS:
        if det == detector and column in columns:
            return reason
    return None


@dataclass
class Finding:
    column: str
    detector: str
    category: str
    sensitivity: str
    match_count: int
    row_count: int
    rows: list[int] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)
    suppressed: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.suppressed is None


@dataclass
class PIIReport:
    n_rows: int
    declared: dict[str, tuple[str, str, str]]
    findings: list[Finding]
    suppressed: list[Finding]
    leaks: list[Finding]
    rows_with_pii: int
    k_anonymity: dict[str, int]
    unique_rows: int
    quasi_identifiers: list[str]
    incomplete_signatures: float
    leak_rows: int


def redact(value: str) -> str:
    """Coarse redaction for evidence samples. Reports must not carry raw PII."""
    v = str(value)
    v = re.sub(r"[A-Za-z0-9._%+\-]+@", lambda m: m.group(0)[0] + "***@", v)
    v = re.sub(r"\d", "#", v)
    return v[:44]


def _scan_column(series: pd.Series, column: str,
                 apply_suppressions: bool = True) -> list[Finding]:
    found = []
    for det in DETECTORS:
        rows, samples, matches = [], [], 0
        for idx, value in series.items():
            if is_missing(value):
                continue
            hits = det.pattern.findall(str(value))
            if hits:
                rows.append(int(idx))
                matches += len(hits)
                if len(samples) < 3:
                    samples.append(redact(str(value)))
        if rows:
            found.append(Finding(column, det.name, det.category, det.sensitivity,
                                 matches, len(rows), rows, samples,
                                 suppression_for(det.name, column)
                                 if apply_suppressions else None))
    return found


def verify_release(df: pd.DataFrame) -> list[Finding]:
    """Re-scan a masked extract for direct identifiers.

    Masking is asserted everywhere else and checked only here.

    Scans every column, not only those the policy claims to mask: scoping it
    to masked columns made the check vanish along with any masking rule that
    was removed.
    """
    residual: list[Finding] = []
    for column in df.columns:
        # Suppressions cut noise while triaging raw data; on a release they
        # would wave through a real identifier.
        for finding in _scan_column(df[column], column, apply_suppressions=False):
            if finding.category == DIRECT:
                residual.append(finding)
    return residual


def detect(df: pd.DataFrame, cfg: Config) -> PIIReport:
    scanned: list[Finding] = []
    for column in df.columns:
        scanned.extend(_scan_column(df[column], column))

    findings = [f for f in scanned if f.confirmed]
    suppressed = [f for f in scanned if not f.confirmed]
    leaks = [f for f in findings
             if f.column in NON_IDENTIFIER_COLUMNS and f.category == DIRECT]

    pii_rows: set[int] = set()
    for f in findings:
        pii_rows.update(f.rows)
    # Every row carries a name and an id by schema, so exposure is total
    # regardless of what the content scan found.

    keys = signatures(df, cfg.quasi_identifiers_before, cfg)
    buckets = k_buckets(keys)
    return PIIReport(
        n_rows=len(df),
        declared=DECLARED,
        findings=sorted(findings, key=lambda f: -f.row_count),
        suppressed=sorted(suppressed, key=lambda f: -f.row_count),
        leaks=leaks,
        rows_with_pii=len(df),
        k_anonymity=buckets,
        unique_rows=buckets.get("k=1 (unique)", 0),
        quasi_identifiers=cfg.quasi_identifiers_before,
        incomplete_signatures=incomplete_share(keys),
        # Union, not a sum: a row leaking both an email and a phone is one
        # affected record, not two.
        leak_rows=len({r for f in leaks for r in f.rows}),
    )
