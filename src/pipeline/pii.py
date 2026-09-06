"""Part 2: detect PII and quantify breach exposure.

Runs on the raw dataset, before cleaning. Exposure is a property of what
actually landed on disk - dropping bad rows first would understate it.

Two passes, because they answer different questions:

  declared  - which columns hold PII by design (governance: what must be
              masked, minimised, retention-bound)
  leaked    - PII found by content scan in a column not meant to hold it
              (incident: masking the email column misses these entirely)
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date

import pandas as pd

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
    "date_of_birth":  (QUASI, "high", "With postcode and sex, re-identifies most individuals"),
    "address":        (QUASI, "high", "Locates the individual physically"),
    "income":         (QUASI, "high", "Financial data; discriminatory if disclosed"),
    "account_status": ("non-PII", "low", "Operational attribute"),
    "created_date":   (QUASI, "medium", "Near-unique when exact; a strong quasi-identifier despite being operational"),
}

# Columns whose declared purpose is free text or non-PII: any identifier found
# here is a leak, not a design decision.
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


def redact(value: str) -> str:
    """Coarse redaction for evidence samples. Reports must not carry raw PII."""
    v = str(value)
    v = re.sub(r"[A-Za-z0-9._%+\-]+@", lambda m: m.group(0)[0] + "***@", v)
    v = re.sub(r"\d", "#", v)
    return v[:44]


def _scan_column(series: pd.Series, column: str) -> list[Finding]:
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
                                 suppression_for(det.name, column)))
    return found


def _birth_year(v) -> str:
    try:
        return str(date.fromisoformat(str(v).strip()).year)
    except ValueError:
        return "?"


def _postal(v) -> str:
    m = re.search(r"\b(\d{5})(?:-\d{4})?\b", str(v))
    return m.group(1) if m else "?"


def _income_band(v) -> str:
    try:
        x = float(str(v).replace(",", "").replace("$", "").strip())
    except ValueError:
        return "?"
    if pd.isna(x):
        return "?"
    return f"{int(x // 25_000) * 25}k"


def k_anonymity(df: pd.DataFrame) -> tuple[dict[str, int], int]:
    """Group rows by their quasi-identifier signature.

    A group of size k means each member is indistinguishable from k-1 others.
    k=1 rows are uniquely re-identifiable from the quasi-identifiers alone -
    masking the direct identifiers does not protect them.
    """
    keys = [
        (_birth_year(dob), _postal(addr), _income_band(inc))
        for dob, addr, inc in zip(df["date_of_birth"], df["address"], df["income"])
    ]
    sizes = Counter(keys)
    buckets: dict[str, int] = defaultdict(int)
    for k in sizes.values():
        label = "k=1 (unique)" if k == 1 else "k=2" if k == 2 else "k=3-5" if k <= 5 else "k>5"
        buckets[label] += k
    return dict(buckets), sizes.most_common()[-1][1] if sizes else 0


def detect(df: pd.DataFrame) -> PIIReport:
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
    # Every row also carries a name and an id, so exposure is effectively total.
    declared_pii_rows = len(df)

    buckets, _ = k_anonymity(df)
    return PIIReport(
        n_rows=len(df),
        declared=DECLARED,
        findings=sorted(findings, key=lambda f: -f.row_count),
        suppressed=sorted(suppressed, key=lambda f: -f.row_count),
        leaks=leaks,
        rows_with_pii=max(len(pii_rows), declared_pii_rows),
        k_anonymity=buckets,
        unique_rows=buckets.get("k=1 (unique)", 0),
    )
