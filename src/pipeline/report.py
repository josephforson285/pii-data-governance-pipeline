"""Render result objects into the plain-text reports the brief asks for.

Reports are views over structured results, never printed inline by the stages
that produce them - so every stage stays testable on its data alone.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from pipeline.profile import QualityProfile, VALID_STATUSES

VERSION = "0.1.0"
WIDTH = 78


def file_digest(path: Path) -> str:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return h[:16]


def header(title: str, source: Path, n_rows: int) -> list[str]:
    """Provenance block. Lets two reports be proven to describe the same run."""
    return [
        "=" * WIDTH,
        title.upper(),
        "=" * WIDTH,
        f"Source     : {source}",
        f"SHA256     : {file_digest(source)}",
        f"Rows       : {n_rows:,}",
        f"Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Pipeline   : v{VERSION}",
        "",
    ]


def _section(title: str) -> list[str]:
    return ["-" * WIDTH, title, "-" * WIDTH]


def render_quality_report(p: QualityProfile, source: Path) -> str:
    out = header("Data Quality Report", source, p.n_rows)

    out += _section("1. SCHEMA CONFORMANCE")
    out.append(f"Missing columns    : {', '.join(p.missing_columns) or 'none'}")
    out.append(f"Unexpected columns : {', '.join(p.unexpected_columns) or 'none'}")
    out.append("")
    out.append(f"{'COLUMN':<16}{'DTYPE READ':<14}{'EXPECTED':<12}{'VERDICT'}")
    for c in p.columns:
        ok = "as expected" if c.dtype_expected == "string" and c.dtype_actual == "object" else "needs coercion"
        out.append(f"{c.name:<16}{c.dtype_actual:<14}{c.dtype_expected:<12}{ok}")
    out.append("")
    out.append("Every column reads as object: the CSV is loaded as text so that")
    out.append("malformed values survive to be reported instead of being coerced away.")
    out.append("")

    out += _section("2. COMPLETENESS")
    out.append(f"{'COLUMN':<16}{'NULL':>8}{'SENTINEL':>10}{'MISSING':>9}{'PCT':>8}")
    for c in p.columns:
        out.append(
            f"{c.name:<16}{c.null_count:>8}{c.sentinel_count:>10}"
            f"{c.missing_count:>9}{100 * c.missing_count / p.n_rows:>7.2f}%"
        )
    out.append("")
    out.append("SENTINEL counts values that read as present but mean absent")
    out.append("('N/A', 'NULL', 'unknown', whitespace). These survive dropna().")
    out.append("")

    out += _section("3. UNIQUENESS")
    dup_rows = sum(p.duplicate_ids.values()) - len(p.duplicate_ids)
    out.append(f"customer_id unique      : {'NO' if p.duplicate_ids else 'YES'}")
    out.append(f"Distinct ids duplicated : {len(p.duplicate_ids)}")
    out.append(f"Surplus rows            : {dup_rows}")
    if p.duplicate_ids:
        shown = list(p.duplicate_ids.items())[:10]
        out.append("Examples (id x occurrences): " + ", ".join(f"{k} x{v}" for k, v in shown))
    out.append("")

    out += _section("4. FORMAT INVENTORY")
    out.append("Distinct value shapes per column (digits -> 9, letters -> A).")
    for col, shapes in p.format_inventory.items():
        out.append("")
        out.append(f"{col}  ({len(shapes)} shapes)")
        out.append(f"  {'SHAPE':<24}{'COUNT':>7}   EXAMPLE")
        for sig, n, ex in shapes:
            out.append(f"  {sig[:23]:<24}{n:>7}   {ex[:28]}")
    out.append("")

    out += _section("5. INVALID VALUES")
    out.append(f"{'CHECK':<28}{'COUNT':>7}   EXAMPLES")
    for name, info in p.invalid_values.items():
        ex = ", ".join(str(e) for e in info["examples"])[:38]
        out.append(f"{name:<28}{info['count']:>7}   {ex}")
    out.append("")

    out += _section("6. CATEGORICAL VALIDITY - account_status")
    valid = {k: v for k, v in p.status_counts.items() if k in VALID_STATUSES}
    invalid = {k: v for k, v in p.status_counts.items() if k not in VALID_STATUSES}
    out.append(f"Permitted: {', '.join(sorted(VALID_STATUSES))}")
    out.append("")
    out.append(f"{'VALUE':<20}{'COUNT':>8}   STATUS")
    for k, v in sorted(valid.items(), key=lambda x: -x[1]):
        out.append(f"{repr(k):<20}{v:>8}   valid")
    for k, v in sorted(invalid.items(), key=lambda x: -x[1]):
        out.append(f"{repr(k):<20}{v:>8}   INVALID")
    out.append("")
    out.append(f"Invalid total: {sum(invalid.values())} rows ({100 * sum(invalid.values()) / p.n_rows:.2f}%)")
    out.append("")

    out += _section("SUMMARY")
    worst = max(p.columns, key=lambda c: c.missing_count)
    out.append(f"Rows profiled            : {p.n_rows:,}")
    out.append(f"Columns with missing data: {sum(1 for c in p.columns if c.missing_count)}")
    out.append(f"Least complete column    : {worst.name} ({100 * worst.missing_count / p.n_rows:.2f}% missing)")
    out.append(f"Invalid-value findings   : {sum(i['count'] for i in p.invalid_values.values())}")
    out.append(f"Non-canonical formats    : {sum(len(s) - 1 for s in p.format_inventory.values())}")
    out.append("")
    return "\n".join(out) + "\n"


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
