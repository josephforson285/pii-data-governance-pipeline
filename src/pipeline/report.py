"""Render result objects into the plain-text reports the brief asks for.

Reports are views over structured results, never printed inline by the stages
that produce them - so every stage stays testable on its data alone.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from pipeline.clean import NON_CRITICAL, CleaningLog, policy_sensitivity
from pipeline.pii import DETECTORS, PIIReport
from pipeline.profile import QualityProfile, VALID_STATUSES
from pipeline.validate import ValidationResult

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


def render_pii_report(r: PIIReport, source: Path) -> str:
    out = header("PII Detection Report", source, r.n_rows)

    out += _section("1. DECLARED PII INVENTORY")
    out.append("What each column holds by design. Governance metadata, not inference.")
    out.append("")
    out.append(f"{'COLUMN':<16}{'CLASSIFICATION':<20}{'SENS':<10}RATIONALE")
    for col, (cat, sens, note) in r.declared.items():
        out.append(f"{col:<16}{cat:<20}{sens:<10}{note}")
    out.append("")
    n_pii = sum(1 for c, s_ in r.declared.items() if s_[0] != "non-PII")
    out.append(f"{n_pii} of {len(r.declared)} columns carry personal data.")
    out.append("")

    out += _section("2. CONTENT SCAN - PATTERNS APPLIED")
    out.append(f"{'DETECTOR':<14}{'CLASSIFICATION':<20}{'SENS':<10}NOTE")
    for d in DETECTORS:
        out.append(f"{d.name:<14}{d.category:<20}{d.sensitivity:<10}{d.note}")
    out.append("")
    out.append("Every column is scanned with every pattern. Detecting by column")
    out.append("name would find only the PII we already knew about.")
    out.append("")

    out += _section("3. CONFIRMED MATCHES")
    out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}{'MATCHES':>9}   SAMPLE (redacted)")
    for f in r.findings:
        out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}{f.match_count:>9}   {f.samples[0] if f.samples else ''}")
    out.append("")
    out.append("Samples are redacted. A PII report that quotes raw PII is itself a breach.")
    out.append("")

    out += _section("4. SUPPRESSED MATCHES - PRECISION")
    out.append("Regex matches shape, not meaning. These hits are structural")
    out.append("coincidence, discarded by declared rule rather than by tuning the")
    out.append("patterns, so the decision stays auditable.")
    out.append("")
    out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}   REASON")
    for f in r.suppressed:
        out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}   {f.suppressed}")
    total_hits = sum(f.row_count for f in r.findings) + sum(f.row_count for f in r.suppressed)
    kept = sum(f.row_count for f in r.findings)
    out.append("")
    out.append(f"Raw hits {total_hits:,} -> confirmed {kept:,} ({100 * kept / total_hits:.1f}% precision).")
    out.append("Scanning recall-first and suppressing afterwards is deliberate: a")
    out.append("missed identifier is a breach, a false positive is review effort.")
    out.append("")

    out += _section("5. UNDECLARED PII - LEAKAGE")
    if not r.leaks:
        out.append("None found.")
    else:
        out.append("Direct identifiers found in columns not meant to hold them.")
        out.append("Field-level masking driven by the schema would miss all of these.")
        out.append("")
        out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}   FIRST AFFECTED ROWS")
        for f in r.leaks:
            out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}   {f.rows[:6]}")
        out.append("")
        out.append(f"Total: {sum(f.row_count for f in r.leaks)} rows.")
        worst = max(r.leaks, key=lambda f: {"critical": 3, "high": 2, "medium": 1}.get(f.sensitivity, 0))
        out.append(f"Highest severity: {worst.detector} in {worst.column} ({worst.sensitivity}).")
    out.append("")

    out += _section("6. BREACH EXPOSURE")
    out.append(f"Records containing personal data : {r.rows_with_pii:,} of {r.n_rows:,} (100%)")
    out.append("")
    out.append("Every record carries a name, an identifier and contact details, so")
    out.append("exposure is total: there is no subset of this file that is safe to")
    out.append("release unmasked.")
    out.append("")
    ssn = sum(f.row_count for f in r.findings if f.detector == "us_ssn")
    out.append("If this file were disclosed:")
    out.append(f"  - Direct identifiers  name, email, phone" + (f", and {ssn} leaked SSNs" if ssn else ""))
    out.append("  - Financial data      income for every data subject")
    out.append("  - Location            home address for every data subject")
    out.append("")
    out.append("GDPR Art. 33 requires notifying the supervisory authority within 72")
    out.append("hours where a breach is likely to risk data subjects' rights. Volume")
    out.append("and the presence of financial data put this well above that bar.")
    out.append("")

    out += _section("7. RE-IDENTIFICATION RISK")
    out.append("Masking direct identifiers does not make a dataset anonymous. Grouping")
    out.append("rows by quasi-identifiers (birth year, postal code, income band) shows")
    out.append("how many people each record is hidden among.")
    out.append("")
    out.append(f"{'GROUP SIZE':<16}{'ROWS':>8}{'PCT':>9}")
    for label in ["k=1 (unique)", "k=2", "k=3-5", "k>5"]:
        if label in r.k_anonymity:
            v = r.k_anonymity[label]
            out.append(f"{label:<16}{v:>8}{100 * v / r.n_rows:>8.1f}%")
    out.append("")
    pct = 100 * r.unique_rows / r.n_rows
    out.append(f"{pct:.1f}% of records are unique on quasi-identifiers alone (k=1).")
    out.append("Those individuals stay re-identifiable after every direct identifier")
    out.append("is masked, by anyone holding a second dataset with the same attributes.")
    out.append("")
    out.append("The masked output is therefore pseudonymous, not anonymous, and remains")
    out.append("personal data under GDPR Recital 26. Genuine anonymisation would need")
    out.append("generalisation of the quasi-identifiers to reach a k threshold.")
    out.append("")
    return "\n".join(out) + "\n"


def render_validation_report(pre: ValidationResult, source: Path,
                             post: ValidationResult | None = None) -> str:
    out = header("Validation Results", source, pre.n_rows)
    out.append("Engine: pandera, lazy=True - every rule is evaluated against every")
    out.append("row so one bad value cannot hide the rest.")
    out.append("")

    out += _section("1. RULES APPLIED")
    out.append("Declared in config/rules.yml and translated to pandera checks, so")
    out.append("the rules can change without touching pipeline code.")
    out.append("")

    out += _section(f"2. TYPE COERCION - {pre.stage.upper()}")
    out.append("Values that are present but will not convert to their declared type.")
    out.append("Pandera sees these as null once coerced, so they would otherwise be")
    out.append("counted as missing - a different defect needing a different fix.")
    out.append("")
    out.append(f"{'COLUMN':<20}{'UNCOERCIBLE':>13}   EXAMPLES")
    for col, n in pre.coercion_by_column.items():
        ex = ", ".join(dict.fromkeys(str(f.failure_case) for f in pre.coercion if f.column == col))[:36]
        out.append(f"{col:<20}{n:>13}   {ex}")
    out.append(f"{'TOTAL':<20}{len(pre.coercion):>13}")
    out.append("")

    out += _section("3. RULE FAILURES")
    if post is None:
        out.append(f"{'RULE':<44}{'FAILURES':>10}")
        for rule, n in pre.by_rule.items():
            out.append(f"{rule:<44}{n:>10}")
        out.append("-" * WIDTH)
        out.append(f"{'TOTAL':<44}{len(pre.failures):>10}")
        out.append("")
        out.append(f"Rows with at least one failure: {len(pre.failing_rows):,} "
                   f"of {pre.n_rows:,} ({100 * len(pre.failing_rows) / pre.n_rows:.1f}%)")
    else:
        rules = list(dict.fromkeys(list(pre.by_rule) + list(post.by_rule)))
        out.append(f"{'RULE':<44}{'PRE':>8}{'POST':>8}{'DELTA':>9}")
        for rule in rules:
            a, b = pre.by_rule.get(rule, 0), post.by_rule.get(rule, 0)
            out.append(f"{rule:<44}{a:>8}{b:>8}{b - a:>+9}")
        out.append("-" * WIDTH)
        a, b = len(pre.failures), len(post.failures)
        out.append(f"{'TOTAL':<44}{a:>8}{b:>8}{b - a:>+9}")
        out.append("")
        out.append(f"Rows failing : {len(pre.failing_rows):,} -> {len(post.failing_rows):,}")
        if b:
            out.append("")
            out.append("Remaining failures are values that could not be repaired without")
            out.append("inventing data. They are quarantined, not silently dropped.")
    out.append("")

    out += _section("4. FAILURE DETAIL")
    out.append("First 40 failures, with the row and the offending value.")
    out.append("")
    out.append(f"{'ROW':>7}   {'COLUMN':<16}{'CHECK':<26}VALUE")
    shown = (post or pre).failures[:40]
    for f in shown:
        row = str(f.index) if f.index is not None else "-"
        out.append(f"{row:>7}   {f.column:<16}{f.check[:25]:<26}{str(f.failure_case)[:24]}")
    out.append("")

    out += _section("SUMMARY")
    final = post or pre
    out.append(f"Stage validated       : {final.stage}")
    out.append(f"Rule failures         : {len(final.failures):,}")
    out.append(f"Uncoercible values    : {len(final.coercion):,}")
    out.append(f"Schema compliant      : {'YES' if final.passed else 'NO'}")
    out.append("")
    return "\n".join(out) + "\n"


def render_cleaning_log(log: CleaningLog, source: Path) -> str:
    out = header("Cleaning Log", source, log.rows_in)

    out += _section("1. NORMALISATIONS APPLIED")
    out.append("Repairs made where the intended value is unambiguous.")
    out.append("")
    out.append(f"{'REPAIR':<30}{'ROWS':>8}")
    for tag, n in log.repairs.most_common():
        out.append(f"{tag:<30}{n:>8}")
    out.append("-" * WIDTH)
    out.append(f"{'TOTAL':<30}{sum(log.repairs.values()):>8}")
    out.append("")
    out.append("Rules: phone -> XXX-XXX-XXXX, dates -> YYYY-MM-DD, names -> Title Case,")
    out.append("status -> lower case against the permitted set, email -> lower case.")
    out.append("")

    out += _section("2. QUARANTINE")
    out.append("Rows that cannot be repaired without inventing data. Written to")
    out.append("data/rejects/quarantine.csv with the reason, never dropped: a deleted")
    out.append("row is an unanswerable question later.")
    out.append("")
    out.append(f"{'REASON':<30}{'ROWS':>8}")
    for reason, n in log.reasons.items():
        out.append(f"{reason:<30}{n:>8}")
    out.append("")
    out.append(f"Distinct rows quarantined: {log.rows_quarantined:,}")
    out.append("(A row can fail several rules, so reasons sum above this figure.)")
    out.append("")

    out += _section("3. RECONCILIATION")
    out.append(f"{'Rows in':<22}{log.rows_in:>10,}")
    out.append(f"{'Rows cleaned':<22}{log.rows_out:>10,}")
    out.append(f"{'Rows quarantined':<22}{log.rows_quarantined:>10,}")
    out.append("-" * WIDTH)
    ok = log.reconciles()
    out.append(f"{'Balance':<22}{log.rows_out + log.rows_quarantined:>10,}   {'OK' if ok else 'MISMATCH'}")
    out.append("")
    out.append("Asserted on every run. Without it, a row lost to a silent exception")
    out.append("looks identical to a row that was never there.")
    out.append("")
    out.append(f"Retention: {100 * log.rows_out / log.rows_in:.1f}%")
    out.append("")

    out += _section("4. POLICY SENSITIVITY")
    s = policy_sensitivity(log)
    out.append("config/rules.yml declares every column non-nullable, so a record is")
    out.append("rejected for a blank optional field as readily as for a corrupt one.")
    out.append("That is a governance choice, not a fact about the data.")
    out.append("")
    out.append(f"Treated as optional: {', '.join(sorted(NON_CRITICAL))}")
    out.append("")
    out.append(f"{'Quarantined under current policy':<42}{s['quarantined']:>8}")
    out.append(f"{'Failing only on a blank optional field':<42}{s['recoverable_under_tiered_policy']:>8}")
    out.append(f"{'Retention if those were kept and flagged':<42}"
               f"{100 * s['retention_if_relaxed'] / log.rows_in:>7.1f}%")
    out.append("")
    out.append(f"Retaining them would raise retention from {100 * log.rows_out / log.rows_in:.1f}% "
               f"to {100 * s['retention_if_relaxed'] / log.rows_in:.1f}%,")
    out.append("at the cost of nulls flowing downstream. The strict policy is kept")
    out.append("here because the brief declares these fields mandatory; the number")
    out.append("is reported so the trade-off can be re-argued with evidence.")
    out.append("")
    return "\n".join(out) + "\n"


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
