"""Render result objects into the plain-text reports the brief asks for.

Reports are views over structured results, never printed inline by the stages
that produce them - so every stage stays testable on its data alone.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from pipeline.clean import CleaningLog, policy_sensitivity
from pipeline.config import Config
from pipeline.mask import MaskResult
from pipeline.pii import DETECTORS, PIIReport, redact
from pipeline.profile import QualityProfile
from pipeline.run import RunResult
from pipeline.score import ScoreCard
from pipeline.validate import ValidationResult

def _safe(value: object, sensitive: bool) -> str:
    """Redact a value from an identifying column: a report that quotes raw
    PII is a disclosure of its own."""
    return redact(str(value)) if sensitive else str(value)


def _pct(num: float, den: float) -> float:
    """Percentage, or zero when there is nothing to divide by."""
    return 100 * num / den if den else 0.0


def _sensitive_check(name: str, cfg: Config) -> bool:
    """A profiler check name is sensitive when it names a sensitive column."""
    return any(col in name for col in cfg.sensitive_columns)

VERSION = "0.1.0"
WIDTH = 78


def file_digest(path: Path) -> str:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return h[:16]


def header(title: str, source: Path, n_rows: int, cfg: Config | None = None) -> list[str]:
    """Provenance block. Lets two reports be proven to describe the same run."""
    extra = []
    if cfg is not None:
        pinned = "pinned" if cfg.reference_date_is_pinned else "today (not pinned)"
        extra = [
            f"Rules      : v{cfg.version}",
            f"Reference  : {cfg.reference_date.isoformat()} ({pinned})",
        ]
    return [
        "=" * WIDTH,
        title.upper(),
        "=" * WIDTH,
        f"Source     : {source}",
        f"SHA256     : {file_digest(source)}",
        f"Rows       : {n_rows:,}",
        f"Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Pipeline   : v{VERSION}",
        *extra,
        "",
    ]


def _section(title: str) -> list[str]:
    return ["-" * WIDTH, title, "-" * WIDTH]


def render_quality_report(p: QualityProfile, source: Path, cfg: Config) -> str:
    out = header("Data Quality Report", source, p.n_rows, cfg)

    out += _section("1. SCHEMA CONFORMANCE")
    out.append(f"Missing columns    : {', '.join(p.missing_columns) or 'none'}")
    out.append(f"Unexpected columns : {', '.join(p.unexpected_columns) or 'none'}")
    out.append("")
    out.append(f"{'COLUMN':<16}{'DTYPE READ':<14}{'EXPECTED':<12}{'VERDICT'}")
    for c in p.columns:
        ok = "as expected" if c.dtype_expected == "string" and c.dtype_actual == "object" else "needs coercion"
        out.append(f"{c.name:<16}{c.dtype_actual:<14}{c.dtype_expected:<12}{ok}")
    out.append("")
    out.append("Everything reads as object: the CSV loads as text so malformed values")
    out.append("survive to be reported instead of coerced away.")
    out.append("")

    out += _section("2. COMPLETENESS")
    out.append(f"{'COLUMN':<16}{'NULL':>8}{'SENTINEL':>10}{'MISSING':>9}{'PCT':>8}")
    for c in p.columns:
        pct = _pct(c.missing_count, p.n_rows)
        out.append(
            f"{c.name:<16}{c.null_count:>8}{c.sentinel_count:>10}"
            f"{c.missing_count:>9}{pct:>7.2f}%"
        )
    out.append("")
    out.append("SENTINEL: reads as present, means absent ('N/A', 'unknown',")
    out.append("whitespace). These survive dropna().")
    out.append("")

    out += _section("3. UNIQUENESS")
    dup_rows = sum(p.duplicate_ids.values()) - len(p.duplicate_ids)
    out.append("Raw values: '00123' and '123' are distinct; absent ids excluded.")
    out.append("")
    out.append(f"customer_id unique      : {'NO' if p.duplicate_ids else 'YES'}")
    out.append(f"Distinct ids duplicated : {len(p.duplicate_ids)}")
    out.append(f"Surplus rows            : {dup_rows}")
    if p.duplicate_ids:
        shown = list(p.duplicate_ids.items())[:10]
        out.append("Examples (id x occurrences): " + ", ".join(f"{k} x{v}" for k, v in shown))
    out.append("")

    out += _section("4. FORMAT INVENTORY")
    out.append("Value shapes per column (digits -> 9, letters -> A). Examples from")
    out.append("identifying columns are redacted.")
    for col, shapes in p.format_inventory.items():
        out.append("")
        out.append(f"{col}  ({len(shapes)} shapes)")
        sensitive = col in cfg.sensitive_columns
        out.append(f"  {'SHAPE':<24}{'COUNT':>7}   EXAMPLE")
        for sig, n, ex in shapes:
            # The shape already carries the format; a redacted example repeats it.
            shown = "[redacted]" if sensitive else ex[:28]
            out.append(f"  {sig[:23]:<24}{n:>7}   {shown}")
    out.append("")

    out += _section("5. INVALID VALUES")
    out.append(f"{'CHECK':<34}{'COUNT':>7}   EXAMPLES")
    for name, info in p.invalid_values.items():
        sensitive = _sensitive_check(name, cfg)
        ex = ", ".join(_safe(e, sensitive) for e in info["examples"])[:32]
        out.append(f"{name:<34}{info['count']:>7}   {ex}")
    out.append("")
    out.append("'repairable_format' is recoverable by the cleaner; 'unrepairable'")
    out.append("needs a decision, not a parser.")
    out.append("")

    out += _section("6. CATEGORICAL VALIDITY - account_status")
    permitted = set(p.permitted_statuses)
    valid = {k: v for k, v in p.status_counts.items() if k in permitted}
    invalid = {k: v for k, v in p.status_counts.items() if k not in permitted}
    out.append(f"Permitted: {', '.join(sorted(permitted))}")
    out.append("")
    out.append(f"{'VALUE':<20}{'COUNT':>8}   STATUS")
    for k, v in sorted(valid.items(), key=lambda x: -x[1]):
        out.append(f"{repr(k):<20}{v:>8}   valid")
    for k, v in sorted(invalid.items(), key=lambda x: -x[1]):
        out.append(f"{repr(k):<20}{v:>8}   INVALID")
    out.append("")
    invalid_pct = _pct(sum(invalid.values()), p.n_rows)
    out.append(f"Invalid total: {sum(invalid.values())} rows ({invalid_pct:.2f}%)")
    out.append("")

    out += _section("SUMMARY")
    worst = max(p.columns, key=lambda c: c.missing_count, default=None)
    out.append(f"Rows profiled            : {p.n_rows:,}")
    out.append(f"Columns with missing data: {sum(1 for c in p.columns if c.missing_count)}")
    if worst is None:
        out.append("Least complete column    : none (no columns)")
    else:
        out.append(f"Least complete column    : {worst.name} "
                   f"({_pct(worst.missing_count, p.n_rows):.2f}% missing)")
    out.append(f"Invalid-value findings   : {sum(i['count'] for i in p.invalid_values.values())}")
    out.append(f"Additional format shapes : "
               f"{sum(max(len(s) - 1, 0) for s in p.format_inventory.values())}")
    out.append("  (shapes beyond the canonical one, not a count of bad records)")
    out.append("")
    return "\n".join(out) + "\n"


def render_pii_report(r: PIIReport, source: Path, cfg: Config) -> str:
    out = header("PII Detection Report", source, r.n_rows, cfg)

    out += _section("1. DECLARED PII INVENTORY")
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
    out.append("")
    out.append("Every column is scanned with every pattern; detecting by column name")
    out.append("would find only known PII. Patterns are US-format: absence of a")
    out.append("finding does not prove absence of international-format PII.")
    out.append("")

    out += _section("3. CONFIRMED MATCHES")
    out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}{'MATCHES':>9}   SAMPLE (redacted)")
    for f in r.findings:
        out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}{f.match_count:>9}   {f.samples[0] if f.samples else ''}")
    out.append("")
    out.append("Samples redacted: a PII report must not itself carry PII.")
    out.append("")

    out += _section("4. SUPPRESSED MATCHES")
    out.append("Structural coincidences, discarded by declared rule rather than by")
    out.append("tuning the patterns, so each discard stays auditable.")
    out.append("")
    out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}   REASON")
    for f in r.suppressed:
        out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}   {f.suppressed}")
    total_hits = sum(f.row_count for f in r.findings) + sum(f.row_count for f in r.suppressed)
    kept = sum(f.row_count for f in r.findings)
    out.append("")
    out.append(f"Raw hits {total_hits:,} -> confirmed {kept:,} "
               f"({_pct(kept, total_hits):.1f}% confirmation rate).")
    out.append("Not precision: these are regex hits filtered by policy, not matches")
    out.append("labelled against ground truth. Recall-first is deliberate - a missed")
    out.append("identifier is a breach, a false positive is review effort.")
    out.append("")

    out += _section("5. UNDECLARED PII - LEAKAGE")
    if not r.leaks:
        out.append("None found.")
    else:
        out.append("Direct identifiers in columns not meant to hold them. Schema-driven")
        out.append("masking would miss every one.")
        out.append("")
        out.append(f"{'COLUMN':<16}{'DETECTOR':<14}{'ROWS':>7}   FIRST AFFECTED ROWS")
        for f in r.leaks:
            out.append(f"{f.column:<16}{f.detector:<14}{f.row_count:>7}   {f.rows[:6]}")
        out.append("")
        out.append(f"Total: {r.leak_rows} distinct rows "
                   f"({sum(f.row_count for f in r.leaks)} findings; a row can leak more "
                   f"than one identifier).")
        worst = max(r.leaks, key=lambda f: {"critical": 3, "high": 2, "medium": 1}.get(f.sensitivity, 0))
        out.append(f"Highest severity: {worst.detector} in {worst.column} ({worst.sensitivity}).")
    out.append("")

    out += _section("6. BREACH EXPOSURE")
    pct_exposed = _pct(r.rows_with_pii, r.n_rows)
    out.append(f"Records containing personal data : {r.rows_with_pii:,} of "
               f"{r.n_rows:,} ({pct_exposed:.1f}%)")
    out.append("")
    out.append("Every record carries a name, an identifier and contact details, so no")
    out.append("subset of this file is safe to release unmasked.")
    out.append("")
    ssn = sum(f.row_count for f in r.findings if f.detector == "us_ssn")
    out.append("If disclosed:")
    out.append("  - Direct identifiers  name, email, phone" + (f", and {ssn} leaked SSNs" if ssn else ""))
    out.append("  - Financial data      income for every data subject")
    out.append("  - Location            home address for every data subject")
    out.append("")
    out.append("Where GDPR applies, Art. 33 sets a 72-hour notification duty for a")
    out.append("breach likely to risk data subjects' rights. Whether that threshold")
    out.append("is met is a formal assessment, not this pipeline's call; volume,")
    out.append("financial data and national identifiers are what it would weigh.")
    out.append("")

    out += _section("7. RE-IDENTIFICATION RISK")
    out.append("Masking direct identifiers does not make a dataset anonymous. Rows are")
    out.append("grouped by quasi-identifier (exact DOB, postal code, income band) to")
    out.append("show how many people each record hides among.")
    out.append("")
    out.append(f"Quasi-identifiers modelled: {', '.join(r.quasi_identifiers)}")
    if r.incomplete_signatures:
        out.append(f"Signatures with an unparseable component: "
                   f"{100 * r.incomplete_signatures:.1f}% - these share a common")
        out.append("'unknown' signature, which groups them together and overstates")
        out.append("their protection.")
    out.append("")
    out.append(f"{'GROUP SIZE':<16}{'ROWS':>8}{'PCT':>9}")
    for label in ["k=1 (unique)", "k=2", "k=3-5", "k>5"]:
        if label in r.k_anonymity:
            v = r.k_anonymity[label]
            out.append(f"{label:<16}{v:>8}{_pct(v, r.n_rows):>8.1f}%")
    out.append("")
    pct = _pct(r.unique_rows, r.n_rows)
    out.append(f"{pct:.1f}% of records are unique on quasi-identifiers alone (k=1).")
    out.append("These carry elevated linkage risk wherever matching auxiliary data")
    out.append("exists. Masking names and emails alone would not change it -")
    out.append("generalising the quasi-identifiers is what does.")
    out.append("")
    out.append("Treat the output as pseudonymised, not anonymous: k-anonymity does not")
    out.append("settle that, and Recital 26 keeps pseudonymised data in scope.")
    out.append("")
    return "\n".join(out) + "\n"


def render_validation_report(pre: ValidationResult, source: Path, cfg: Config,
                             post: ValidationResult | None = None) -> str:
    out = header("Validation Results", source, pre.n_rows, cfg)
    out.append("Engine: pandera, lazy=True - every rule against every row, so one bad")
    out.append("value cannot hide the rest.")
    out.append("")

    out += _section("1. RULES APPLIED")
    out.append("Declared in config/rules.yml, so rules change without touching code.")
    out.append("")

    out += _section("2. TYPE COERCION")
    out.append("Present but unconvertible. Pandera sees these as null once coerced,")
    out.append("which would lump them with genuinely missing values - a different")
    out.append("defect needing a different fix. They also block publication.")
    out.append("")
    out.append("These are a subset of the rule failures below, not additional to")
    out.append("them: an uncoercible value becomes null and then fails not_nullable.")
    out.append("Do not sum the two totals.")
    out.append("")
    if post is None:
        out.append(f"{'COLUMN':<20}{'UNCOERCIBLE':>13}   EXAMPLES")
        for col, n in pre.coercion_by_column.items():
            sensitive = col in cfg.sensitive_columns
            ex = ", ".join(dict.fromkeys(
                _safe(f.failure_case, sensitive) for f in pre.coercion if f.column == col))[:36]
            out.append(f"{col:<20}{n:>13}   {ex}")
        out.append(f"{'TOTAL':<20}{len(pre.coercion):>13}")
    else:
        columns = list(dict.fromkeys(
            list(pre.coercion_by_column) + list(post.coercion_by_column)))
        out.append(f"{'COLUMN':<20}{'PRE':>8}{'POST':>8}{'DELTA':>9}")
        for col in columns:
            a = pre.coercion_by_column.get(col, 0)
            b = post.coercion_by_column.get(col, 0)
            out.append(f"{col:<20}{a:>8}{b:>8}{b - a:>+9}")
        out.append("-" * WIDTH)
        out.append(f"{'TOTAL':<20}{len(pre.coercion):>8}{len(post.coercion):>8}"
                   f"{len(post.coercion) - len(pre.coercion):>+9}")
    out.append("")

    out += _section("3. RULE FAILURES")
    if post is None:
        out.append(f"{'RULE':<44}{'FAILURES':>10}")
        for rule, n in pre.by_rule.items():
            out.append(f"{rule:<44}{n:>10}")
        out.append("-" * WIDTH)
        out.append(f"{'TOTAL':<44}{len(pre.failures):>10}")
        out.append("")
        failing_pct = _pct(len(pre.failing_rows), pre.n_rows)
        out.append(f"Rows with at least one failure: {len(pre.failing_rows):,} "
                   f"of {pre.n_rows:,} ({failing_pct:.1f}%)")
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
        out.append("")
        if not post.passed:
            out.append("Rows survived cleaning and still fail validation, by rule or by")
            out.append("type coercion. They were neither repaired nor quarantined - a")
            out.append("defect in the cleaner, not the data. Publication is blocked.")
        else:
            out.append("Every row remaining after cleaning satisfies the schema. Rows")
            out.append("that could not be repaired without inventing data are in the")
            out.append("quarantine file with a reason, not silently dropped.")
    out.append("")

    # Post failures are the blocking ones when any survive; when none do, the
    # pre-clean examples are what a reader wants to see. Rendering post
    # unconditionally left an empty table under a heading promising failures.
    source_result = post if (post is not None and post.failures) else pre
    out += _section(f"4. FAILURE DETAIL - {source_result.stage.upper()}")

    # Spread the sample across checks. Taking the first 40 in order produced
    # forty near-identical rows from whichever check happened to fire first.
    by_check: dict[str, list] = {}
    for f in source_result.failures:
        by_check.setdefault(f"{f.column}.{f.check}", []).append(f)
    shown = []
    while len(shown) < 40 and any(by_check.values()):
        for group in by_check.values():
            if group and len(shown) < 40:
                shown.append(group.pop(0))

    total = len(source_result.failures)
    if not shown:
        out.append("No failures at either stage.")
    elif source_result is pre and post is not None:
        out.append(f"{len(shown)} of {total:,} pre-clean failures, sampled across "
                   f"checks. All were")
        out.append("resolved by cleaning. Identifying values are redacted.")
    else:
        out.append(f"{len(shown)} of {total:,} failures, sampled across checks. "
                   f"Identifying")
        out.append("values are redacted.")
    out.append("")
    out.append(f"{'ROW':>7}   {'COLUMN':<16}{'CHECK':<26}VALUE")
    for f in shown:
        row = str(f.index) if f.index is not None else "-"
        value = _safe(f.failure_case, f.column in cfg.sensitive_columns)[:24]
        out.append(f"{row:>7}   {f.column:<16}{f.check[:25]:<26}{value}")
    out.append("")

    out += _section("SUMMARY")
    final = post or pre
    out.append(f"Stage validated       : {final.stage}")
    out.append(f"Rule failures         : {len(final.failures):,}")
    out.append(f"Uncoercible values    : {len(final.coercion):,}")
    out.append(f"Schema compliant      : {'YES' if final.passed else 'NO'}")
    out.append("")
    return "\n".join(out) + "\n"


def render_cleaning_log(log: CleaningLog, source: Path, cfg: Config) -> str:
    out = header("Cleaning Log", source, log.rows_in, cfg)

    out += _section("1. NORMALISATIONS APPLIED")
    out.append("Repairs made where the intended value is unambiguous.")
    out.append("")
    out.append(f"{'REPAIR':<30}{'ROWS':>8}")
    for tag, n in log.repairs.most_common():
        out.append(f"{tag:<30}{n:>8}")
    out.append("-" * WIDTH)
    out.append(f"{'TOTAL':<30}{sum(log.repairs.values()):>8}")
    out.append("")
    out.append("phone -> XXX-XXX-XXXX, dates -> YYYY-MM-DD, names -> Title Case,")
    out.append("status and email -> lower case.")
    out.append("")

    out += _section("2. QUARANTINE")
    out.append("Not repairable without inventing data. Written to quarantine.csv with")
    out.append("a reason, never dropped - a deleted row is an unanswerable question.")
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
    out.append("Asserted every run: a row lost to a silent exception would otherwise")
    out.append("look identical to a row that was never there.")
    out.append("")
    retention = _pct(log.rows_out, log.rows_in)
    out.append(f"Retention: {retention:.1f}%")
    out.append("")

    out += _section("4. POLICY SENSITIVITY")
    s = policy_sensitivity(log, cfg.non_critical)
    out.append("Every column is declared non-nullable, so a blank optional field is")
    out.append("rejected as readily as a corrupt one - a governance choice, not a")
    out.append("fact about the data.")
    out.append("")
    out.append(f"Treated as optional: {', '.join(sorted(cfg.non_critical))}")
    out.append("")
    out.append(f"{'Quarantined under current policy':<42}{s['quarantined']:>8}")
    out.append(f"{'Failing only on a blank optional field':<42}{s['recoverable_under_tiered_policy']:>8}")
    out.append(f"{'Retention if those were kept and flagged':<42}"
               f"{_pct(s['retention_if_relaxed'], log.rows_in):>7.1f}%")
    out.append("")
    out.append(f"Retaining them would raise retention from "
               f"{_pct(log.rows_out, log.rows_in):.1f}% to "
               f"{_pct(s['retention_if_relaxed'], log.rows_in):.1f}%,")
    out.append("at the cost of nulls downstream. The strict policy is kept because the")
    out.append("brief declares these fields mandatory; the number is reported so the")
    out.append("trade-off can be re-argued with evidence.")
    out.append("")
    return "\n".join(out) + "\n"


def render_masked_sample(r: MaskResult, original: "pd.DataFrame", source: Path,
                         cfg: Config, n: int = 6) -> str:
    out = header("Masked Sample - Before / After", source, len(r.masked), cfg)
    out.append("HANDLING: shows unmasked values by design - it is the evidence the")
    out.append("control works. Committed only because the data is synthetic; against")
    out.append("production data this would be restricted.")
    out.append("")

    out += _section("1. MASKING RULES")
    out.append(f"{'COLUMN':<16}{'STRATEGY':<14}{'RULE':<34}RATIONALE")
    for rule in cfg.mask_rules:
        out.append(f"{rule.column:<16}{rule.strategy:<14}{rule.description:<34}{rule.rationale}")
    out.append("")
    out.append(f"Untouched: {', '.join(r.columns_untouched)}")
    out.append("customer_id is left intact so the extract still joins - which keeps it")
    out.append("a linkage key back to the unmasked source.")
    out.append("")

    out += _section("2. RECORD COMPARISON")
    for i in range(min(n, len(r.masked))):
        before, after = original.iloc[i], r.masked.iloc[i]
        out.append(f"Record {i + 1}")
        out.append(f"  {'FIELD':<16}{'BEFORE':<40}AFTER")
        for col in r.masked.columns:
            b, a = str(before[col])[:38], str(after[col])[:30]
            marker = "*" if col in r.columns_masked else " "
            out.append(f" {marker}{col:<16}{b:<40}{a}")
        out.append("")
    out.append("* masked field")
    out.append("")

    out += _section("3. LEAKED PII IN FREE TEXT")
    out.append("Part 2 found emails, phones and SSNs inside the address field.")
    out.append("Replacing the whole field removes them; keeping a city or postcode")
    out.append("would have left every one in place.")
    out.append("")

    out += _section("4. RE-IDENTIFICATION AFTER MASKING")
    out.append("Group sizes on the quasi-identifiers. Larger groups hide each person")
    out.append("among more people.")
    out.append("")
    out.append(f"Before : {', '.join(r.quasi_before)}"
               f"   (unparseable component in {100 * r.incomplete_before:.1f}%)")
    out.append(f"After  : {', '.join(r.quasi_after)}"
               f"   (unparseable component in {100 * r.incomplete_after:.1f}%)")
    out.append("Unparseable quasi-identifiers share an 'unknown' signature, which")
    out.append("groups them and overstates their protection.")
    out.append("The model changes with masking: postal code goes with the suppressed")
    out.append("address, DOB and income are generalised, created_date joins at year")
    out.append("granularity. The after set covers every released quasi-identifier,")
    out.append("including unmasked columns - scoring only masked ones would flatter.")
    out.append("")
    total = len(r.masked)
    out.append(f"{'GROUP SIZE':<16}{'BEFORE':>10}{'AFTER':>10}")
    for label in ["k=1 (unique)", "k=2", "k=3-5", "k>5"]:
        out.append(f"{label:<16}{r.k_before.get(label, 0):>10}{r.k_after.get(label, 0):>10}")
    out.append("")
    out.append(f"Uniquely re-identifiable: {_pct(r.unique_before, total):.1f}% "
               f"-> {_pct(r.unique_after, total):.1f}%")
    out.append("")
    out.append("Achieved by generalising quasi-identifiers, not by masking direct")
    out.append("ones. Masking names and emails alone leaves this figure unchanged.")
    out.append("")
    out.append(f"{r.unique_after} records remain unique on the modelled post-mask")
    out.append("quasi-identifiers.")
    out.append("k-anonymity is a risk indicator, not proof of anonymity: it measures")
    out.append("uniqueness only over the quasi-identifiers chosen, says nothing about")
    out.append("attribute disclosure within a group, and an attacker may hold")
    out.append("attributes not modelled here. The extract is pseudonymous, not")
    out.append("anonymous, and remains personal data under GDPR.")
    out.append("")

    out += _section("5. UTILITY RETAINED")
    out.append("Still supported : age analysis, income segmentation by band,")
    out.append("                  email-provider mix, status and tenure reporting,")
    out.append("                  joins on customer_id")
    out.append("Now impossible  : contacting individuals, geographic analysis,")
    out.append("                  exact income statistics, exact age or birthday")
    out.append("")
    return "\n".join(out) + "\n"


def render_execution_report(r: RunResult) -> str:
    out = header("Pipeline Execution Report", r.source, r.stages[0].rows_out if r.stages else 0)
    out.append(f"Started    : {r.started}")
    out.append(f"Rules      : v{r.rules_version}")
    out.append(f"Reference  : {r.reference_date}")
    out.append(f"Status     : {'SUCCESS' if r.ok else 'FAILED at ' + str(r.failed_stage)}")
    out.append(f"Duration   : {r.seconds:.2f}s")
    out.append("")

    out += _section("1. STAGE TIMELINE")
    out.append(f"{'#':<3}{'STAGE':<16}{'IN':>8}{'OUT':>8}{'SECONDS':>9}  {'STATUS':<8}DETAIL")
    for i, s_ in enumerate(r.stages, 1):
        out.append(f"{i:<3}{s_.name:<16}{s_.rows_in:>8}{s_.rows_out:>8}"
                   f"{s_.seconds:>9.2f}  {s_.status:<8}{s_.detail[:30]}")
    out.append("-" * WIDTH)
    out.append(f"{'':<3}{'TOTAL':<16}{'':>8}{'':>8}{r.seconds:>9.2f}")
    out.append("")
    if r.stages and r.seconds > 0:
        slowest = max(r.stages, key=lambda x: x.seconds)
        out.append(f"Slowest stage: {slowest.name} ({slowest.seconds:.2f}s, "
                   f"{100 * slowest.seconds / r.seconds:.0f}% of runtime)")
    out.append("")

    out += _section("2. STAGE ORDER")
    out.append("Two gates. Post-clean validation guards publication: the cleaned")
    out.append("extract is written only once it satisfies its own schema. Release")
    out.append("verification guards masking: the masked frame is re-scanned and")
    out.append("nothing reaches disk unless it is clean.")
    out.append("")
    out.append("PII detection runs on the raw file - exposure is a property of what")
    out.append("landed on disk. Validation runs twice: the pre/post delta is what")
    out.append("shows remediation worked.")
    out.append("")

    out += _section("3. ROW ACCOUNTING")
    o = r.outputs
    if "quarantined" in o:
        rows_in = r.stages[0].rows_out
        cleaned = rows_in - o["quarantined"]
        out.append(f"{'Rows read':<34}{rows_in:>10,}")
        out.append(f"{'Rows cleaned':<34}{cleaned:>10,}")
        out.append(f"{'Rows quarantined':<34}{o['quarantined']:>10,}")
        out.append("-" * WIDTH)
        out.append(f"{'Balance':<34}{cleaned + o['quarantined']:>10,}   "
                   f"{'OK' if cleaned + o['quarantined'] == rows_in else 'MISMATCH'}")
        out.append("")
        out.append("Asserted in the clean stage: a mismatch aborts rather than writing")
        out.append("a file quietly short of rows.")
    out.append("")

    out += _section("4. OUTCOMES")
    labels = {
        "quality_issues": "Invalid values found",
        "pii_findings": "PII finding types confirmed",
        "pii_leaks": "Rows with PII leaked into free text",
        "failures_pre": "Rule failures before cleaning",
        "coercion_pre": "Values that would not convert, before cleaning",
        "repairs": "Values normalised",
        "quarantined": "Rows quarantined",
        "failures_post": "Rule failures after cleaning",
        "coercion_post": "Values that would not convert, after cleaning",
        "unique_before": "Uniquely re-identifiable before masking",
        "unique_after": "Uniquely re-identifiable after masking",
        "residual_identifiers": "Direct identifiers left in the masked extract",
    }
    for key, label in labels.items():
        if key in o:
            out.append(f"{label:<44}{o[key]:>8,}")
    out.append("")

    out += _section("5. ARTIFACTS WRITTEN")
    for path in r.artifacts:
        size = path.stat().st_size if path.exists() else 0
        out.append(f"  {str(path.name):<32}{size:>10,} bytes")
    out.append("")

    if not r.ok:
        out += _section("6. FAILURE")
        out.append(f"Stage : {r.failed_stage}")
        out.append(f"Error : {r.error}")
        out.append("")
        out.append("Downstream stages did not run. Artifacts written before the")
        out.append("failure are listed above and describe the last good state.")
        out.append("")
    return "\n".join(out) + "\n"


def render_scorecard(card: ScoreCard, source: Path, n_rows: int, cfg: Config) -> str:
    out = header("Detection Scorecard", source, n_rows, cfg)
    out.append("Measured against the generator's manifest. Nothing in the pipeline")
    out.append("reads it: a detector that can see the answer key measures nothing.")
    out.append("")

    out += _section("1. WHAT IS MEASURED")
    out.append("RECALL      the row was acted on - repaired or rejected")
    out.append("ATTRIBUTION the check expected to catch it is the one that fired")
    out.append("CONTAINMENT it did not survive into the cleaned extract")
    out.append("SPECIFICITY defect-free rows that were not quarantined")
    out.append("")
    out.append("Recall and specificity are a pair: quarantining everything scores")
    out.append("100% recall and 0% specificity, so neither can be gamed alone.")
    out.append("")

    out += _section("2. PER-DEFECT RESULTS")
    out.append(f"{'DEFECT':<32}{'COLUMN':<15}{'PLANTED':>8}{'RECALL':>8}"
               f"{'ATTRIB':>8}{'CONTAIN':>9}")
    for s_ in card.scores:
        out.append(f"{s_.defect:<32}{s_.column:<15}{s_.planted:>8}"
                   f"{100 * s_.recall:>7.1f}%{100 * s_.attribution:>7.1f}%"
                   f"{100 * s_.pre_mask_containment:>8.1f}%")
    out.append("-" * WIDTH)
    out.append(f"{'TOTAL (micro)':<47}{card.planted:>8}"
               f"{100 * card.recall:>7.1f}%{100 * card.attribution:>7.1f}%"
               f"{100 * card.pre_mask_containment:>8.1f}%")
    out.append(f"{'TOTAL (macro, per defect class)':<47}{len(card.scores):>8}"
               f"{100 * card.macro_recall:>7.1f}%{100 * card.macro_attribution:>7.1f}%")
    out.append("")
    out.append("Micro weights by volume; macro weights each defect class equally, so")
    out.append("a rare broken rule stays visible.")
    out.append("")
    if card.unmeasured:
        out.append(f"Unmeasured defects: {', '.join(card.unmeasured)}")
        out.append("")

    out += _section("3. DEFECTS NOT FULLY RECALLED")
    misses = [s_ for s_ in card.scores if s_.recall < 1.0]
    if not misses:
        out.append("None: every planted defect was acted on.")
    else:
        out.append("Not acted on in its own column. Another control may still have")
        out.append("contained the row - these need review, not assumption.")
        out.append("")
        out.append(f"{'DEFECT':<34}{'COLUMN':<16}{'PLANTED':>8}{'MISSED':>8}")
        for s_ in misses:
            out.append(f"{s_.defect:<34}{s_.column:<16}{s_.planted:>8}"
                       f"{s_.planted - s_.handled:>8}")
    out.append("")

    out += _section("4. RECALL AND ATTRIBUTION DIVERGENCE")
    diverged = [s_ for s_ in card.scores if s_.attribution < s_.recall]
    if not diverged:
        out.append("None: every handled defect was caught by the expected check.")
    else:
        out.append("Handled, but by a different check than expected. May be genuine")
        out.append("ambiguity - a value both malformed and sentinel-null is reportable")
        out.append("as either - or a mismatched mapping. Worth reviewing.")
        out.append("")
        out.append(f"{'DEFECT':<34}{'RECALL':>9}{'ATTRIB':>9}{'DIFF':>8}")
        for s_ in diverged:
            out.append(f"{s_.defect:<34}{100 * s_.recall:>8.1f}%"
                       f"{100 * s_.attribution:>8.1f}%{s_.handled - s_.attributed:>8}")
    out.append("")

    out += _section("SUMMARY")
    out.append(f"{'Defect classes measured':<34}{len(card.scores):>8,}")
    out.append(f"{'Defects planted':<34}{card.planted:>8,}")
    out.append(f"{'Handled':<34}{card.handled:>8,}   {100 * card.recall:.1f}%")
    out.append(f"{'Correctly attributed':<34}{card.attributed:>8,}   {100 * card.attribution:.1f}%")
    out.append("")
    out.append(f"{'Survived into cleaned extract':<34}{card.escaped:>8,}   "
               f"pre-mask containment {100 * card.pre_mask_containment:.1f}%")
    out.append("")
    if card.escaped:
        out.append("Reached customers_cleaned.csv untouched in that column. Masking may")
        out.append("still remove them; verify_release confirms the masked extract is")
        out.append("clean.")
        out.append("")
    out.append(f"{'Rows with no planted defect':<34}{card.clean_rows:>8,}")
    out.append(f"{'  of those, quarantined':<34}{card.falsely_quarantined:>8,}")
    out.append(f"{'Specificity':<34}{'':>8}   {100 * card.specificity:.1f}%")
    out.append("")
    if card.falsely_quarantined:
        out.append("Not necessarily errors: defects are planted per column, so a row")
        out.append("can carry an invalid combination that was never planted.")
        out.append("")
    return "\n".join(out) + "\n"


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Explicit: reports carry names in any script, the default is locale-dependent.
    path.write_text(content, encoding="utf-8")
    return path
