"""Part 6: orchestrate every stage into one run.

Detection runs on raw data (exposure is a property of what landed on disk) and
validation runs both sides of cleaning (the delta is the evidence). Nothing is
published until it has been validated, and nothing masked is written until it
has been re-scanned. A stage failure still writes the execution report.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("pipeline.run")


@dataclass
class Stage:
    name: str
    rows_in: int
    rows_out: int
    seconds: float
    status: str = "ok"
    detail: str = ""


@dataclass
class RunResult:
    source: Path
    started: str
    reference_date: str = ""
    stages: list[Stage] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    outputs: dict[str, Any] = field(default_factory=dict)
    rules_version: int = 0
    failed_stage: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.failed_stage is None

    @property
    def seconds(self) -> float:
        return sum(s.seconds for s in self.stages)


class _Timer:
    def __init__(self, result: RunResult, name: str, rows_in: int):
        self.result, self.name, self.rows_in = result, name, rows_in

    def __enter__(self):
        self.t0 = time.perf_counter()
        log.info("stage %s: start (%d rows in)", self.name, self.rows_in)
        return self

    def finish(self, rows_out: int, detail: str = "") -> None:
        elapsed = time.perf_counter() - self.t0
        self.result.stages.append(Stage(self.name, self.rows_in, rows_out, elapsed, "ok", detail))
        log.info("stage %s: ok in %.2fs (%d rows out) %s", self.name, elapsed, rows_out, detail)

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            elapsed = time.perf_counter() - self.t0
            self.result.stages.append(
                Stage(self.name, self.rows_in, 0, elapsed, "FAILED", f"{exc_type.__name__}: {exc}")
            )
            self.result.failed_stage = self.name
            self.result.error = f"{exc_type.__name__}: {exc}"
            log.error("stage %s: FAILED after %.2fs - %s", self.name, elapsed, exc)
        return False


def run(source: Path, rules_path: Path, processed: Path, rejects: Path,
        reports: Path) -> RunResult:
    from pipeline.clean import clean, quarantine_frame
    from pipeline.loading import load_raw
    from pipeline.mask import mask
    from pipeline.pii import detect, verify_release
    from pipeline.profile import profile
    from pipeline.report import (
        render_cleaning_log, render_masked_sample, render_pii_report,
        render_quality_report, render_validation_report, write,
    )
    from pipeline.config import load as load_config
    from pipeline.validate import validate

    from datetime import datetime, timezone

    result = RunResult(source=source, started=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    processed.mkdir(parents=True, exist_ok=True)
    rejects.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    # Clear what this run publishes. A failed run would otherwise leave the
    # previous run's extract in place, looking current.
    for stale in ("customers_cleaned.csv", "customers_masked.csv"):
        (processed / stale).unlink(missing_ok=True)
    (rejects / "quarantine.csv").unlink(missing_ok=True)

    def artifact(path: Path) -> None:
        result.artifacts.append(path)

    try:
        with _Timer(result, "load", 0) as t:
            cfg = load_config(rules_path)
            result.rules_version = cfg.version
            result.reference_date = cfg.reference_date.isoformat()
            raw = load_raw(source)
            # Structural check before any stage touches a column, so a renamed
            # or absent field fails here with a usable message rather than as a
            # KeyError from whichever stage happened to reach it first.
            missing = [c for c in cfg.schema if c not in raw.columns]
            if missing:
                raise ValueError(
                    f"input is missing required columns: {', '.join(missing)}; "
                    f"found {', '.join(raw.columns)}"
                )
            unexpected = [c for c in raw.columns if c not in cfg.schema]
            if unexpected:
                # An unclassified column may be new sensitive data. The policy
                # decides whether that stops the run.
                result.outputs["unexpected_columns"] = ", ".join(unexpected)
                if cfg.unexpected_column_policy == "fail":
                    raise ValueError(
                        f"input has columns absent from the schema: "
                        f"{', '.join(unexpected)}. They are unclassified, so their "
                        f"sensitivity is unknown and nothing masks them."
                    )
                log.warning("unexpected columns not in schema: %s", ", ".join(unexpected))
            t.finish(len(raw), f"{len(raw.columns)} columns")

        with _Timer(result, "profile", len(raw)) as t:
            prof = profile(raw, cfg)
            artifact(write(reports / "data_quality_report.txt", render_quality_report(prof, source, cfg)))
            issues = sum(i["count"] for i in prof.invalid_values.values())
            result.outputs["quality_issues"] = issues
            t.finish(len(raw), f"{issues} invalid values")

        with _Timer(result, "detect_pii", len(raw)) as t:
            pii = detect(raw, cfg)
            artifact(write(reports / "pii_detection_report.txt", render_pii_report(pii, source, cfg)))
            result.outputs["pii_findings"] = len(pii.findings)
            leak_rows = set()
            for f in pii.leaks:
                leak_rows.update(f.rows)
            result.outputs["pii_leaks"] = len(leak_rows)
            t.finish(len(raw), f"{len(pii.findings)} findings, {result.outputs['pii_leaks']} leaked rows")

        with _Timer(result, "validate_pre", len(raw)) as t:
            pre = validate(raw, cfg, stage="pre-clean")
            result.outputs["failures_pre"] = len(pre.failures)
            result.outputs["coercion_pre"] = len(pre.coercion)
            t.finish(len(raw), f"{len(pre.failures)} rule failures")

        with _Timer(result, "clean", len(raw)) as t:
            cleaned, clog = clean(raw, cfg)
            if not clog.reconciles():
                raise RuntimeError(
                    f"reconciliation failed: {clog.rows_in} in != "
                    f"{clog.rows_out} out + {clog.rows_quarantined} quarantined"
                )
            # Not written here: post-validation gates publication.
            quarantine_frame(clog, cfg.sensitive_columns).to_csv(rejects / "quarantine.csv", index=False)
            artifact(write(reports / "cleaning_log.txt", render_cleaning_log(clog, source, cfg)))
            artifact(rejects / "quarantine.csv")
            result.outputs["quarantined"] = clog.rows_quarantined
            result.outputs["repairs"] = sum(clog.repairs.values())
            t.finish(len(cleaned), f"{clog.rows_quarantined} quarantined, reconciled")

        with _Timer(result, "validate_post", len(cleaned)) as t:
            post = validate(cleaned, cfg, stage="post-clean")
            artifact(write(reports / "validation_results.txt",
                           render_validation_report(pre, source, cfg, post=post)))
            result.outputs["failures_post"] = len(post.failures)
            result.outputs["coercion_post"] = len(post.coercion)
            t.finish(len(cleaned), f"{len(post.failures)} rule failures")

        with _Timer(result, "publish", len(cleaned)) as t:
            # A row that survived cleaning and still fails the schema was
            # neither repaired nor quarantined - a defect in the cleaner.
            if not post.passed:
                offenders = ", ".join(
                    sorted({f.column for f in post.failures + post.coercion})[:5])
                raise RuntimeError(
                    f"post-clean validation failed: {len(post.failures)} rule "
                    f"failures, {len(post.coercion)} coercion failures across "
                    f"[{offenders}]; refusing to publish. "
                    f"See reports/validation_results.txt"
                )
            cleaned.to_csv(processed / "customers_cleaned.csv", index=False)
            artifact(processed / "customers_cleaned.csv")
            t.finish(len(cleaned), "schema compliant")

        with _Timer(result, "mask", len(cleaned)) as t:
            # Masked in memory only. Nothing reaches disk until verify_release
            # has confirmed it carries no direct identifiers.
            masked = mask(cleaned, cfg)
            result.outputs["unique_before"] = masked.unique_before
            result.outputs["unique_after"] = masked.unique_after
            t.finish(len(masked.masked), f"unique {masked.unique_before} -> {masked.unique_after}")

        with _Timer(result, "verify_release", len(masked.masked)) as t:
            residual = verify_release(masked.masked)
            if residual:
                detail = ", ".join(f"{f.detector} in {f.column} ({f.row_count} rows)"
                                   for f in residual)
                raise RuntimeError(
                    f"masked extract still contains direct identifiers: {detail}. "
                    f"The masking policy does not cover what the scan found."
                )
            result.outputs["residual_identifiers"] = 0
            t.finish(len(masked.masked), "no direct identifiers remain")

        with _Timer(result, "publish_masked", len(masked.masked)) as t:
            masked.masked.to_csv(processed / "customers_masked.csv", index=False)
            artifact(write(reports / "masked_sample.txt",
                           render_masked_sample(masked, cleaned, source, cfg)))
            artifact(processed / "customers_masked.csv")
            t.finish(len(masked.masked), "verified before write")
    except Exception:
        # _Timer has already recorded which stage failed and why; the caller
        # needs the partial result to write the execution report.
        log.error("run aborted at stage %s", result.failed_stage)
    return result
