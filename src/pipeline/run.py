"""Part 6: orchestrate every stage into one run.

Stage order matters and is not the order the brief lists:

  profile -> detect PII -> validate(pre) -> clean -> validate(post) -> mask

PII detection runs on the raw data because breach exposure is a property of
what actually landed on disk; running it after cleaning would understate it by
however many rows were quarantined. Validation runs on both sides because a
single post-clean pass only proves the clean data is clean - the delta is what
shows remediation worked.

A stage failure aborts the run and still writes the execution report: a run
that dies without a record of where is the failure mode this exists to avoid.
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
    from pipeline.pii import detect
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

    def artifact(path: Path) -> None:
        result.artifacts.append(path)

    try:
        with _Timer(result, "load", 0) as t:
            cfg = load_config(rules_path)
            result.rules_version = cfg.version
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
                # Schema drift in a PII pipeline may be a new sensitive column
                # arriving unclassified, so it is surfaced rather than ignored.
                log.warning("unexpected columns not in schema: %s", ", ".join(unexpected))
                result.outputs["unexpected_columns"] = ", ".join(unexpected)
            t.finish(len(raw), f"{len(raw.columns)} columns")

        with _Timer(result, "profile", len(raw)) as t:
            prof = profile(raw, cfg)
            artifact(write(reports / "data_quality_report.txt", render_quality_report(prof, source, cfg)))
            issues = sum(i["count"] for i in prof.invalid_values.values())
            result.outputs["quality_issues"] = issues
            t.finish(len(raw), f"{issues} invalid values")

        with _Timer(result, "detect_pii", len(raw)) as t:
            pii = detect(raw)
            artifact(write(reports / "pii_detection_report.txt", render_pii_report(pii, source, cfg)))
            result.outputs["pii_findings"] = len(pii.findings)
            result.outputs["pii_leaks"] = sum(f.row_count for f in pii.leaks)
            t.finish(len(raw), f"{len(pii.findings)} findings, {result.outputs['pii_leaks']} leaked rows")

        with _Timer(result, "validate_pre", len(raw)) as t:
            pre = validate(raw, cfg, stage="pre-clean")
            result.outputs["failures_pre"] = len(pre.failures)
            t.finish(len(raw), f"{len(pre.failures)} rule failures")

        with _Timer(result, "clean", len(raw)) as t:
            cleaned, clog = clean(raw, cfg)
            if not clog.reconciles():
                raise RuntimeError(
                    f"reconciliation failed: {clog.rows_in} in != "
                    f"{clog.rows_out} out + {clog.rows_quarantined} quarantined"
                )
            cleaned.to_csv(processed / "customers_cleaned.csv", index=False)
            quarantine_frame(clog, cfg.sensitive_columns).to_csv(rejects / "quarantine.csv", index=False)
            artifact(write(reports / "cleaning_log.txt", render_cleaning_log(clog, source, cfg)))
            artifact(processed / "customers_cleaned.csv")
            artifact(rejects / "quarantine.csv")
            result.outputs["quarantined"] = clog.rows_quarantined
            result.outputs["repairs"] = sum(clog.repairs.values())
            t.finish(len(cleaned), f"{clog.rows_quarantined} quarantined, reconciled")

        with _Timer(result, "validate_post", len(cleaned)) as t:
            post = validate(cleaned, cfg, stage="post-clean")
            artifact(write(reports / "validation_results.txt",
                           render_validation_report(pre, source, cfg, post=post)))
            result.outputs["failures_post"] = len(post.failures)
            t.finish(len(cleaned), f"{len(post.failures)} rule failures")

        with _Timer(result, "mask", len(cleaned)) as t:
            masked = mask(cleaned, cfg)
            masked.masked.to_csv(processed / "customers_masked.csv", index=False)
            artifact(write(reports / "masked_sample.txt",
                           render_masked_sample(masked, cleaned, source, cfg)))
            artifact(processed / "customers_masked.csv")
            result.outputs["unique_before"] = masked.unique_before
            result.outputs["unique_after"] = masked.unique_after
            t.finish(len(masked.masked), f"unique {masked.unique_before} -> {masked.unique_after}")
    except Exception:
        # _Timer has already recorded which stage failed and why; the caller
        # needs the partial result to write the execution report.
        log.error("run aborted at stage %s", result.failed_stage)
    return result
