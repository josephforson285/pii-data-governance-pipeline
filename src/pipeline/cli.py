"""Command line entrypoint. Run with: python -m pipeline <command>"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "customers_raw.csv"
REPORTS = ROOT / "reports"

log = logging.getLogger("pipeline")


def _cmd_generate(args: argparse.Namespace) -> int:
    from pipeline.generate import write

    path = write(Path(args.out), n_rows=args.rows, seed=args.seed)
    log.info("wrote %s (%d rows, seed %d)", path, args.rows, args.seed)
    return 0


def _cmd_profile(args: argparse.Namespace) -> int:
    from pipeline.loading import load_raw
    from pipeline.profile import profile
    from pipeline.report import render_quality_report, write

    src = Path(args.input)
    df = load_raw(src)
    log.info("loaded %s (%d rows)", src.name, len(df))

    out = write(Path(args.reports) / "data_quality_report.txt", render_quality_report(profile(df), src))
    log.info("wrote %s", out)
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    from pipeline.loading import load_raw
    from pipeline.pii import detect
    from pipeline.report import render_pii_report, write

    src = Path(args.input)
    df = load_raw(src)
    report = detect(df)
    log.info("scanned %d columns, %d confirmed findings, %d leaks",
             len(df.columns), len(report.findings), len(report.leaks))

    out = write(Path(args.reports) / "pii_detection_report.txt", render_pii_report(report, src))
    log.info("wrote %s", out)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    from pipeline.loading import load_raw
    from pipeline.report import render_validation_report, write
    from pipeline.validate import load_rules, validate

    src = Path(args.input)
    result = validate(load_raw(src), load_rules(Path(args.rules)), stage="pre-clean")
    log.info("%d rule failures across %d rows, %d uncoercible values",
             len(result.failures), len(result.failing_rows), len(result.coercion))

    out = write(Path(args.reports) / "validation_results.txt",
                render_validation_report(result, src))
    log.info("wrote %s", out)
    return 0


def _cmd_clean(args: argparse.Namespace) -> int:
    from pipeline.clean import clean, quarantine_frame
    from pipeline.loading import load_raw
    from pipeline.report import render_cleaning_log, render_validation_report, write
    from pipeline.validate import load_rules, validate

    src = Path(args.input)
    rules = load_rules(Path(args.rules))
    raw = load_raw(src)

    pre = validate(raw, rules, stage="pre-clean")
    log.info("pre-clean: %d rule failures", len(pre.failures))

    cleaned, clog = clean(raw, rules)
    if not clog.reconciles():
        raise RuntimeError(
            f"row reconciliation failed: {clog.rows_in} in, "
            f"{clog.rows_out} out, {clog.rows_quarantined} quarantined"
        )
    log.info("cleaned %d rows, quarantined %d", clog.rows_out, clog.rows_quarantined)

    Path(args.processed).mkdir(parents=True, exist_ok=True)
    Path(args.rejects).mkdir(parents=True, exist_ok=True)
    cleaned.to_csv(Path(args.processed) / "customers_cleaned.csv", index=False)
    quarantine_frame(clog).to_csv(Path(args.rejects) / "quarantine.csv", index=False)

    post = validate(cleaned, rules, stage="post-clean")
    log.info("post-clean: %d rule failures", len(post.failures))

    write(Path(args.reports) / "cleaning_log.txt", render_cleaning_log(clog, src))
    write(Path(args.reports) / "validation_results.txt",
          render_validation_report(pre, src, post=post))
    log.info("wrote cleaning_log.txt and validation_results.txt")
    return 0


def _cmd_mask(args: argparse.Namespace) -> int:
    import pandas as pd

    from pipeline.mask import mask
    from pipeline.report import render_masked_sample, write

    src = Path(args.input)
    cleaned = pd.read_csv(src, dtype=str, keep_default_na=False)
    result = mask(cleaned)

    out_csv = Path(args.processed) / "customers_masked.csv"
    result.masked.to_csv(out_csv, index=False)
    log.info("masked %d columns over %d rows -> %s",
             len(result.columns_masked), len(result.masked), out_csv.name)
    log.info("uniquely re-identifiable: %d -> %d rows", result.unique_before, result.unique_after)

    write(Path(args.reports) / "masked_sample.txt",
          render_masked_sample(result, cleaned, src))
    log.info("wrote masked_sample.txt")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from pipeline.report import render_execution_report, write
    from pipeline.run import run

    result = run(
        source=Path(args.input),
        rules_path=Path(args.rules),
        processed=Path(args.processed),
        rejects=Path(args.rejects),
        reports=Path(args.reports),
    )
    write(Path(args.reports) / "pipeline_execution_report.txt", render_execution_report(result))
    log.info("run %s in %.2fs", "succeeded" if result.ok else "FAILED", result.seconds)
    return 0 if result.ok else 1


def _cmd_score(args: argparse.Namespace) -> int:
    from pipeline.clean import clean
    from pipeline.loading import load_raw
    from pipeline.pii import detect
    from pipeline.report import render_scorecard, write
    from pipeline.score import load_ground_truth, score
    from pipeline.validate import load_rules

    src = Path(args.input)
    truth_path = src.parent / "_ground_truth.json"
    if not truth_path.exists():
        log.error("no ground truth at %s; scoring needs a generated dataset", truth_path)
        return 1

    raw = load_raw(src)
    _, clog = clean(raw, load_rules(Path(args.rules)))
    card = score(load_ground_truth(truth_path), clog, detect(raw))
    log.info("recall %.1f%%, attribution %.1f%% over %d planted defects",
             100 * card.recall, 100 * card.attribution, card.planted)

    out = write(Path(args.reports) / "detection_scorecard.txt",
                render_scorecard(card, src, len(raw)))
    log.info("wrote %s", out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipeline", description="PII detection and data quality pipeline")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate the synthetic raw dataset")
    g.add_argument("--rows", type=int, default=5000)
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--out", default=str(RAW.parent))
    g.set_defaults(func=_cmd_generate)

    pr = sub.add_parser("profile", help="profile the raw dataset (part 1)")
    pr.add_argument("--input", default=str(RAW))
    pr.add_argument("--reports", default=str(REPORTS))
    pr.set_defaults(func=_cmd_profile)

    dt = sub.add_parser("detect", help="detect PII in the raw dataset (part 2)")
    dt.add_argument("--input", default=str(RAW))
    dt.add_argument("--reports", default=str(REPORTS))
    dt.set_defaults(func=_cmd_detect)

    va = sub.add_parser("validate", help="validate against the schema (part 3)")
    va.add_argument("--input", default=str(RAW))
    va.add_argument("--rules", default=str(ROOT / "config" / "rules.yml"))
    va.add_argument("--reports", default=str(REPORTS))
    va.set_defaults(func=_cmd_validate)

    cl = sub.add_parser("clean", help="normalise, quarantine and re-validate (part 4)")
    cl.add_argument("--input", default=str(RAW))
    cl.add_argument("--rules", default=str(ROOT / "config" / "rules.yml"))
    cl.add_argument("--processed", default=str(ROOT / "data" / "processed"))
    cl.add_argument("--rejects", default=str(ROOT / "data" / "rejects"))
    cl.add_argument("--reports", default=str(REPORTS))
    cl.set_defaults(func=_cmd_clean)

    mk = sub.add_parser("mask", help="mask PII in the cleaned dataset (part 5)")
    mk.add_argument("--input", default=str(ROOT / "data" / "processed" / "customers_cleaned.csv"))
    mk.add_argument("--processed", default=str(ROOT / "data" / "processed"))
    mk.add_argument("--reports", default=str(REPORTS))
    mk.set_defaults(func=_cmd_mask)

    rn = sub.add_parser("run", help="run every stage end to end (part 6)")
    rn.add_argument("--input", default=str(RAW))
    rn.add_argument("--rules", default=str(ROOT / "config" / "rules.yml"))
    rn.add_argument("--processed", default=str(ROOT / "data" / "processed"))
    rn.add_argument("--rejects", default=str(ROOT / "data" / "rejects"))
    rn.add_argument("--reports", default=str(REPORTS))
    rn.set_defaults(func=_cmd_run)

    sc = sub.add_parser("score", help="measure detection against the planted defects")
    sc.add_argument("--input", default=str(RAW))
    sc.add_argument("--rules", default=str(ROOT / "config" / "rules.yml"))
    sc.add_argument("--reports", default=str(REPORTS))
    sc.set_defaults(func=_cmd_score)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    REPORTS.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(), logging.FileHandler(REPORTS / "pipeline.log", mode="w")],
    )
    try:
        return args.func(args)
    except Exception:
        log.exception("unhandled error in %s", args.command)
        return 1
