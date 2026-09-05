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

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    return args.func(args)
