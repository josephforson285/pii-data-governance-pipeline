"""Command line entrypoint. Run with: python -m pipeline <command>"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

log = logging.getLogger("pipeline")


def _cmd_generate(args: argparse.Namespace) -> int:
    from pipeline.generate import write

    path = write(Path(args.out), n_rows=args.rows, seed=args.seed)
    log.info("wrote %s (%d rows, seed %d)", path, args.rows, args.seed)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipeline", description="PII detection and data quality pipeline")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate the synthetic raw dataset")
    g.add_argument("--rows", type=int, default=5000)
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--out", default=str(ROOT / "data" / "raw"))
    g.set_defaults(func=_cmd_generate)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    return args.func(args)
