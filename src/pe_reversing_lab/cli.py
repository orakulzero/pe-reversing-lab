"""
src/pe_reversing_lab/cli.py
CLI entry point for PE Reversing Lab (`pe-reversing-lab triage --profile packed_injector --json`).
"""

from __future__ import annotations

import argparse
import json

from pe_reversing_lab.l3_pipeline import StaticTriagePipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pe-reversing-lab",
        description="Static PE32+ x86_64 Reverse Engineering, Entropy & YARA Triage CLI",
    )
    sub = parser.add_subparsers(dest="command")

    p_triage = sub.add_parser("triage", help="Run 5-stage static PE32+ x86_64 triage")
    p_triage.add_argument(
        "--profile",
        default="packed_injector",
        help="Target sample profile (clean, anti_debug, packed_injector)",
    )
    p_triage.add_argument("--json", action="store_true", help="Emit JSON output")

    args = parser.parse_args(argv)
    if args.command == "triage":
        pipeline = StaticTriagePipeline()
        res = pipeline.triage_sample(profile=args.profile)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(
                f"[{res['profile']}] severity={res['severity']} "
                f"score={res['threat_score']} packed={res['packed']}"
            )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
