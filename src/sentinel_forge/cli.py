from __future__ import annotations

import argparse
from pathlib import Path

from sentinel_forge.replay import (
    replay_analyst_report_json,
    replay_findings_json,
    replay_manager_summary_text,
    replay_samples_json,
    replay_summary_json,
)
from sentinel_forge.logger import setup_logging, get_logger

logger = get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel-forge")
    parser.add_argument(
        "command",
        nargs="?",
        default="status",
        choices=[
            "status",
            "replay-samples",
            "replay-findings",
            "incident-summary",
            "analyst-report",
            "manager-summary",
        ],
        help="Command to run",
    )
    parser.add_argument(
        "--json-log",
        action="store_true",
        help="Emit logs in SIEM-friendly JSON format",
    )
    args = parser.parse_args()

    setup_logging(json_format=args.json_log)

    if args.command == "status":
        logger.info("sentinel_forge_status", status="operational")
        print(
            "Sentinel Forge MVP is in place. Sample ingestion, normalization, detections, and reporting are available."
        )
        return

    if args.command == "replay-samples":
        root = Path(__file__).resolve().parents[2]
        print(replay_samples_json(root / "samples"))
        return

    if args.command == "replay-findings":
        root = Path(__file__).resolve().parents[2]
        print(replay_findings_json(root / "samples"))
        return

    if args.command == "incident-summary":
        root = Path(__file__).resolve().parents[2]
        print(replay_summary_json(root / "samples"))
        return

    if args.command == "analyst-report":
        root = Path(__file__).resolve().parents[2]
        print(replay_analyst_report_json(root / "samples"))
        return

    if args.command == "manager-summary":
        root = Path(__file__).resolve().parents[2]
        print(replay_manager_summary_text(root / "samples"))


if __name__ == "__main__":
    main()
