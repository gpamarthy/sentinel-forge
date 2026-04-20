# Sentinel Forge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Defensive AWS Cloud Detection & Response Lab**

Sentinel Forge is a high-fidelity detection engineering framework designed to ingest, normalize, and analyze AWS-native security telemetry. It transforms raw CloudTrail, GuardDuty, and Security Hub logs into actionable, evidence-rich findings, providing security analysts with structured timelines and clear triage guidance.

## ⚠️ Disclaimer

This tool is for educational and authorized security monitoring purposes only. The authors are not responsible for any misuse or for any security incidents that occur in environments where this tool is deployed.

## Features

- **Standardized Event Model**: Normalizes diverse AWS log sources into a unified schema for consistent analysis.
- **YAML-Based Detection Engine**: Decouples detection logic from code, allowing for rapid rule development and tuning.
- **Stateful Persistence**: Leverages an SQLite backend to track normalized events and findings across multiple runs.
- **Evidence-Rich Reporting**: Generates analyst incident reports with group-based timelines and manager-level summaries.
- **SIEM-Ready Logging**: Fully integrated with `structlog` for structured JSON output suitable for ingestion into modern SIEM platforms.
- **Containerized Execution**: Ready to run in any environment via the provided `Dockerfile`.

## Installation

```bash
# Clone the repository
git clone https://github.com/gpamarthy/sentinel-forge.git
cd sentinel-forge

# Install in editable mode with dev dependencies
pip install -e .[dev]
```

## Quick Start

```bash
# Replay findings from the current sample corpus
sentinel-forge replay-findings

# Generate a full analyst incident report
sentinel-forge analyst-report

# Generate a manager-level summary
sentinel-forge manager-summary
```

## Initial Detections

- **Root Account Usage**: Detection of root account activity within the control plane.
- **MFA Gaps**: Successful console logins occurring without multi-factor authentication.
- **Privileged Escalation**: Unusual `AssumeRole` calls into sensitive or administrative roles.
- **Tampering**: Identification of actions that disable or materially weaken CloudTrail logging.
- **GuardDuty Corroboration**: Automatic linking of GuardDuty findings with corroborating CloudTrail API activity.
- **Network Exposure**: Detection of security group changes exposing sensitive ports to `0.0.0.0/0`.

## Architecture

Sentinel Forge follows a robust defensive pipeline:
1. **Ingest**: Loads raw JSON telemetry and identifies the source family.
2. **Normalize**: Maps diverse payloads into a common, searchable event shape.
3. **Detect**: Evaluates a registry of YAML-based rules against the event stream.
4. **Report**: Synthesizes findings into structured timelines and executive summaries.

## Data Persistence

Sentinel Forge stores all processed events and findings in a local SQLite database at `sentinel_forge.db`.

## License

Distributed under the MIT License. See `LICENSE` for more information.
