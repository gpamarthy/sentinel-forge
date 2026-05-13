# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-13

First public release. AWS detection lab and playbook engine.

### Added
- Multi-source finding normalizer covering CloudTrail, GuardDuty, and SecurityHub
- YAML-defined detection rules with field-equality, contains, and regex predicates
- CLI subcommands: `status`, `replay-findings`, `incident-summary`, `analyst-report`, `manager-summary`
- Analyst report renders structured incident write-ups; manager summary rolls them up
- Playbook-driven incident summaries with recommended response steps
- Sample corpus under `samples/` with 6 normalized findings exercising 6 rules
- 28 unit tests across Python 3.11, 3.12
- CI: ruff lint, mypy typecheck, pytest, pip-audit security
