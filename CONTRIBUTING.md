# Contributing

Thanks for considering a contribution.

## Useful contributions

1. **New detection rules** under `rules/` (YAML). Each rule needs a sample finding in `samples/` that fires it and a test that asserts on the fire.
2. **New finding sources** beyond CloudTrail / GuardDuty / SecurityHub (AWS Config, Inspector, Macie). Add a normalizer in `src/sentinel_forge/normalize.py`.
3. **Playbook entries** for incident classes the tool doesn't cover yet. Each playbook ships in `playbooks/` and is referenced from a rule.
4. **Report templates** for the analyst / manager output. Templates live in `src/sentinel_forge/templates/`.

## Dev setup

```sh
git clone https://github.com/gpamarthy/sentinel-forge
cd sentinel-forge
make install
make test     # 28 tests
make lint     # ruff
```

## Code style

- Python 3.11+. `ruff check src/ tests/` must pass.
- Four-space indent. Type-annotate public functions.
- No emojis. Plain prose in commits, comments, and PR descriptions.
- Conventional commits: `feat(rules):`, `fix(normalize):`, `chore:`, `docs:`, `ci:`.

## Adding a rule

A rule lives in `rules/` and:

1. Has a unique `id` and a one-line `description`.
2. Has at least one positive sample under `samples/` that fires it.
3. Has a test in `tests/` exercising both fire and no-fire cases.
4. Adds an entry to `CHANGELOG.md` under `[Unreleased]`.
