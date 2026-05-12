from pathlib import Path

import pytest

from sentinel_forge.ingest import detect_source_family, iter_sample_paths, load_json


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_iter_sample_paths_discovers_expected_files() -> None:
    paths = iter_sample_paths(SAMPLES)
    assert len(paths) == 6
    assert any(path.name == "root_console_login.json" for path in paths)
    assert any(path.name == "credential_access_finding.json" for path in paths)


@pytest.mark.parametrize(
    ("relative_path", "expected_family"),
    [
        ("cloudtrail/root_console_login.json", "cloudtrail"),
        ("cloudtrail/assume_role_privileged.json", "cloudtrail"),
        ("cloudtrail/cloudtrail_stop_logging.json", "cloudtrail"),
        ("cloudtrail/security_group_open_ssh.json", "cloudtrail"),
        ("guardduty/credential_access_finding.json", "guardduty"),
        ("securityhub/iam_root_mfa_finding.json", "securityhub"),
    ],
)
def test_detect_source_family(relative_path: str, expected_family: str) -> None:
    payload = load_json(SAMPLES / relative_path)
    assert detect_source_family(payload) == expected_family
