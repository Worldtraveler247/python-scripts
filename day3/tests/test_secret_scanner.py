# day3/tests/test_secret_scanner.py
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from secret_scanner import scan_file, walk_directory


def test_scan_file_finds_aws_access_key(tmp_path: Path) -> None:
    f = tmp_path / "config.env"
    f.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f)
    assert len(findings) == 1
    category, path, line_num, line_text = findings[0]
    assert category == "AWS Access Key ID"
    assert line_num == 1


def test_scan_file_finds_password(tmp_path: Path) -> None:
    f = tmp_path / "config.py"
    f.write_text('password = "hunter2"\n')
    findings = scan_file(f)
    assert len(findings) == 1
    assert findings[0][0] == "Generic Password"


def test_scan_file_finds_private_key_header(tmp_path: Path) -> None:
    f = tmp_path / "key.txt"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n")
    findings = scan_file(f)
    assert len(findings) == 1
    assert findings[0][0] == "Private Key Header"


def test_scan_file_clean_file_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "clean.py"
    f.write_text("def hello():\n    return 'world'\n")
    assert scan_file(f) == []


def test_scan_file_one_finding_per_line(tmp_path: Path) -> None:
    # A line that matches multiple patterns produces only one finding
    f = tmp_path / "config.env"
    f.write_text('secret_password = "hunter2"\n')
    findings = scan_file(f)
    assert len(findings) == 1


def test_scan_file_permission_error_warns_and_returns_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    f = tmp_path / "secret.env"
    f.write_text("password=secret\n")
    # Unix only: chmod 000 blocks reads; this test will not work on Windows or as root
    f.chmod(0o000)
    findings = scan_file(f)
    assert findings == []
    captured = capsys.readouterr()
    assert "[WARN]" in captured.err
    f.chmod(0o644)  # restore so tmp_path cleanup works


def test_scan_file_finds_api_key(tmp_path: Path) -> None:
    f = tmp_path / "config.env"
    f.write_text('api_key = "sk-abc123xyz789"\n')
    findings = scan_file(f)
    assert len(findings) == 1
    assert findings[0][0] == "Generic API Key"


def test_scan_file_finds_token(tmp_path: Path) -> None:
    f = tmp_path / "config.env"
    f.write_text('token = "ghp_abc123xyz789"\n')
    findings = scan_file(f)
    assert len(findings) == 1
    assert findings[0][0] == "Generic Token/Secret"


def test_walk_directory_skips_skip_dirs(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("password=secret\n")
    normal = tmp_path / "app.py"
    normal.write_text("x = 1\n")
    paths = list(walk_directory(tmp_path))
    assert normal in paths
    assert (git_dir / "config") not in paths


def test_walk_directory_filters_to_scan_extensions(tmp_path: Path) -> None:
    py_file = tmp_path / "app.py"
    py_file.write_text("x = 1\n")
    pdf_file = tmp_path / "report.pdf"
    pdf_file.write_text("not scanned\n")
    paths = list(walk_directory(tmp_path))
    assert py_file in paths
    assert pdf_file not in paths


def test_walk_directory_skips_symlinks(tmp_path: Path) -> None:
    real = tmp_path / "real.py"
    real.write_text("x = 1\n")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    paths = list(walk_directory(tmp_path))
    assert real in paths
    assert link not in paths
