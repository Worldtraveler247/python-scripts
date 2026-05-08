# day3/secret_scanner.py
import re
import sys
from collections.abc import Iterator
from pathlib import Path

PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(
        r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?(?:[A-Za-z0-9/+=]{40})['\"]?"
    ),
    "Generic Password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S{8,})"
    ),
    "Generic API Key": re.compile(
        r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?(\S{8,})"
    ),
    "Generic Token/Secret": re.compile(
        r"(?i)(token|secret|auth)\s*[=:]\s*['\"]?(\S{8,})"
    ),
    "Private Key Header": re.compile(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
}

SKIP_DIRS: set[str] = {
    ".git", "venv", ".venv", "node_modules",
    "__pycache__", ".tox", "dist", "build",
}

SCAN_EXTENSIONS: set[str] = {
    ".py", ".js", ".env", ".yaml", ".yml",
    ".json", ".tf", ".sh", ".toml", ".cfg", ".ini",
}

Finding = tuple[str, Path, int, str]


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for category, pattern in PATTERNS.items():
                    if pattern.search(line):
                        findings.append((category, path, line_num, line.rstrip()))
                        break  # one finding per line max
    except PermissionError:
        print(f"[WARN] Cannot read {path}", file=sys.stderr)
    return findings


def walk_directory(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            p = dirpath / filename
            if p.suffix in SCAN_EXTENSIONS and not p.is_symlink():
                yield p


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
