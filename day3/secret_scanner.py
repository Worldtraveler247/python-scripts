# day3/secret_scanner.py
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

PATTERNS: dict[str, re.Pattern] = {}

SKIP_DIRS: set[str] = set()

SCAN_EXTENSIONS: set[str] = set()

Finding = tuple[str, Path, int, str]


def scan_file(path: Path) -> list[Finding]:
    raise NotImplementedError


def walk_directory(root: Path) -> Iterator[Path]:
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
