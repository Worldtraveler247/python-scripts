# day3/tests/test_secret_scanner.py
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from secret_scanner import scan_file, walk_directory
