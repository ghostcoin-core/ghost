"""Runs benchmarks/tests/test_header_sample_bound.py from the repository root.

The tests of the written sampling bound sit beside the other scale tests in
benchmarks/tests; this module loads them under a name of their own, so that
`python3 -m unittest tests.test_header_sample_bound` finds them from here.
"""

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "benchmarks" / "tests" / "test_header_sample_bound.py"
_SPEC = importlib.util.spec_from_file_location("benchmarks_test_header_sample_bound", _PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromModule(_MODULE)
