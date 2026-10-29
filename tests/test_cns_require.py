"""ENFORCER_REQUIRE_CNS=1 turns a missing cns into a failure; unset, the CNS tests skip.

Each case imports tests/test_cns_integration.py in a fresh interpreter in which
``cns`` is blocked outright (``sys.modules['cns'] = None`` makes any import of it
fail), so the result does not depend on what the test environment contains.
These tests never skip and need no CNS.
"""
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCK = "import sys; sys.modules['cns'] = None; sys.modules['cns.gate'] = None\n"
RUN_MODULE = """
import unittest
import test_cns_integration as m
suite = unittest.defaultTestLoader.loadTestsFromModule(m)
result = unittest.TextTestRunner(stream=open({devnull!r}, "w")).run(suite)
print("ran", result.testsRun, "skipped", len(result.skipped), "failures", len(result.failures) + len(result.errors))
assert result.testsRun > 0 and result.testsRun == len(result.skipped)
"""


def run(code: str, *, require: bool) -> subprocess.CompletedProcess:
    env = {
        "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT / "tests")]),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if require:
        env["ENFORCER_REQUIRE_CNS"] = "1"
    return subprocess.run(
        [sys.executable, "-c", BLOCK + textwrap.dedent(code)],
        capture_output=True, text=True, env=env, timeout=120,
    )


class RequireCNSTests(unittest.TestCase):
    def test_import_fails_when_required_and_cns_is_missing(self) -> None:
        done = run("import test_cns_integration", require=True)
        self.assertNotEqual(done.returncode, 0, done.stdout)
        self.assertIn("ModuleNotFoundError", done.stderr)
        self.assertIn("cns.gate", done.stderr)

    def test_import_succeeds_and_every_test_skips_when_not_required(self) -> None:
        done = run(RUN_MODULE.format(devnull=os.devnull), require=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertRegex(done.stdout, r"ran (\d+) skipped \1 failures 0")

    def test_only_the_value_one_requires_cns(self) -> None:
        env_code = "import os; os.environ['ENFORCER_REQUIRE_CNS'] = '0'\n" + RUN_MODULE.format(devnull=os.devnull)
        done = run(env_code, require=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertRegex(done.stdout, r"ran (\d+) skipped \1 failures 0")


if __name__ == "__main__":
    unittest.main()
