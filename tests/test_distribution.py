import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

from promptintel_cli import __version__
from promptintel_cli.endpoints import ENDPOINTS
from scripts.build_zipapp import BOOTSTRAP, ROOT, build_zipapp
from scripts.checksums import write_checksums


class DistributionTests(unittest.TestCase):
    def test_portable_file_runs_in_isolation_without_installing_the_package(self):
        with tempfile.TemporaryDirectory() as directory:
            target = build_zipapp(Path(directory) / "promptintel-cli")
            for arguments in (["--version"], ["endpoints", "--format", "json"]):
                with self.subTest(arguments=arguments):
                    # -I ignores PYTHONPATH and user site packages. -S disables
                    # site initialization, so editable installs cannot mask faults.
                    result = subprocess.run([sys.executable, "-I", "-S", str(target), *arguments],
                                            cwd=directory, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if arguments == ["--version"]:
                        self.assertEqual(result.stdout.strip(), f"promptintel-cli {__version__}")
                    else:
                        self.assertEqual(len(json.loads(result.stdout)["endpoints"]), len(ENDPOINTS) + 1)
            self.assertTrue(os.access(target, os.X_OK))
            self.assertTrue(target.read_bytes().startswith(b"#!/usr/bin/env python3\n"))

    def test_archive_contains_only_package_sources_and_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            target = build_zipapp(Path(directory) / "promptintel-cli")
            expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / "promptintel_cli").rglob("*.py")}
            with ZipFile(target) as archive:
                self.assertEqual(set(archive.namelist()), expected | {"__main__.py", "LICENSE"})
                self.assertEqual(archive.read("__main__.py").decode(), BOOTSTRAP)
                self.assertEqual(archive.read("LICENSE"), (ROOT / "LICENSE").read_bytes())

    def test_unchanged_sources_produce_identical_artifacts_and_valid_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            first = build_zipapp(directory / "promptintel-cli")
            second = build_zipapp(directory / "second-copy")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            manifest = write_checksums(directory)
            self.assertEqual(manifest.read_text(), f"{hashlib.sha256(first.read_bytes()).hexdigest()}  promptintel-cli\n")

    def test_bootstrap_reports_unsupported_python_before_importing_package(self):
        # Verify the pre-import guard without needing an obsolete interpreter.
        code = "import sys\nsys.version_info = (3, 9, 0)\n" + BOOTSTRAP
        result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires Python 3.10", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
