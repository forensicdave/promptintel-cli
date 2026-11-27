"""Build a deterministic, source-only executable; never archive the workspace."""

import argparse
import io
import os
from pathlib import Path
import tempfile
import zipapp
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = '''import sys

if sys.version_info < (3, 10):
    sys.exit("promptintel-cli requires Python 3.10 or newer; run it with a supported python3")

from promptintel_cli.cli import main

raise SystemExit(main())
'''


def build_zipapp(destination, *, source_root=ROOT):
    destination = Path(destination)
    source_root = Path(source_root).resolve()
    package = source_root / "promptintel_cli"
    members = {"__main__.py": BOOTSTRAP.encode("utf-8"), "LICENSE": (source_root / "LICENSE").read_bytes()}
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(source_root)
        if "__pycache__" in relative.parts:
            continue
        candidate = source_root
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError("Do not package symlinked source files or directories")
        members[relative.as_posix()] = path.read_bytes()
    if "promptintel_cli/cli.py" not in members or "promptintel_cli/__init__.py" not in members:
        raise ValueError("Cannot find the PromptIntel package")

    # Fixed metadata and ordering produce identical bytes for unchanged sources.
    archive = io.BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
        for name, content in sorted(members.items()):
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = ZIP_DEFLATED
            bundle.writestr(entry, content)
    archive.seek(0)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
        zipapp.create_archive(archive, target=temporary, interpreter="/usr/bin/env python3")
        temporary.chmod(0o755)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "promptintel-cli")
    args = parser.parse_args()
    path = build_zipapp(args.output)
    print(f"Built {path} ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

