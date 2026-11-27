"""Write a SHA256SUMS manifest for release artifacts, on macOS or Linux."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def write_checksums(directory):
    directory = Path(directory)
    artifacts = sorted(path for path in directory.iterdir() if path.is_file() and (
        path.name == "promptintel-cli" or path.suffix == ".whl" or path.name.endswith(".tar.gz")
    ))
    if not artifacts:
        raise ValueError("No release artifacts found; run make build first")
    lines = []
    for path in artifacts:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  {path.name}\n")
    manifest = directory / "SHA256SUMS"
    manifest.write_text("".join(lines), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(f"Wrote {write_checksums(ROOT / 'dist')}")

