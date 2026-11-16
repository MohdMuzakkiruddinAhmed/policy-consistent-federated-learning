"""Build the Linux runtime from an allowlisted context; never send local data/keys."""

import argparse
import io
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def context_bytes(root=ROOT):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        hashes = {}
        candidates = [root / "pyproject.toml"]
        candidates += list((root / "src").rglob("*.py"))
        candidates += [root / "containers" / name for name in ("Dockerfile", "requirements-linux.lock", "entrypoint.py")]
        candidates += [root / "policies/rego" / name for name in ("pcfl.rego", "data.json", "api_authz.rego", "log_mask.rego")]
        for path in sorted(candidates):
            if path.is_symlink() or not path.is_file() or "__pycache__" in path.parts:
                raise ValueError("invalid_or_missing_allowlisted_build_input")
            name = path.relative_to(root).as_posix()
            content = path.read_bytes()
            info = archive.gettarinfo(str(path), arcname=name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
            hashes[name] = hashlib.sha256(content).hexdigest()
        content = json.dumps({"schema_version": "0.1.0", "files_sha256": hashes}, sort_keys=True).encode()
        info = tarfile.TarInfo("containers/build-source.json")
        info.size, info.mode = len(content), 0o444
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="pcfl-runtime:0.1.0")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*(?::[a-z0-9._-]+)?", args.tag):
        raise ValueError("invalid_local_image_tag")
    result = subprocess.run(["docker", "build", "--platform", "linux/amd64", "--file", "containers/Dockerfile",
                             "--tag", args.tag, "--progress", "plain", "-"], input=context_bytes(), check=False)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
