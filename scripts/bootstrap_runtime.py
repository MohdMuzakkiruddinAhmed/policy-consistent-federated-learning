"""Install the optional hash-locked CPU runtime in a short user-local path."""

import argparse
import os
from pathlib import Path
import platform
import subprocess
import venv

ROOT = Path(__file__).resolve().parents[1]


def runtime_python():
    return Path.home() / ".pcfl/flwr127" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check without installing")
    args = parser.parse_args()
    if platform.python_version() != "3.12.10":
        raise RuntimeError("Use CPython 3.12.10 to reproduce this runtime")
    executable = runtime_python()
    lock = ROOT / ("requirements-runtime.lock" if os.name == "nt" else "containers/requirements-linux.lock")
    if not args.check:
        if not executable.is_file():
            venv.EnvBuilder(with_pip=True).create(executable.parent.parent)
        subprocess.run([str(executable), "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
                        "-r", str(lock)], check=True)
    if not executable.is_file():
        raise RuntimeError("Runtime is not installed; run without --check")
    subprocess.run([str(executable), "-m", "pip", "check"], check=True)
    probe = "import importlib.metadata as m,json; print(json.dumps({n:m.version(n) for n in ['flwr','torch','numpy','scikit-learn','SQLAlchemy']}))"
    subprocess.run([str(executable), "-c", probe], check=True)
    print(f"Runtime Python: {executable}")


if __name__ == "__main__":
    main()
