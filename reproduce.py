#!/usr/bin/env python3
"""Verify this paper artifact and reproduce its public aggregate statistics.

No training, clinical rows, private models, credentials or cloud services are
used. This wrapper belongs to the reorganized paper artifact; it is not the
original native release verifier.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
SHA256 = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_bytes(body):
    return hashlib.sha256(body).hexdigest()


def digest_json(value):
    return digest_bytes(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8"))


def member_name(value):
    require(
        isinstance(value, str) and value and "\\" not in value and ":" not in value
        and not value.startswith("/") and str(PurePosixPath(value)) == value
        and all(part not in {"", ".", ".."} for part in value.split("/")),
        "Unsafe artifact member name.",
    )
    name = PurePosixPath(value)
    require(
        not (name.suffix.lower() == ".md"
             and re.match(r"^(?:plan|theor)", name.stem, flags=re.I)),
        "Planning or theory Markdown is excluded from this artifact: " + value,
    )
    require(name.parts[0] != "runs", "Generated output cannot be an immutable artifact member.")
    return value


def reject_links(path, boundary):
    for current in (path, *path.parents):
        if current.exists() or current.is_symlink():
            require(
                not current.is_symlink()
                and not (hasattr(current, "is_junction") and current.is_junction()),
                "Linked artifact or output path is not allowed: " + str(current),
            )
        if current == boundary:
            break


def content(name):
    path = ROOT / member_name(name)
    reject_links(path, ROOT)
    require(path.resolve().is_relative_to(ROOT), "Artifact member escapes its root.")
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode),
            "Missing or nonregular artifact member: " + name)
    return path.read_bytes()


def check_hash_map(value, label):
    require(isinstance(value, dict) and value, label + " must be a nonempty hash map.")
    seen = set()
    for name, expected in value.items():
        member_name(name)
        require(name.casefold() not in seen, "Case-colliding artifact member: " + name)
        seen.add(name.casefold())
        require(isinstance(expected, str) and SHA256.fullmatch(expected),
                "Invalid SHA-256 for " + name)


def verify_artifact():
    manifest = json.loads(content("artifact_manifest.json"))
    require(manifest.get("kind") == "pcfl-poster-research-artifact",
            "This is not a PCFL poster research artifact manifest.")
    require(str(manifest.get("schema_version")) == "1.0", "Unsupported manifest schema.")
    files = manifest.get("files_sha256")
    check_hash_map(files, "files_sha256")
    require("artifact_manifest.json" not in files, "Manifest must not hash itself.")
    for name, expected in files.items():
        require(digest_bytes(content(name)) == expected, "Artifact hash mismatch: " + name)

    frozen = manifest.get("frozen_executable_files_sha256")
    check_hash_map(frozen, "frozen_executable_files_sha256")
    require(len(frozen) == 270, "Expected the 270-file frozen executable inventory.")
    for name, expected in frozen.items():
        require(files.get(name) == expected,
                "Frozen source is not preserved and bound: " + name)

    scientific = manifest.get("scientific_inputs")
    require(isinstance(scientific, dict), "Missing scientific input bindings.")
    for field in ("registration", "attempts"):
        name = member_name(scientific.get(field))
        require(name in files, "Scientific input is not hash-bound: " + field)
    registration_body = content(scientific["registration"])
    attempts_body = content(scientific["attempts"])
    plan = json.loads(registration_body)
    attempts = json.loads(attempts_body)
    require(isinstance(attempts, list), "Aggregate attempts must be a JSON list.")
    require(plan.get("plan_digest") == scientific.get("plan_digest"),
            "Frozen registration digest binding differs.")
    require(digest_json(attempts) == scientific.get("attempts_digest"),
            "Aggregate attempts digest binding differs.")
    require(plan.get("provenance", {}).get("source_files_sha256") == frozen,
            "Registration and executable inventory differ.")

    outputs = manifest.get("analysis_outputs_sha256")
    check_hash_map(outputs, "analysis_outputs_sha256")
    require(len(outputs) == 13 and "analysis.json" in outputs,
            "Expected all 13 registered statistical outputs.")
    for name, expected in outputs.items():
        require("/" not in name, "Statistical output names must be basenames.")
        require(files.get("results/tables/" + name) == expected,
                "Original statistical output is not bound: " + name)
    summary = {
        "kind": "paper-artifact-public-aggregate-reproduction",
        "successful": True,
        "artifact_version": manifest.get("artifact_version"),
        "payload_files_verified": len(files),
        "frozen_executable_files_verified": len(frozen),
        "registration_sha256": digest_bytes(registration_body),
        "aggregate_attempts_sha256": digest_bytes(attempts_body),
        "plan_digest": scientific["plan_digest"],
        "attempts_digest": scientific["attempts_digest"],
        "scope": "public-source-and-aggregate-statistics-only",
        "private_model_audit_replayed": False,
        "fresh_training_performed": False,
        "cloud_access_performed": False,
    }
    return manifest, plan, attempts, summary


def output_directory(value):
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    reject_links(candidate, ROOT)
    resolved = candidate.resolve()
    runs = ROOT / "runs"
    require(resolved.is_relative_to(runs) and resolved != runs,
            "--output must be a subdirectory of this artifact's runs/ directory.")
    require(not resolved.exists() or resolved.is_dir(), "Output exists and is not a directory.")
    return resolved


def preserve_or_write(destination, body):
    reject_links(destination, ROOT)
    if destination.exists():
        require(destination.is_file() and destination.read_bytes() == body,
                "Existing generated file differs; use a new --output directory: " + str(destination))
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(body)


def reproduce(manifest, plan, attempts, destination, figures):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    try:
        import numpy
        from pcfl.analysis import analyze_registry, write_analysis
    except ImportError as error:
        raise ValueError("Install the hash-locked analysis dependencies first; see README.md.") from error
    require(numpy.__version__ == "2.4.3", "Use the pinned NumPy 2.4.3 analysis environment.")
    report = analyze_registry(plan, attempts)
    expected_outputs = manifest["analysis_outputs_sha256"]
    byte_exact = True
    newline_canonicalized = []
    generated_hashes = {}
    with tempfile.TemporaryDirectory(prefix="pcfl-paper-reproduction-") as temporary:
        generated = Path(temporary)
        write_analysis(report, generated)
        actual = {path.relative_to(generated).as_posix()
                  for path in generated.rglob("*") if path.is_file()}
        require(actual == set(expected_outputs), "Regenerated statistical output set differs.")
        for name in sorted(expected_outputs):
            body = (generated / name).read_bytes()
            original = content("results/tables/" + name)
            if body != original:
                require(os.name == "nt"
                        and body.replace(b"\r\n", b"\n") == original.replace(b"\r\n", b"\n"),
                        "Statistical output differs beyond permitted Windows text newlines: " + name)
                byte_exact = False
                newline_canonicalized.append(name)
            generated_hashes[name] = digest_bytes(body)
        # Verify all outputs before writing any of them to the requested run.
        for name in sorted(expected_outputs):
            preserve_or_write(destination / name, (generated / name).read_bytes())

        figure_count = 0
        if figures:
            try:
                import matplotlib
                matplotlib.use("Agg")
                matplotlib.rcParams["pdf.compression"] = 0
                plotting = runpy.run_path(str(ROOT / "scripts/plot_research.py"))
                figure_manifest = plotting["make_figures"](
                    plan, attempts, generated / "figures", analysis=report
                )
            except ImportError as error:
                raise ValueError("Figure generation requires the pinned Matplotlib dependencies.") from error
            require(len(figure_manifest["files"]) == 21,
                    "Expected seven figures in PNG, SVG and PDF formats.")
            for path in sorted((generated / "figures").iterdir()):
                require(path.is_file(), "Unexpected generated figure entry.")
                preserve_or_write(destination / "figures" / path.name, path.read_bytes())
            figure_count = 7
    return {
        "analysis_files_verified": len(expected_outputs),
        "byte_exact": byte_exact,
        "comparison_mode": "exact-bytes" if byte_exact else "windows-crlf-lf-canonical-text",
        "newline_canonicalized_files": newline_canonicalized,
        "numeric_tolerance_used": False,
        "generated_analysis_sha256": generated_hashes,
        "figures_generated": figure_count,
        "figure_byte_identity_claimed": False,
        "output": destination.relative_to(ROOT).as_posix(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true",
                        help="Verify artifact and input integrity without importing NumPy.")
    parser.add_argument("--output", default="runs/reproduction",
                        help="Generated output subdirectory under this artifact's runs/.")
    parser.add_argument("--figures", action="store_true",
                        help="Also regenerate seven descriptive figures (21 image files).")
    args = parser.parse_args()
    require(not (args.verify_only and args.figures), "--figures cannot be combined with --verify-only.")
    manifest, plan, attempts, summary = verify_artifact()
    summary["verification_only"] = args.verify_only
    if not args.verify_only:
        summary.update(reproduce(manifest, plan, attempts, output_directory(args.output), args.figures))
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("Artifact reproduction failed: " + str(error), file=sys.stderr)
        sys.exit(1)
