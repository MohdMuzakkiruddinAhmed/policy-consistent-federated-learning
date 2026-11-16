# Reproducing the public aggregate results

## Environment and integrity

Use CPython 3.12.10 and the included requirements-analysis.lock. Install with pip's --require-hashes option in a clean environment. NumPy 2.4.3 and Matplotlib 3.10.8 are among the pinned analysis dependencies.

Run from the extracted package root:

    python -B reproduce.py --verify-only
    python -B reproduce.py
    python -B reproduce.py --figures

The first command verifies the package without importing numerical dependencies. The default analysis path consumes results/inputs/experiment_registration.json and results/inputs/aggregate_attempts.json, invokes the unchanged analysis implementation, and checks all 13 regenerated statistical outputs against results/tables/. The optional figure step invokes the original plotting implementation to produce seven figures in three formats.

Results are written beneath runs/reproduction/ by default. Treat the released inputs and results as immutable. The helper refuses output destinations that would replace packaged payload files. Its JSON result distinguishes integrity checking, statistical comparisons and figure generation.

## Comparison policy

The original final statistical release was generated and reproduced under Linux. The frozen analysis writer uses platform-default text newline handling for analysis.json. Windows can therefore produce CRLF where the release contains LF.

This derivative helper reports byte-exact comparison separately from a Windows-only text-newline canonical comparison. A successful newline comparison does not claim original byte identity. It does not round numbers, relax numeric tolerances or modify the released files. Figure bytes can vary with rendering libraries and export metadata; regenerated plots are separate outputs.

## Included and excluded evidence

The scientific registration and aggregate attempts retain the original study bindings. The files_sha256 inventory in artifact_manifest.json covers the reorganized payload; the frozen executable inventory identifies preserved research code. The new wrapper is package tooling and is not part of the original frozen executable inventory.

No original source or native-release ZIP is nested here: those archives include documents excluded from this paper-oriented distribution. This package therefore has its own integrity manifest and does not claim to be the unchanged original native release.

Aggregate reproduction requires neither clinical rows nor trained models. It does not repeat full-cohort metric computation, protected audit/model replay, cloud execution or training. Those completed checks have separate evidence scopes, described in the expanded manuscript.

## Original utilities and tests

The original scripts and tests are retained for inspection and further development. Some require optional runtime dependencies, local services, retained historical records or private operator configuration. The complete historical validation command is not promised to pass in a public-only package.

The focused public suites passed 35 tests (13 independent-oracle and 22 local state-model tests). From the artifact root, use:

    # Linux/macOS
    PYTHONPATH=src python -B -m unittest discover -s tests -p test_oracle.py
    PYTHONPATH=src python -B -m unittest discover -s tests -p test_state_model.py

In PowerShell set `$env:PYTHONPATH = "src"` first, then run the two python commands without the `PYTHONPATH=src` prefix. These suites use synthetic fixtures and an in-memory model; they do not deploy resources or train a clinical model.

In particular, scripts/analyze_experiments.py expects a hash-chained attempt ledger, whereas the public aggregate input is a JSON list. Use the new root reproduce.py for the supplied inputs. Infrastructure scripts are not invoked by reproduction.

The current paper/pcfl-poster.pdf is the supplied final PDF with the GitHub repository link, updated on November 16, 2026. The bundled LaTeX source and expanded manuscript are earlier snapshots; they are not claimed to reproduce this replacement PDF. To build the bundled LaTeX source, run build.ps1 in a separate copy of paper/ on a machine with pdfLaTeX and the listed TeX packages, or upload its LaTeX source and IEEEtran.cls to Overleaf. The build writes pcfl-poster.pdf, so keep it separate from the supplied final PDF. Recheck the three-page limit after edits.
