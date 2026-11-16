# Contributing

Use CPython 3.12.10 and the hash-locked dependencies described in the
[reproduction guide](docs/REPRODUCIBILITY.md).

Verify the distribution before making changes:

```sh
python -B reproduce.py --verify-only
```

Set `PYTHONPATH=src` (`$env:PYTHONPATH = 'src'` in PowerShell), then run the
focused public tests:

```sh
python -B -m unittest discover -s tests -p test_oracle.py
python -B -m unittest discover -s tests -p test_state_model.py
```

Reproduce aggregate statistics and figures with:

```sh
python -m pip install --require-hashes -r requirements-analysis.lock
python -B reproduce.py --figures
```

The full historical test suite includes private configuration and original
repository checks that are outside this public distribution. Public checks do
not deploy infrastructure, retrain models, or replay private clinical data.

Preserve the frozen scientific source, inputs, released results, and their
provenance. Intentional research changes should use a separately versioned
artifact and document their effect on reproduction. Packaging changes require
updating the distribution manifest and checksum list. Keep third-party notices
and cite the artifact using [CITATION.cff](CITATION.cff).
