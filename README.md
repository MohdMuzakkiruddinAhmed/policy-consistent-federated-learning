# Policy-Consistent Federated Learning

### Dynamic Governance and Auditable Aggregation

[![Research checks](https://github.com/MohdMuzakkiruddinAhmed/policy-consistent-federated-learning/actions/workflows/research-checks.yml/badge.svg)](https://github.com/MohdMuzakkiruddinAhmed/policy-consistent-federated-learning/actions/workflows/research-checks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12.10](https://img.shields.io/badge/Python-3.12.10-3776AB.svg)](.python-version)

Research code and aggregate results accompanying the [three-page poster paper](paper/pcfl-poster.pdf).

The paper PDF is the supplied final version with the GitHub repository link, updated on November 16, 2026. The bundled LaTeX source and expanded manuscript are earlier source snapshots and may differ from this PDF.

[Poster paper](paper/pcfl-poster.pdf) · [Reproduction guide](docs/REPRODUCIBILITY.md) · [Results](docs/RESULTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Citation](CITATION.cff)

**Authors:** Muzakkiruddin Ahmed Mohammed, Sana Afsheen Shaik, Alyson Michele Chapman, Abdelrahman Elfikky, and John Talburt.

Mohammed, Elfikky, and Talburt: Center for Advanced Research in Entity Resolution and Information Quality (ERIQ), University of Arkansas at Little Rock. Shaik and Chapman: Bentonville West High School.

## Overview

The protocol evaluates whether an organization remained authorized throughout an update's task-to-publication lifecycle. Inclusive policy histories detect interruptions, including revoke-regrant cycles. A guarded transaction publishes a verified, versioned model candidate only when the authority, membership and parent-model state still match the checked snapshot.

This paper-oriented artifact reorganizes the completed main-v9-final study. It preserves the 270 frozen executable files and included scientific inputs; the package README, documentation and reproduction helper are new. It is a derivative distribution with its own manifest; the original native release bundle is preserved separately.

This GitHub distribution adds repository metadata, an MIT license, contribution guidance and automated public reproduction checks. The frozen research source and scientific records remain byte-for-byte preserved. See the [publication review](verification/publication-review.json) for the checks performed on the supplied ZIP.

## Package contents

| Location | Contents |
| --- | --- |
| paper/ | Named poster PDF, editable LaTeX, IEEEtran class, build script and expanded manuscript |
| src/pcfl/ | Policy, protocol, learning, analysis and verification implementation |
| scripts/, tests/ | Original research utilities and test suite |
| policies/, schemas/ | Rego policies, synthetic traces and evidence contracts |
| containers/, infra/ | Original container and Terraform source |
| configs/, data_manifests/ | Public experiment settings and aggregate dataset metadata |
| results/inputs/ | Frozen machine-readable registration and aggregate attempt records |
| results/tables/ | Released statistics and supplementary tables |
| results/paper_tables/ | Tables I and II exported directly from the released aggregate CSVs |
| results/figures/ | Seven figures in PNG, SVG and PDF |
| results/supplements/, results/evidence/ | Per-attempt aggregate supplements and claim/evidence mappings |
| docs/ | Reproduction, results, data and architecture guides |
| artifact_manifest.json | Package integrity and scientific provenance bindings |
| reproduce.py | Verify the package and regenerate aggregate analysis |
| verification/validation.json | Recorded package reproduction and focused-test checks |

## Quick start

Use CPython 3.12.10. Verification alone needs only the Python standard library:

    git clone https://github.com/MohdMuzakkiruddinAhmed/policy-consistent-federated-learning.git
    cd policy-consistent-federated-learning
    python -B reproduce.py --verify-only

For aggregate analysis, create an environment and install the hash-locked dependencies:

    python -m venv .venv

Activate the environment with the command for your shell:

| Shell | Activation command |
| --- | --- |
| Linux/macOS | `. .venv/bin/activate` |
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |

Then install and reproduce:

    python -m pip install --require-hashes -r requirements-analysis.lock
    python -B reproduce.py

To regenerate the seven figures as well:

    python -B reproduce.py --figures

Generated files go to runs/reproduction/ by default. The included results remain unchanged. No AWS credentials, clinical rows or model arrays are needed. See [reproduction details](docs/REPRODUCIBILITY.md) for comparison modes and execution scope.

## Findings

| Endpoint | Observed result and interpretation |
| --- | --- |
| H1: invalid incorporation | P1 incorporated 0/20 oracle-invalid presented primary updates; supported within the fixed benchmark |
| H2: paired governance contrasts | P1-minus-B2 and P1-minus-B3 mean rate differences -1, with unadjusted 95% intervals [-1, -1] |
| H3: audit/manipulation evidence | Inconclusive: runtime manipulation 0/0 is undefined and targeted success coverage is 40/50 |
| H4: stable-policy utility | Paired AUROC differences and one-sided lower bounds were 0, exceeding the -0.02 benchmark margin |
| Runtime | Ratios of mean P1/B3 round times: 1.03344 IID and 1.18485 non-IID |

Five paired training seeds share one historical cohort and client setup; cells and updates are not independent populations. Different methods have different presentation opportunities. Zero observed invalid incorporation does not establish zero population risk. All 40 ablations have partial component verification; 20 non-IID ablations additionally lack complete five-round evidence. The ten targeted failures remain included. See [results and qualifications](docs/RESULTS.md).

The paper's two result tables are provided as [governance CSV](results/paper_tables/table_1_governance.csv) and [runtime CSV](results/paper_tables/table_2_runtime.csv), with full precision retained where the paper rounds display values.

## Reproduction and reuse scope

The entry point checks packaged hashes and recomputes the 13 aggregate statistical outputs. Linux byte comparison and Windows text-newline comparison are reported separately. Figure exports are not promised to be byte-identical across environments. Public aggregate reproduction does not retrain models or repeat private model/audit replay.

The original full test suite includes historical repository and private-configuration checks. Consequently, scripts/validate.py is not the minimal public-package quick start. Container and infrastructure code is supplied for inspection; aggregate reproduction performs no deployment.

Package validation reproduced all 13 original statistical files byte-for-byte on Linux, checked the explicitly reported Windows newline comparison, generated seven figures and passed 35 focused synthetic oracle/state-model tests. Full-suite validation and private-data replay are separate scopes. See [the validation record](verification/validation.json).

Clinical records, trained arrays, signing keys, credentials, Terraform state and internal working notes are excluded. AWS identifiers appearing in retained source or provenance are metadata, not access credentials. Planning and theory Markdown documents are excluded at every archive depth.

Use [CITATION.cff](CITATION.cff) for artifact attribution. The paper's conference year and poster-specific submission instructions remain unconfirmed; no publication or acceptance status is asserted. See [data attribution](docs/DATA.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

## License and contributions

Project-authored code and accompanying documentation are distributed under the [MIT License](LICENSE). Third-party material, including IEEEtran and the underlying dataset, retains its original terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The MIT license does not replace those terms.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the public checks and guidance on preserving the research artifact.
