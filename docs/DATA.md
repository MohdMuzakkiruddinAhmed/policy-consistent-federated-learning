# Dataset and public inputs

The benchmark uses **Diabetes 130-US Hospitals for Years 1999-2008**, UCI dataset 296:

J. Clore, K. Cios, J. DeShazo, and B. Strack, UCI Machine Learning Repository, 2014. DOI: [10.24432/C5230J](https://doi.org/10.24432/C5230J).

The [official dataset record](https://archive.ics.uci.edu/dataset/296/diabetes+130-us+hospitals+for+years+1999-2008) provides source access and CC BY 4.0 attribution information. The dataset itself is not bundled.

The study contains 101,766 encounters from 71,518 patient groups. Patient-grouped train/validation/test splits contain 71,160/15,324/15,282 encounters. The binary outcome is readmission within 30 days. Training-only preprocessing produces 194 encoded features.

Eight fictional clients use balanced IID or label-stratified Dirichlet allocation with concentration 0.5, keeping patient groups intact. These clients are not inferred real hospital memberships. This historical split is not chronological external or clinical validation.

data_manifests/dataset.json contains aggregate preparation statistics, feature contracts, source attribution and hashes. results/inputs/ contains the frozen machine-readable experiment registration and aggregate attempts. Per-attempt supplements describe experimental outcomes, not patient-level records.

Raw clinical rows, patient membership files, processed client tables, trained arrays and checkpoints are excluded. The original data-preparation code is retained, but aggregate reproduction does not download or prepare the clinical dataset.
