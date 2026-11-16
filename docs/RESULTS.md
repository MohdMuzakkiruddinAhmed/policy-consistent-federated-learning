# Results and interpretation

The primary benchmark crosses four methods, two partition conditions, S0-S3 and five training seeds: 160 cells. The seeds are 296, 593, 887, 1181 and 1483. IID and non-IID conditions use the same underlying patient cohort.

## Primary governance results

| Method | Invalid incorporated/presented | Valid rejected/presented |
| --- | ---: | ---: |
| B1: policy ignored | 140/140 | 0/1460 |
| B2: initial admission cached | 140/140 | 0/1460 |
| B3: dispatch authorization cached | 20/20 | 0/1460 |
| P1: lifecycle history and guarded commit | 0/20 | 0/1460 |

Presentation opportunities differ. These ratios are conditional counts, not equal-exposure causal effects. A zero-opportunity ratio is undefined.

H1 was supported in this suite. With no violating clusters among five conditional training seeds, the one-sided 95% upper bound for a violating seed cluster is 45.07%; this is not an update-level risk bound. H2 pools S1-S3 and both distributions within each seed. Both registered P1-minus-comparator differences were -1 with unadjusted 95% bootstrap intervals [-1, -1]. Degenerate intervals reflect the observed finite sample.

## Utility and runtime

H4 uses only primary stable S0 P1/B3 pairs: five pairs per distribution. Every paired AUROC difference was 0; one-sided 95% lower bounds of 0 exceed the prespecified -0.02 margin. This supports benchmark noninferiority, not population equivalence or clinical noninferiority.

Ratios of mean round times, P1/B3, were 1.033442 under IID and 1.184846 under non-IID. Mean paired differences were 1.612 and 10.093 seconds, respectively. The observations do not support a negligible-overhead claim.

## Coverage and qualifications

The 258 canonical obligations comprise 160 primary, 50 targeted, 40 ablation and eight fresh-replication cells. The original analysis records 248 successful statuses and ten targeted failures. Successful status is distinct from complete protocol verification.

All 40 ablations have component-specific partial verification; the 20 non-IID ablations additionally lack complete five-round evidence. Replacing history with current-state authorization admitted 5/5 invalid updates per distribution. Other zero-violation ablations do not establish that omitted guards are universally unnecessary.

H3 remains inconclusive despite 3304/3304 audited final decisions and 94/94 verified record sets: runtime manipulation detection is undefined (0/0) and targeted successful coverage is 40/50. Six detected manipulations of copied evidence are a separate post-run exercise.

Eight replicas used one new deployment, two disjoint client fleets and an existing seed. Twenty-one exploratory cases remain single-seed, validation-only descriptions. Neither adds independent primary seeds or stable S0 utility pairs.

The expanded manuscript records interim metric exposures without retuning or favorable replacement, partial evidence and prior-work access limits. Trust in authority, enforcement, storage and protected anchors remains assumed. No clinical effectiveness, poisoning resilience, differential privacy, secure aggregation, unlearning, general legal compliance or remote attestation is established.
