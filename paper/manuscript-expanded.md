# Policy-Consistent Federated Learning: Dynamic Data Governance and Auditable Model Aggregation

**Research manuscript: main-v9-final.** The registered analysis and protected final-response replay are complete, and all six AWS deployments are closed. The machine-readable phase and release records provide their separate completion and reproduction statuses; this manuscript preserves the scientific qualifications below.

## Abstract

Federated learning separates local data processing from model aggregation, but an authorization established at dispatch may become invalid before an update contributes to a published model. This study evaluates inclusive authorization histories and a guarded model-publication boundary in an eight-client, single-region artifact. Policy evaluation, transactional authority state, immutable object versions and independently protected evidence support replay of authorization, audit and sample-weighted aggregation. A prospectively fixed comparison crosses four enforcement methods, two partition conditions, four primary scenarios and five seeds, with separate targeted, ablation, sensitivity and fresh-deployment components. All 258 registered canonical obligations were attempted: 248 received native successful status and 10 targeted attempts failed. P1 incorporated zero of 20 oracle-invalid presented primary updates. Both registered paired invalid-incorporation contrasts were -1 with two-sided 95 percent bootstrap intervals [-1, -1]. Stable primary S0 P1-minus-B3 AUROC differences were 0 under both partition conditions, with one-sided 95 percent lower bounds 0 above the -0.02 margin. The unchanged project analysis classified H1, H2 and H4 as supported within this frozen benchmark; H3 remained inconclusive because the manipulation denominator was zero and targeted success coverage was incomplete. All 40 ablations use component-specific partial-protocol verification; the 20 non-IID executions additionally lack complete five-round evidence. Twenty-one separate exploratory cases remain single-seed, validation-only descriptions, and eight fresh replicas used one new deployment with two four-case applications. Independent protected replay verified both original runtime images, and full-cohort recomputation of all 269 originally reported final utility outputs passed the fixed numeric comparison policy. The contribution is an incremental protocol and deployment evaluation under explicit trust assumptions. A close policy-driven FL paper remains available only as an abstract, and no firstness or clinical-effectiveness claim follows.

## 1. Introduction

Federated learning permits iterative model training using locally computed updates rather than a pooled training table. The original FedAvg formulation provides a common learning rule for this study; it does not by itself define when an organization's contribution remains authorized for a changing collaboration purpose. [McMahan et al., Communication-Efficient Learning of Deep Networks from Decentralized Data](https://arxiv.org/html/1602.05629v4).

The problem considered here is a temporal authorization gap. A client may receive an authorized task, train while a policy changes, and return an update after its original permission has been revoked. Rechecking only the current state can still miss a revoke–regrant interruption. Checking immediately before aggregation can leave another race if policy mutation occurs before publication. These are protocol counterexamples to specified enforcement arrangements, not claims that every existing FL system exhibits the same failure.

The study asks which lifecycle failures arise under the declared policy grammar; how history-aware authorization and an ordered commit boundary can prevent invalid publication; how independently verifiable decisions compare with simpler baselines; and what governance checks cost in utility, participation, latency and resource use. Its intended contribution is a precisely specified protocol and reproducible evidence about its behavior under stated assumptions. It does not claim to invent policy-aware FL, continuous authorization, purpose-based access control, guarded transactions or tamper-evident logs.

## 2. Related work and comparison limits

Usage control already treats continuity and mutable attributes as central access-control concerns. Purpose-based access control links data use to declared purpose and conditional roles. The present artifact deliberately uses a smaller exact-string purpose/action grammar and does not claim a general replacement for these models. [Sandhu and Park, Usage Control: A Vision for Next Generation Access Control](https://profsandhu.com/confrnc/misconf/2003_MMS_UCON.pdf); [Byun, Bertino and Li, Purpose Based Access Control of Complex Data for Privacy Protection](https://www.cs.purdue.edu/homes/ninghui/papers/purpose_sacmat05.pdf).

Several FL systems directly limit broad novelty claims. AspectFL combines dynamic policies, provenance and compliance-sensitive aggregation. Smart Policy Control specifies local-training and aggregation policies with model hashes and blockchain-backed storage. Consequently, adding a policy engine or an audit trail to FedAvg is not sufficient novelty. [AspectFL, §§4.4–4.5 and Algorithm 5](https://www.mdpi.com/2078-2489/16/12/1048); [Smart Policy Control, §§IV-B–IV-D](https://arxiv.org/html/2305.09134).

FLA³ is a close infrastructure precedent: institutional authentication, study-scoped authorization, temporal validity, fail-closed decisions and cryptographic accounting accompany Flower-based execution. Its inspected authorization expression uses current request time and its aggregation stage filters participants. The comparison needed here is whether lifecycle interruptions and mutations racing publication receive an equivalent history/commit treatment; that distinction must be demonstrated rather than presumed. [Building Privacy-and-Security-Focused Federated Learning Infrastructure for Global Multi-Centre Healthcare Research, §§III–IV](https://arxiv.org/html/2603.10063v1).

FairAI binds approval to artifacts and context, checks signer revocation, expiry and replay, and cancels publication when required approved artifacts cannot be retrieved or verified. It also separates decision authenticity from signer truthfulness. GAFL independently verifies update-bound governance evidence and combines temporal trust, governed aggregation and audit logging. Independent checking, bound artifacts and governance/utility trade-off studies therefore also have direct precedents. [FairAI, §§4.5–4.6 and 5.13](https://www.mdpi.com/1999-5903/18/9/455); [GAFL, §§3–5](https://arxiv.org/pdf/2610.38411).

Ranathunga, Bharti and McGibney's *Policy-Driven Federated Learning* is confirmed by the institutional record and official conference program. Only the abstract was available for methodological comparison. That abstract claims lifecycle enforcement; policy definition, enforcement and observability; governed data-space interoperability; and IID/strongly non-IID/adversarial evaluation with improved robustness and negligible overhead. These remain attributed abstract claims. Exact interval/regrant semantics, atomic publication and detailed measurements are **unknown**. The unavailable methods do not support an inference that these mechanisms are absent. [Institutional publication record](https://pure.mtu.ie/en/publications/policy-driven-federated-learning-operationalising-governance-trus/); user-provided abstract provenance (retained evidence artifact ID `reports/ranathunga_abstract_provenance.json`; not included in the public aggregate release); retrieval audit (retained evidence artifact ID `reports/ranathunga_retrieval.json`; not included in the public aggregate release).

Auditable history also requires a protected reference point. Crosby and Wallach distinguish retained-event integrity and consistency across observations using auditor-held commitments. A hash chain with a freely replaceable colocated head cannot establish the same protection. This project consequently qualifies tamper evidence by anchor custody and attacker capability. [Efficient Data Structures for Tamper-Evident Logging, §§1–2](https://www.usenix.org/legacy/events/sec09/tech/full_papers/crosby.pdf).

The defensible contribution is incremental: an explicit inclusive authorization-history protocol, a specified publication linearization point and reproducible interruption/race evaluation under declared assumptions. Novelty and firstness remain unresolved. The [targeted literature matrix](../docs/literature_matrix.csv) records inspected sections and access limits; it is not an exhaustive systematic review. A negative retrieval result cannot establish uniqueness.

PoCoFL is additional close prior work on policy compliance through commitments and zero-knowledge proofs. Its stated threat model separates malicious clients and servers and excludes their collusion; its aggregation guarantee concerns admitted records, with earlier omissions requiring additional submission accountability. The present study does not establish that its invariant cannot be expressed in PoCoFL, and adds no retrospective comparison to the frozen experiment matrix. [George, Mishra and Abidin, PoCoFL, §§II–V](https://arxiv.org/html/2610.03650v1).

## 3. Methods

The study specifies a controlled, single-region governance experiment with eight synthetic organizations and eight separately authenticated Fargate client tasks. A coordinator and trusted commit service use an authoritative policy-history service, native OPA decisions, DynamoDB transactional state and versioned S3 artifacts. Clients acknowledge nonce-bound tasks and submit updates bound to organization, purpose, round, schema and content digest. The design assumes correct identity mapping, trusted enforcement and order services, controlled policy writers, durable staged objects and separately protected audit anchors. It excludes malicious poisoning, compromised trusted administrators, secure aggregation, differential privacy, unlearning and clinical deployment claims.

Later recovery and replication use distinct support orchestration: three guarded standalone support tasks are issued before health and DNS checks, with all four managed ECS service schedulers held at zero desired, running and pending counts. Frozen main service/runtime code and the full P1 protocol remain unchanged. Sensitivity trials use a separately bound adapter image layered on the frozen main runtime; canonical fresh replication uses the original main runtime. Earlier primary runs retain their original orchestration. Later support-startup observations remain separate operational metadata and are not pooled into the primary S0 runtime-overhead comparison. The frozen per-method audit and latency inclusion rules retain all canonical non-ablated attempts, including later canonical applications with distinct support versions; no retrospective orchestration-based filter is applied. These mixed-stage summaries remain descriptive.

Policies use exact purpose strings and the actions train, submit_update and aggregate. Matching denials override permissions; absence of an applicable allowance denies. Grant and change events replace the complete rule set; revoke and expire events remove permissions. Each mutation advances a contiguous organization epoch and appends immutable history atomically. Eligibility requires all three actions to remain allowed at task acknowledgment and every transition in the inclusive interval through publication. A relevant denial invalidates that task lifecycle permanently, including after regrant. An unrelated-purpose change may preserve eligibility but still requires epoch revalidation. Expiry is an explicit authority transition, without a hard wall-clock guarantee or retrospective invalidation of earlier committed models.

P1 candidate preparation reads a coherent authority snapshot and complete, strongly read history prefixes, rejecting missing epochs, inconsistent tails or incomplete pagination. Eligible updates are combined by sample-weighted FedAvg, using unique contributing sample counts. The candidate is staged and its exact S3 version, digest, size and availability verified before publication. A single DynamoDB transaction guards the global sequence, every contributing epoch, parent pointer, round membership generation, pending-update finality and audit state, then records the manifest, final outcomes and audit updates while switching the committed pointer. This pointer transition is the release linearization point; S3 and DynamoDB are not treated as one cross-service transaction. Conflicts require refreshed histories, membership and aggregation. Durable operation fingerprints resolve ambiguous responses; identical delivery cannot contribute twice.

Final decisions retain identities, outcome and reason, authority order, observed epoch, history digest and manifest binding. Independent checks reconstruct policy eligibility, weighted models, immutable versions, audit membership and pointer consistency. Operator witnesses use ECDSA-P384-SHA384 with an externally supplied public-key fingerprint and separately retained commitments. This supplies evidence binding under the trusted-operator assumption, rather than proof of truthful client training. Replacing records together with an untrusted colocated chain head is outside hash-chain integrity alone.

The benchmark uses UCI Diabetes 130-US Hospitals, dataset 296 (Clore et al., 2014; DOI 10.24432/C5230J), with all 101,766 encounters representing 71,518 patient keys. The discharge-time binary target is readmission within 30 days; later readmission and no readmission are negative. Patient keys determine groups only, and encounter identifiers detect duplicates; neither is a predictor. Discharge disposition and declared high-cardinality or outcome-proxy fields are excluded. A seed 296 hash-based patient split assigns 70/15/15 percent to training, validation and test before preprocessing, yielding 71,160/15,324/15,282 encounters. Patients remain disjoint across splits. This is a historical benchmark split, not chronological external validation or evidence of clinical suitability.

Training-only medians, means and population standard deviations determine numeric imputation and scaling. Training vocabularies define 32 categorical predictors, with distinct missing and unseen categories, alongside eight numeric predictors. Categorical codes become separate one-hot blocks. Eight fictional organizations receive training patient groups through balanced shuffled allocation or label-stratified Dirichlet allocation with base concentration 0.5; patients remain intact. Organization minima are 100 patient groups and 25 positive encounters, with bounded sampling retries. Frozen manifests bind source, partition, preprocessing and holdout bytes. Distributions reuse the same patients and do not represent independent datasets or actual hospital membership.

The full-data experiment configuration specifies a float32 CPU MLP with 64- and 32-unit ReLU hidden layers, one output logit, no dropout or batch normalization, five global rounds and one local epoch. Local optimization uses binary logit loss, fresh Adam state, learning rate 0.001, batches of 64 and one CPU thread. All prepared partitions and full validation are bounded by an explicit 100,000-row cap. The threshold is 0.5. Initialization uses the cell seed; local shuffles use seed plus 100 times the round number plus the zero-based organization index. The earlier two-round, 256-example configuration remains pilot material. Average precision, rather than trapezoidal precision-recall area, defines AUPRC; undefined metrics remain explicit.

The registration comprises 160 primary cells: B1/B2/B3/P1 crossed with IID/non-IID, S0-S3 and seeds 296, 593, 887, 1181 and 1483. Matched methods share training, data, initialization, resource, selection, source/image, schedule and analysis bindings. Additional registries contain 50 P1 targeted S4-S8 cells and 40 ablation cells. Authority barriers define revocation before dispatch, in-flight revocation, held-update delivery, revoke-regrant, expiry, near-publication mutation, duplicate/reordered consumption, restart and transport-fault scenarios. The four canonical families contain 258 registered obligations. Registered schedules specify intended interventions; their execution requires retained traces.

B1 ignores policy while retaining structural and custody checks. B2 caches initial organization admission; B3 caches dispatch authorization. Both reuse their actual decision provenance without fabricated later OPA decisions. P1 checks dispatch, receipt and the complete lifecycle before guarded publication. Abl-1 removes receipt rechecking; Abl-2 removes contributor-epoch conditions but retains the global sequence fence, so it tests guard redundancy without forcing an unsafe counterexample. Abl-3 omits final-decision audit appends while retaining other bookkeeping. Abl-4 substitutes current-state authorization for continuous history. These variants retain their declared identities and never become final P1 evidence; partial component verification remains distinct from full-protocol qualification.

All failed, aborted, excluded and repeated attempts remain in coverage and missingness accounting. Cumulative resource and cost accounting retains incurred physical work; unavailable per-case numeric allocations remain explicit. A clean primary cell requires exactly one successful attempt; a favorable retry cannot replace an earlier failure. Assigned, acknowledged and presented tasks, final allows, denials, operational errors and indeterminate tasks have separate denominators. Invalid incorporation divides oracle-invalid incorporated unique updates by oracle-invalid presented updates; incorrect rejection uses oracle-valid rejected/presented updates. Issued tasks lacking final attributable outcomes remain indeterminate; operational errors without received updates still enter the audit denominator. Missing counts and zero-opportunity ratios remain undefined. Audit completeness, independent verification and manipulation detection retain their own attempted denominators.

Inference uses five paired training-seed clusters conditional on the fixed UCI patient split and client setup. They are not independent cohorts or sites, and the 160 crossed primary cells and individual updates are not independent seed replicates. Paired bootstrap resampling uses common seed indices, 10,000 resamples and RNG seed 271828. Two-sided 95 percent intervals use the 2.5th/97.5th percentiles; one-sided 95 percent lower bounds use the fifth percentile. These bounds are approximate with five clusters. H1 enumerates P1 invalid incorporations and opportunities, with conditional upper bound 1 - 0.05^(1/n) for n independent seed clusters if no cluster violates. H2 pools S1-S3 and both distributions within seed before paired P1-minus-B2/B3 differences; both comparator upper bounds must be negative. Intervals are unadjusted and do not establish simultaneous coverage. H3 is eligible for a decision only when confirmatory analysis is permitted, all 50 registered targeted cells each have exactly one attempt and that attempt succeeded, audit counts are complete, and the manipulation-attempt denominator is nonzero. Its audit completeness, verification and detection statistics follow the unchanged frozen inclusion rules, including later canonical non-ablated executions under their actual support versions. The expected H3 qualification and verdict are determined by native analysis rather than inferred from operational expectations. Expected operational failures remain failures. Operator copied-evidence tampering has a separate scope and is not backfilled as runtime attacks.

H4 concerns only the primary stable S0 P1-minus-B3 AUROC comparison: five matched seed pairs per distribution, giving ten AUROC values under IID and ten under non-IID, twenty values in total. Each original MAIN application's 80-run test authority is broader than this statistical subset; H4 membership neither creates nor narrows authority. Both one-sided 95 percent lower bounds must exceed minus 0.02, with values within 1e-12 of the margin conservatively failing. Validation-only data, missing pairs, unaccepted protocols, changed analysis settings or synthetic evidence cannot decide H4.

The separate sensitivity component comprises 21 single-seed exploratory cases covering non-IID severity, revocation frequency, participation, update size, artificial delay and client-clock skew. Shared controls do not create additional independent seeds. The failed alpha 0.1 preparation remains separate from cloud trials and successful scientific cases. These validation-only descriptions do not enlarge H4. The eight-cell B3/P1 replication component used one new deployment with a fixed 2.75-hour window and two distribution-specific applications. Each four-case application contained B3 and P1 under S2 and S3 with seed 296. Its deployment, namespace and client task identities differed from the corresponding primary execution. Four cells shared each application's eight-client fleet; the two applications used fresh, disjoint client fleets. These eight S2/S3 cells neither create new independent seeds nor add primary S0 H4 pairs. Latency and overhead summaries remain descriptive; revocation responses use one coordinator clock and authority-bound timing intervals with censoring and missingness. Missing per-case costs are never zero-filled. All 40 ablations use the independent-partial-protocol verifier and provide evidence for their named component experiments; none was certified as full P1. The native successful status of the 20 non-IID ablations additionally does not establish complete five-round execution for those cells.

An earlier replication-startup project failed operationally after 21 physical tasks and produced no clinical attempt rows. Those tasks remain in cumulative operational and budget accounting; they are not successful replication cells or additional clinical observations. The replacement deployment produced the eight separately registered replica rows; fresh-deployment metadata passed for each. The completed protected replay preserved each original assessment and separately recomputed all originally reported final metrics, including those from the eight fresh replica cells; these checks do not create additional independent seeds.

## 4. Results

### 4.1 Attempt census and retained failures

The final canonical ledger contains 258 attempts, with the original 250-row prefix unchanged and eight fresh replica rows appended. Native analysis reports 248 successful statuses and 10 failures; every registered obligation was attempted. The 21 exploratory cases and original G1 development material remain separately labeled and do not add canonical cells or independent seed clusters.

| Canonical family | Registered cells | Native-successful | Failed or ambiguous | Unattempted |
| --- | ---: | ---: | ---: | ---: |
| Primary | 160 | 160 | 0 | 0 |
| Targeted | 50 | 40 | 10 | 0 |
| Ablation | 40 | 40 | 0 | 0 |
| Fresh replication | 8 | 8 | 0 | 0 |

Here, native refers to the unchanged project verifier, ingester and analysis, rather than hardware attestation. The status column is the retained native classification. All 40 ablations are classified under independent-partial-protocol verification, which scopes their component evidence separately from full P1 safety. For the 20 non-IID ablations, successful status additionally must not be read as complete five-round execution. The 10 failed targeted attempts remain failures and prevent full successful targeted coverage. The failed earlier startup project consumed 21 physical tasks but produced no clinical attempt rows, so it is retained in operational and cost accounting rather than fabricated as clinical data. All settings, registered allocations, seeds, native values and analysis rules remained unchanged; no result-based retuning or favorable retry replaced these records.

### 4.2 Registered hypotheses and uncertainty

**H1.** The primary P1 suite incorporated 0 of 20 oracle-invalid presented unique updates, with no missing H1 counts and zero violating clusters among five training seeds conditional on the fixed UCI split and client setup. The registered H1 verdict is supported. The conditional one-sided 95 percent upper bound on the probability of a violating seed cluster is 0.4507197283469412 (45.07197283469412 percent); it is not an update-level failure probability or a bound that establishes zero population risk.

Across all primary scenarios and both distributions, the aggregate governance counts were:

| Method | Invalid incorporated/presented | Valid rejected/presented |
| --- | ---: | ---: |
| B1 | 140/140 | 0/1460 |
| B2 | 140/140 | 0/1460 |
| B3 | 20/20 | 0/1460 |
| P1 | 0/20 | 0/1460 |

The methods produce different presentation opportunities. A stratum with no oracle-invalid presented updates retains an undefined invalid-incorporation rate rather than a zero. Counts are therefore conditional on the stated presented-update denominators, not a common-denominator causal effect.

**H2.** S1-S3 and both distributions were pooled within each seed before the two registered paired comparisons. Both contrasts were supported:

| Comparison | Paired training seeds | Mean rate difference | Two-sided 95% interval | Verdict |
| --- | ---: | ---: | --- | --- |
| P1-B2 | 5 | -1 | [-1, -1] | supported |
| P1-B3 | 5 | -1 | [-1, -1] | supported |

The -1 differences correspond to 100 percentage-point lower observed invalid-incorporation rates under the registered estimand. The degenerate intervals reflect identical observed seed-level differences in this finite suite; they do not supply simultaneous coverage or generalize to arbitrary policies, attacks, deployments or populations. Both H2 intervals use the registered 10,000 paired bootstrap resamples and RNG seed 271828.

**H3.** The native verdict is inconclusive. Under the unchanged canonical non-ablated inclusion rules, the P1 audit table covers 94 attempts, with 3304/3304 final decisions carrying complete audit evidence and 94/94 tested record sets verified. Runtime manipulation detection is 0/0 and remains undefined. In addition, only 40 of 50 targeted cells have native successful status. Complete observed audit counts cannot supply the missing manipulation opportunities or successful targeted cells. Separately protected copied-evidence tampering is not backfilled into the runtime detection denominator. Later canonical support versions remain in the frozen audit inclusion scope; their startup measurements are not substituted for H3 evidence.

**H4.** Only the primary stable S0 P1/B3 cells enter this test: five matched seed pairs per distribution, ten AUROC values per distribution and twenty values total. The observed P1-minus-B3 AUROC contrast was zero in each matched pair.

| Distribution | Paired seeds | Mean AUROC difference | Two-sided 95% interval | One-sided 95% lower bound | Verdict |
| --- | ---: | ---: | --- | ---: | --- |
| iid | 5 | 0 | [0, 0] | 0 | supported |
| non_iid | 5 | 0 | [0, 0] | 0 | supported |

Both lower bounds 0 strictly exceed the prespecified -0.02 margin, so H4 is supported within the authorized frozen-test benchmark. The zero-width intervals show no observed paired AUROC variation here; they do not prove population equivalence or clinical non-inferiority. The twenty values are the H4 statistical subset, not a replacement for each original MAIN application's broader 80-run test authority. The fresh S2/S3 replicas and validation-only exploration do not enlarge this S0 test.

### 4.3 Ablations, sensitivity and fresh replication

All 40 registered ablation cells have native successful status under the ablation-specific partial-protocol verifier. For the 20 non-IID cells, complete five-round execution remains unestablished. Ablation identities and incomplete components remain separate from full P1 evidence. The following descriptive counts are shown separately for each distribution; every row contains five registered seed cells.

| Variant | Distribution | Invalid incorporated/presented | Complete audited/final decisions | Evidence scope |
| --- | --- | ---: | ---: | --- |
| Abl-1 | iid | 0/5 | 180/180 | component ablation; partial verifier |
| Abl-2 | iid | 0/5 | 180/180 | component ablation; partial verifier |
| Abl-3 | iid | 0/0 (undefined) | 0/200 | audit append removed; partial verifier |
| Abl-4 | iid | 5/5 | 200/200 | current-state authorization; partial verifier |
| Abl-1 | non_iid | 0/5 | 180/180 | partial verifier; five-round completion unestablished |
| Abl-2 | non_iid | 0/5 | 180/180 | partial verifier; five-round completion unestablished |
| Abl-3 | non_iid | 0/0 (undefined) | 0/200 | partial verifier; five-round completion unestablished |
| Abl-4 | non_iid | 5/5 | 200/200 | partial verifier; five-round completion unestablished |

Abl-3 exposes the intended final-audit gap, while Abl-4 admits interrupted lifecycles under current-state authorization. Abl-1 and Abl-2 do not force unsafe publication in these observations; receipt removal or redundant epoch-guard removal alone does not establish that the remaining guards fail. Non-IID rows retain their recorded partial scope and are not promoted to complete five-round proof. No additional inferential comparison is introduced. In the targeted suite, S4-S7 each have five successful cells per distribution; S8 has five failed cells per distribution. All ten S8 failures remain in the ledger and H3 eligibility check.

The 21 prescribed exploratory cases remain a separate single-seed, validation-only sensitivity component. Their shared controls do not create extra independent replicates, and the failed alpha 0.1 constrained preparation remains a separate negative result rather than a cloud-training success. No exploratory population effect or confidence interval is inferred. Original G1 development observations remain separate.

All eight fresh replica cells received native successful status, and each of the eight final analysis rows passed the fresh-deployment metadata check. One new AWS project hosted two applications, one per distribution, with B3/P1 x S2/S3 and seed 296: four cells per application. The new deployment, namespaces and client identities differed from their primary counterparts, and the two applications used disjoint new client fleets. This is fresh execution at an already registered seed, not eight new deployments or new independent seed clusters. Native execution and fresh-deployment metadata verification were supplemented by completed protected model/audit replay in both original images and full-cohort final-metric recomputation. These retained-snapshot checks establish neither fresh retraining nor live-provider attestation.

### 4.4 Timing and conservative administrative cost

The registered primary S0 comparison yielded the following P1-versus-B3 round-time results. Millisecond values are rounded to six decimals and ratios to nine decimals for display; the bound native aggregate retains full precision.

| Distribution | Paired seeds | Ratio of mean round times (P1/B3) | Mean P1-B3 difference (ms) | Two-sided 95% interval (ms) |
| --- | ---: | ---: | ---: | --- |
| iid | 5 | 1.033442042 | 1611.914057 | [814.484857, 2520.074577] |
| non_iid | 5 | 1.184845861 | 10093.284226 | [9200.718935, 10690.420522] |

Each ratio divides the P1 mean round time by the B3 mean round time over the paired seeds; it is not the mean of per-seed ratios. The paired-difference intervals are computed separately. The ratios correspond to descriptive increases of approximately 3.3 percent under IID and 18.5 percent under non-IID. These observations do not support a negligible-overhead claim and are conditional on the fixed training-seed, data and client setup. Later recovery/support startup is reported separately, while generic per-method latency summaries retain their frozen mixed-stage descriptive scope. Revocation response intervals remain coordinator-clock brackets with censoring and missingness, not exact revocation times or additional independent seeds.

The conservative whole-B upper bound is USD 24.840400414 and 54.576903873056 normalized resource-hours against limits of USD 25 and 56 hours. The six-project union includes all three inherited predecessors and all three recovery/replication projects, including the failed 21-task zero-clinical-row startup. All six deployments have genuine native seven-check closure evidence; the three recovery projects additionally retain separate Event sidecar and standalone DNS closure evidence, and the new deployment's 16 generated secrets were read back as absent. These closure facts do not repair the original 30 unknown task durations or nine historical last-RUNNING rows.

No numeric per-attempt cost entries are available for any of the 258 canonical attempts. The aggregate table's sum over absent per-case entries is not evidence of zero spending. Per-case/per-published-model prices remain unavailable; the administrative bound is conditional, not an invoice, CPU-utilization measurement or native historical all-STOPPED accounting pass.

### 4.5 Figures and evidence scope

The seven native figures were generated in PNG, SVG and PDF (21 files), and all seven PDFs were visually checked. Public PDFs use lossless uncompressed streams after an export check rejected an accidental local-path byte pattern in a compressed stream. The unchanged native plotting code and identical scientific inputs generated the export again; all 14 PNG/SVG hashes and all seven rendered PDF images were identical to the original figures. They show: (1) invalid incorporation by scenario; (2) incorrect rejection by scenario; (3) policy-call and publication-attempt latency; (4) the twenty primary stable-test AUROC values as paired B3/P1 observations; (5) descriptive participation and utility; (6) descriptive round time and revocation frequency; and (7) the registered paired governance confidence intervals and one-sided stable-AUROC lower bounds. Missing opportunity ratios remain undefined. Figure 7 is an effect-interval figure, not a per-case cost plot. These plots reproduce the declared primary/aggregate scopes and do not extend the number of independent seeds or establish clinical effectiveness.

## 5. Limitations and research record

Interim metric output was accidentally exposed twice. The first incident, recorded at 2026-11-15 00:29:50.011081 UTC, involved targeted validation output without held-out test output (retained incident record: accidental_targeted_validation_display_v1/incident.json). The second, recorded at 2026-11-15 16:01:53.238867 UTC, arose from an unintended broad search during cleanup source review and included at least one primary B3 held-out test-metric record and protocol, accounting and timing metadata (retained records: peer-unintended-search-exposure-v1.json and clarification-v2.json). Its original primary-record source path and hash remain unknown because the truncated display did not retain a reliable filename. The budget block and cleanup decision preceded the second exposure, as recorded in the retained incident clarification. Neither exposure changed study settings, allocation, seeds or analysis policy. We therefore cannot claim that interim or held-out metrics were never exposed.

Per-case cost gaps remain explicit. Terminal conservative whole-B accounting includes the original 269-task baseline and every new physical task, including failed attempts and the failed zero-clinical-row startup project. The terminal union covers all six projects: three inherited predecessors and three recovery or replication projects. All six deployments have genuine final native seven-check resource-closure records. The three recovery projects also retain their separate Event-capture sidecar and standalone service-discovery closure evidence; the new deployment's 16 generated secrets were read back as absent. The conservative upper bound is USD 24.840400414 and 54.576903873056 normalized resource-hours, within the approved USD 25 and 56-hour limits. It remains conditional on the declared clock, resource and sidecar assumptions. It does not supply missing per-case measurements, measure CPU utilization, constitute an invoice, or establish a native historical all-STOPPED accounting pass. The original 30 unknown durations include the nine historical last-RUNNING ledger rows; resource closure does not repair their historical timestamps or statuses.

The investigator described this as independent computational research using public secondary data and synthetic policies and organizations, and reported no institutional review requirement. No institutional approval, exemption, determination or IRB approval is claimed.

The comparison with Ranathunga, Bharti and McGibney is limited to their abstract. Detailed authorization-interval, revoke-regrant, history-completeness and atomic-publication mechanisms remain unresolved. Failure to inspect the full text provides no evidence that those mechanisms are absent and supports no firstness claim (the retained primary-source refresh and abstract provenance records).

PoCoFL (George, Mishra and Abidin, arXiv:2610.03650v1) is close prior work on policy compliance using commitments and zero-knowledge proofs. Its stated threat model excludes client-server collusion, and its guarantee concerns admitted records, with earlier omissions requiring submission accountability. We position this artifact as an incremental explicit protocol, deployment and invariant evaluation. Expressibility of its invariant in PoCoFL has not been ruled out; no PoCoFL reproduction or comparative performance experiment was added to the frozen matrix (the retained primary-source refresh and abstract provenance records).

Original exploratory placement reports recorded MISSING responses for older task ARNs. Current learning and support actors could pass their native placement checks while the historical failures kept the original overall reports unverified; both the original reports and statuses remain retained. The original capture-time SDK MISSING failures remain retained. A separate derived metadata view resolves historical inactive ARNs only when separately retained earlier genuine SDK STOPPED records and matching qualified archived AWS STOPPED events establish terminal state before the original capture. The original MISSING responses identify the capture-time failures; they do not establish STOPPED state. It preserves the original snapshot, failures, actor identities and capture time, and carries distinct provenance and hashes. The unchanged independent normalizer was rerun against an explicitly declared new input. Raw case exports, signatures, model bytes, settings and scientific attempts are unchanged. Such a metadata qualification is not a claim that the original witness signed the derived view. All 21 exploratory cases were qualified by the unchanged native normalizer using explicitly declared derived placement views and an independently reviewed provenance packet. The original reports remain unverified where historical MISSING responses occurred; the new qualification is separate evidence. Successful API delivery of a historical MISSING response is not treated as a positive STOPPED observation. Qualified archived STOPPED events and original capture-time/actor bindings supply the stated historical resolution. No scientific attempt, raw model, signature or witness statement was rewritten.

## 6. Reproducibility

The canonical 258-attempt aggregate and its registered analysis are bound to plan digest `11d134cc9d16fa4da242e7afc09ae66c00fb5f78d62ce09b302729a9706919ee` and attempts digest `f26109f958dd5943ce4b57998b060c35e0488d2acc4e301e1ca16b686f606b4c`. The original 250-row prefix is unchanged. The native analysis uses the original five paired training-seed clusters conditional on the fixed UCI split and client setup, 10,000 bootstrap resamples and RNG seed 271828; no settings were retuned. These clusters are not independent cohorts or sites. Fresh AWS execution, protected native model/audit replay, full-cohort numeric metric recomputation, and public hash-bound aggregate reproduction are separate claims.

Two earlier retained-proof invocations failed in verification-tool integration: first a pure helper with no Path constructor was included in the relocation list, then a path-only callback attempted to parse a public PEM key as JSON after processing the canonical batches. Corrective build FMR8-c2 excludes the pure helper from constructor scope, uses authenticated raw-byte access for the path-only key lookup, and explicitly scopes the existing reporting module. It also raises the finite local offline worker deadline from 3600 to 7200 seconds; cloud leases and budget limits are unchanged. The native 270-file scientific source, the other 12 replay assets, original data/model/evidence inputs and numeric comparison policy remain unchanged. Both failed invocations remain retained. The corrected full replay completed on 16 November 2026 with a literal outer process exit code of 0. Both original immutable runtime images completed the full no-clinical-CSV native proof, with matching admissions and all 258 original canonical assessment hashes preserved. The 21 exploratory cases and accepted G1 protected export remained separately scoped. All 269 originally reported final utility outputs were recomputed exactly once across five original image/cohort/metadata groups: 168 test outputs on the full 15,282-row test cohort and 101 validation outputs on their full 15,324-row validation cohorts. Original model bytes, parameters, response hashes, preprocessing, source roles and complete position sets were bound; no training, cohort sampling, substitution or new test authorization occurred. Ten failed targeted attempts had no original final response and remain explicit noneligible failures; G1 was protected-export replay only. Counts, positive counts, prevalence and threshold agreed exactly. All six floating metrics passed the prespecified absolute tolerance of 0.000001 with relative tolerance 0 and no rounding or widening. Maximum absolute differences were 8.60009687e-8 for AUROC, 3.1427421687e-7 for AUPRC and 7.98784927e-9 for loss; precision, recall and F1 differences were 0. None of the 269 complete metric vectors was entirely bit-exact. Original scientific values were unchanged. Every owned replay container was confirmed absent afterward. The retained evidence is local operator execution under a protected-snapshot boundary; it is not remote attestation or a live-provider-currentness check. Unreported client training losses, intermediate learning curves and checkpoints remain outside this final-response verification.

Public reproduction uses a source snapshot, locked plan, aggregate attempts and registered statistical outputs, together with the seven figures and detailed reporting. The distributed reproduce.py checks bound source/archive/artifact hashes and recomputes aggregate statistics. Its scope is source and aggregate statistical reproduction; it does not perform fresh federated training or private model/audit/cohort replay. Native phase assessment and release verification use separate machine-readable evidence and execution receipts. Their genuine returned statuses provide the completion record; no execution is inferred from the manuscript or from file existence. An operations source supplement requires separate packaging, core pins and verification; it does not broaden the public data boundary.

The public export boundary excludes clinical rows, labels, individual predictions, patient-membership records, bearer nonces, credentials, private keys and model arrays. Fresh retraining, protected native model and audit replay, full-cohort numeric metric replay, and public aggregate or statistical reproduction have distinct purposes and custody boundaries. Completion of one does not establish another. Final release verification must bind the accepted plan, every retained attempt, exact sources and immutable images, final utility replay, analysis and rendered figures. Public packaging and reproduction require their separately bound execution records. Conservative cost qualification remains distinct from per-case allocation and invoice reconciliation.

## Appendix A: Conditional safety obligations

This is a finite conditional specification and preservation argument, not a universal theorem, a complete implementation-refinement proof, or an empirical result. The logical state, assumptions A1-A12, obligations PO-01-PO-10 and commit argument below reproduce the existing register's logical text without changing its premises. Compliance of actual code, providers, identities, IAM and failure executions remains a separate validation duty; finite tests cannot discharge every assumption.

Logical-text source: retained document ID `spec/proof_obligations.md` (not included as a separate file in the public aggregate release), SHA-256 `614defe5b0783f692fd6b5bb79f427476703b153464148dffeafb613e073938c`. The [INV-1-INV-4 definitions](../spec/invariants.md) remain included. Historical implementation-status inventories and observed test counts from the retained document are not imported into this appendix. No new execution, liveness, privacy, unlearning, novelty or confirmatory claim follows from this argument.

### A.1 State and transitions

The abstract state is `(q,H,E,T,U,R,C,M,P,D,A)`: authority sequence, immutable

policy history, current epochs/hashes, acknowledged tasks, bound receipts, round

membership/generation, staged candidates, immutable manifests, published pointer,

final outcomes and audit/head. Exactly eight organization identities and three

actions (`train`, `submit_update`, `aggregate`) are in scope. Every committed

mutation consumes `q+1`; policy orders need not be consecutive because other

operations consume sequence values.

For organization `c`, purpose `p` and lifecycle `[s,k]`, checkpoints are the latest

state at or before `s`, then every replacement in `(s,k]`. `HV(c,p,s,k)` requires

valid complete history and an exact allow without a matching deny for every

action at every checkpoint. Regrant cannot erase an earlier denial. Expiry is a

committed `EXPIRE` transition, not an unobserved clock tick.

`Issue` binds identity/purpose/round/schema/nonce; `Ack` establishes `s` with a

policy guard; `Receipt` binds the task, bytes and sample count; `Prepare` snapshots,

computes and stages; `Reject` finalizes ineligibility; `Publish` atomically changes

pointer and final outcomes; `Recover` reads the original durable request outcome.

An empty round closes without a new manifest. The successful pointer transaction,

not aggregation completion or object upload, is publication's linearization point.

### A.2 Necessary assumptions

| ID | Assumption | Counterexample if violated |
| --- | --- | --- |
| A1 | Every relevant writer uses one single-region guarded sequencer. | A bypass administrator writes policy or pointer directly. |
| A2 | Current state/hash, increasing epoch and immutable history/event identity change atomically. Epochs never reset or wrap. | Missing history, rollback or reused versions. |
| A3 | Snapshot acquisition checks coherence, complete epochs and matching history tails. | Mixing an old current item with a different history. |
| A4 | The pinned Rego service implements the grammar and returns request-bound known-revision decisions. | Compromised evaluator or substituted rules; echoed metadata is not attestation. |
| A5 | Identity mapping, coordinator, policy writer and evaluator are trusted; task and payload bindings are checked. | Forged identity, trusted-actor compromise or dishonest sample counts. |
| A6 | Successful conditional DynamoDB transactions are atomic with the required conflict semantics. | A weaker storage model or unguarded multi-region writes. |
| A7 | Candidate identity binds exact membership, parent, schema, history, rule hash and confirmed immutable object version/bytes/size. | Mutable reference, altered parameters or missed membership generation. |
| A8 | Consumers discover models only through committed manifests/pointers. | Consuming a staged candidate as published. |
| A9 | Required object versions/evidence are retained under access controls. | Deleting a version after confirmation; continued availability then fails. |
| A10 | SHA-256 collision resistance and unambiguous canonical encodings/parameter order hold. | Serialization ambiguity or cryptographic break. |
| A11 | Final outcomes, history and audit head cannot be overwritten; independently retained anchors are trusted. | Replacing both exported chain and colocated head or privileged rollback. |
| A12 | Unresolved attempts remain explicitly incomplete; eventual completion additionally needs available services and a recovery actor. | Treating timeout as success or deriving liveness from bounded retries. |

### A.3 Proof obligations and finite evidence

| ID | Required preservation argument | Evidence boundary |
| --- | --- | --- |
| PO-01 / INV-1 | Publication implies `HV`, exact task binding and recomputation from exactly the included contributors. | Oracle/OPA histories and reconstruction tests cover finite cases; no complete implementation refinement proof. |
| PO-02 / INV-2 | A pre-publication mutation invalidates the old sequencer/epoch guard; a later mutation cannot change the earlier interval. | Both operation orders and conflict tests; deployed IAM/bypass resistance needs separate evidence. |
| PO-03 | Mutation writes state, epoch, unique event/order and outcome atomically, or writes none. | Request-builder checks, API-local tests and separately scoped AWS evidence. |
| PO-04 | The pointer references exactly the confirmed version/manifest; incomplete staging cannot publish. | Missing-version, digest, size and staging/crash tests; continued availability needs A9. |
| PO-05 / INV-3 | At most one immutable final outcome and contribution per update/round; exact retries recover it, rebound IDs fail. | Duplicate, restart and binding tests; eventual exactly-one resolution additionally needs A12. |
| PO-06 | Acceptance, OPA proof, membership and mandatory audit/head share publication's transaction; rejection evidence is durable/idempotent. | Missing-proof/audit and durable-row replay tests; hash/shape validity alone does not prove completeness. |
| PO-07 | Conflict recovery refreshes history, parent and generation and recomputes eligibility/weights. | Stale-epoch, concurrent-receipt/publisher and reaggregation tests; unbounded progress is not proved. |
| PO-08 | Empty eligibility preserves the pointer and records closure; late replies cannot reopen the round. | Empty-round, late-reply and restart tests; dispatch failures need attempt accounting. |
| PO-09 / INV-4 | Post-commit mutation changes future eligibility without rewriting prior manifests. | Publish-then-revoke tests; no unlearning guarantee. |
| PO-10 | Public exports exclude records/labels/bearer nonces; evaluation binds committed models and returns aggregate metrics. | Schema, coordinator-boundary, evaluator and logging checks; free text is not made private by a field-name check. |

### A.4 Conditional commit-safety argument

Suppose a candidate uses coherent snapshot `q0`, checks its inclusive interval

through proposed commit `q0+1`, and verifies every task, membership, schema,

history and immutable-object binding. The transaction requires sequence `q0`,

unchanged included epochs, parent and membership generation, pending receipts and

the expected audit head; it writes pointer, manifest and final evidence together.

Under A1–A7, a mutation linearized first changes a guarded item and prevents the

old publication. If publication succeeds first, no relevant policy transition

occurred between snapshot and linearization. The checked start/intermediate

states therefore remain the applicable interval. Regrant cannot erase a recorded

denial because all checkpoints are evaluated. This explains intended safety; it

does not mechanically prove every code/provider/IAM/failure execution satisfies

the premises. S3 and DynamoDB do not share an atomic transaction.

### A.5 Explicit exclusions

Unobserved wall-clock expiry, direct staged-object consumers, deletion after

confirmation, replacement of both history and anchor, false sample counts, or a

shape-valid record bound to the wrong task fall outside or violate the premises.

Schemas cannot repair them. Independent semantic replay, byte reconstruction,

role/isolation checks and protected anchors remain necessary. Literature novelty

and confirmatory hypothesis conclusions are separate scholarly/empirical questions.

