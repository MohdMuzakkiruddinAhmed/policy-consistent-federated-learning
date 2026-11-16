# Targeted literature and novelty audit

Search date: **2026-11-12 America/Chicago**, with a retrieval follow-up through
2026-11-13 01:01 UTC. This is a targeted engineering audit, not an exhaustive systematic review.
The [matrix](literature_matrix.csv) records access and inspected sections.
Unresolved means unestablished, including abstract-only evidence; it never means
absent. No research gate or novelty claim follows from these files.

## Retrieval and inclusion

Claims were checked against publishers, author/institution manuscripts, arXiv
preprints, or official service documentation. SciSpace supplied known-item
metadata, then explicitly reported abstract-only extraction context for Ranathunga.
Secondary summaries, rankings and generated text were not used to establish a
missing mechanism. No authors were contacted or access controls bypassed.

Exact targeted web queries in this extension:

```text
"Policy-Driven Federated Learning" Ranathunga pdf 11627589
"Ranathunga" "Policy-Driven" filetype:pdf
"10.1109/SmartComp-Companion70724.2026.00041" pdf
"Tharindu Ranathunga" federated policy arxiv
"Operationalising Governance" federated preprint
"Policy-Driven Federated Learning" site:arxiv.org
"Policy-Driven Federated Learning" site:nimbus.ie OR site:tharindu.me OR site:github.com OR site:zenodo.org
"AspectFL" "temporal" policies aggregation
"UCON" "continuity" "mutability" Park Sandhu 2004 usage control
federated learning verifiable aggregation audit provenance paper purpose access control revocation
"governance-aware federated learning" "temporal" arxiv
"Building Privacy-and-Security-Focused" "Federated"
purpose based access control privacy protection Byun Bertino Li 2005 pdf purdue
"Purpose Based Access Control" Byun Bertino Li pdf site:cs.purdue.edu
"Purpose Based Access Control" "2005" site:cerias.purdue.edu
"Efficient Data Structures For Tamper-Evident Logging" usenix
"Linearizability" Herlihy Wing pdf 1990 author
"s41746-025-01836-3" PMC
"A scoping review of the governance" Eden federated learning
```

SciSpace search used the exact Ranathunga title. Follow-up extraction requested
accessible full text, a primary PDF URL, and page/section evidence for interval
authorization, revoke–regrant and atomic publication; it supplied none. Include
works specifying executable FL governance, ongoing/purpose authorization, model
provenance, publication concurrency or tamper evidence, including competitors
that weaken the claimed contribution. Exclude unrelated domain papers and
secondary summaries from mechanism claims. Foundational work has no year cutoff;
recent discovery extends through the search date. Iterative targeted retrieval
does not support a complete screened-hit count.

## Evidence against broad novelty

[Eden et al.](https://pmc.ncbi.nlm.nih.gov/articles/PMC12246253/), Results,
Discussion and methodology, synthesize governance mechanisms across 39 papers.
Its search scope and largely conceptual evidence motivate the problem but cannot
establish a new executable concurrency protocol.

[AspectFL](https://www.mdpi.com/2078-2489/16/12/1048), §§4.4–4.5 and Algorithm 5,
already combines provenance, compliance-sensitive aggregation and dynamic policies
with temporal conditions. A compliance weighting mechanism differs from the
artifact's mandatory deny gate; equivalent closed-interval commit safety remains
unestablished by the inspected sections. Dynamic policy-aware FL is prior art.

[FLA³](https://arxiv.org/html/2603.10063v1), §§III–IV, is especially close: Flower,
institutional authentication, study-scoped XACML, time-bounded membership,
failure-closed enforcement and cryptographic accounting. Its displayed predicate
uses current request time; §IV-D checks permission before each aggregation. The
specific comparison must concern interruptions within a lifecycle and mutations
racing final publication. First runtime governance or expiry-aware FL claims are
unsupported.

[Smart Policy Control](https://arxiv.org/html/2305.09134), §§IV-B–IV-D and
Algorithms 1–2, already links training policy, aggregation policy, participant
restrictions, model hashes and blockchain storage. Auditable policy-controlled
aggregation itself is not new.

[FairAI](https://www.mdpi.com/1999-5903/18/9/455), §§4.5–4.6, 5.13 and protocol
experiments, already binds approval to artifact/context, checks signer revocation,
expiry and replay, retrieves approved models and cancels when required artifacts
are unavailable. Its proof relation has explicit truthfulness limits. Any contrast
must establish precise authorization-interval and commit-order differences;
approval gates, immutable artifacts and failure-closed release are prior art.

[GAFL](https://arxiv.org/pdf/2610.38411), §§3–5, pp.3–10, combines independent
update-bound evidence verification, historical trust, governed normalized
aggregation and tamper-evident records. Temporal trust scores differ from a
universal purpose/action interval predicate. This is a candidate distinction, not
proof that its implementation lacks an equivalent protocol. Governance/utility
and overhead comparisons are already reported.

[UCON](https://profsandhu.com/confrnc/misconf/2003_MMS_UCON.pdf), §§2–4, treats
ongoing decisions and mutable attributes as foundational usage control.
[Byun, Bertino and Li](https://www.cs.purdue.edu/homes/ninghui/papers/purpose_sacmat05.pdf),
§§3–6, formalize purpose-based access and conditional roles. Exact purpose strings
and replacement rules here are a restricted grammar, not a new general model.

[Crosby and Wallach](https://www.usenix.org/legacy/events/sec09/tech/full_papers/crosby.pdf),
§§1–2, distinguish integrity inside a committed history from consistency across
histories using auditor-held commitments. Hash chaining is prior art; replacing
both exported records and a colocated head defeats that local integrity check.

[FedAvg](https://arxiv.org/html/1602.05629v4), §2, Algorithm 1 and the v4 erratum,
provides the common contributor-normalized learning baseline. The
[DynamoDB contract](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html)
supplies guarded item transactions, not S3/DynamoDB atomicity. Verified staging
and pointer-based release remain application obligations.

## User-confirmed abstract-only comparison boundary

[The institutional record](https://pure.mtu.ie/en/publications/policy-driven-federated-learning-operationalising-governance-trus/)
confirms Ranathunga, Bharti and McGibney, SMARTCOMP Companion 2026, pp.141–146,
DOI `10.1109/SmartComp-Companion70724.2026.00041`. The abstract describes lifecycle
enforcement and observability; the access section links only the DOI. The
[IEEE record](https://ieeexplore.ieee.org/document/11627589/) returned a robot
challenge. Its `stamp/stamp.jsp?tp=&arnumber=11627589`,
`stampPDF/getPDF.jsp?tp=&arnumber=11627589` and DOI endpoints did not expose full
text. Author/DOI/preprint searches and SciSpace did not establish an accessible
primary manuscript. This is an access failure, not absence evidence. The user
confirmed they do not have the full text and supplied the abstract. Its exact
user-provided wording and provenance are retained in
`reports/ranathunga_abstract_provenance.json` (retained evidence artifact; not included in the public aggregate release).
Retrieval has stopped; no further paper request is pending.

The available abstract claims lifecycle enforcement; integration of policy
definition, enforcement and observability; governed data-space interoperability;
and evaluation under IID, strongly non-IID and adversarial-client conditions
with improved robustness and negligible overhead. These are attributed abstract
claims, not inspected methods or independently reproduced results. Exact interval,
revoke-regrant, history-completeness and atomic-commit details remain **unknown**.
No absence, equivalence, firstness or novelty verdict follows. The project can
continue with an explicitly incremental protocol/evaluation contribution and this
comparison limitation; full-text retrieval is not an external execution blocker.

### Additional legitimate retrieval attempts

The 2026-11-13 UTC follow-up is recorded in
`reports/ranathunga_retrieval.json` (retained evidence artifact; not included in the public aggregate release). Crossref's public
works API and DOI content negotiation returned bibliographic metadata. The
published Crossref PDF link is designated `similarity-checking`; its staging host
was **not requested** as a public reading route. The normal published IEEE PDF
route did not yield accessible text through the web tool.

OpenAlex record `W7171976457` and the Semantic Scholar DOI record mark the paper
open access/hybrid, with a CC-BY label, but their returned OA links point only to
the DOI. OpenAlex provides no repository location, PDF URL or stored full text in
the retrieved record. These index labels do not establish a successfully read
copy, and the publisher license was not independently verified. They also mean
the access failure must not be described as evidence that the paper is paywalled.
OpenAIRE timed out; the direct DBLP XML request failed certificate validation and
was not retried with TLS verification disabled. SciSpace fetch returned metadata
and abstract, without a readable full-text link.

The official [SMARTCOMP program](https://portale2.unime.it/smartcomp2026/program/)
and [UCC SmartAIDa workshop page](https://www.cs.ucc.ie/smartaida/) list the paper.
Neither inspected page supplies its manuscript. Targeted searches included:

```text
"10.1109/SmartComp-Companion70724.2026.00041"
"Policy-Driven Federated Learning" Ranathunga full text accepted manuscript
"11627589" pdf SMARTCOMP
SMARTCOMP 2026 companion proceedings policy driven Ranathunga
"Policy-Driven Federated Learning" site:sword.cit.ie OR site:sharepoint.com OR site:researchgate.net OR site:zenodo.org
"Ranathunga" "Operationalising" manuscript
"Ranathunga" "Policy-Driven Federated Learning" site:repository.mtu.ie OR site:sword.cit.ie OR site:arxiv.org OR site:research.mtu.ie
SmartAIDa 2026 "Policy-Driven" paper pdf
"0009-0001-8914-7708" manuscript federated learning
```

A normal-browser fallback was attempted using the published IEEE landing URL in
a new hidden in-app tab. The computer-use tool returned exactly `The browser
access host is unavailable`; no IEEE UI, challenge or tab identity was returned.
No CAPTCHA, authentication, access control or certificate warning was bypassed.
No institutional-library connector is exposed in the current tool inventory.
The subsequent user-confirmed abstract-only boundary closes this retrieval effort.
Detailed protocol comparison remains unresolved; no further URL request is needed.

## Current defensible position

The artifact operationalizes an explicit inclusive authorization-history predicate,
guarded single-region manifest publication and independent replay, combining
established usage-control, transaction and audit ideas. Whether this combination
and its matched race/failure evaluation form a publishable contribution remains
unresolved. Do not claim first policy-aware FL, first temporal authorization,
first auditable aggregation, first independent evidence checking, or truthful
training proven cryptographically. The defensible scope is an incremental explicit
protocol and reproducible evaluation under declared assumptions. Qualified P1
evidence can be reported with the abstract-only comparison limitation; detailed
interruption/regrant, stale-read, commit-race, complete-history and crash-recovery
experiments remain necessary for the artifact's own claims. The unread paper is
not an assertion of missing prior mechanisms or an external block on execution.
A negative search cannot prove no equivalent exists.


## November 15 primary-source refresh after protocol freeze

This bibliography refresh changes no study settings, hypotheses, seeds,
allocation, or analysis rule. The [MTU institutional record](https://pure.mtu.ie/en/publications/policy-driven-federated-learning-operationalising-governance-trus/)
and a fresh connected SciSpace extraction still leave Ranathunga et al.'s detailed
methods unverified. Its abstract-only comparison boundary remains explicit.

[George, Mishra and Abidin, PoCoFL (arXiv:2610.03650v1)](https://arxiv.org/html/2610.03650v1)
is additional close prior work. Sections II–V describe policy compliance through
commitments and zero-knowledge proofs. The stated threat model separates
malicious clients and servers, excluding their collusion. Its aggregation
guarantee concerns the admitted record; earlier omissions require additional
submission accountability.

The present artifact should retain its incremental deployment and invariant
scope. It does not establish first policy-aware or verifiable FL, truthful
training, or zero-knowledge privacy. The generic expressibility of its invariant
in PoCoFL has not been ruled out. No PoCoFL reproduction or comparative
performance experiment was added to the frozen matrix. A separately retained literature-refresh record, outside this public package,
preserves access and scope details; no study utility was inspected during that literature review.
