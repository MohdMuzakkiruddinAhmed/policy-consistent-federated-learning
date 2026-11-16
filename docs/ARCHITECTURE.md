# Protocol architecture

Each authenticated client receives a task bound to organization, purpose, round, nonce and schema. Updates additionally bind their content digest. An authority maintains immutable, contiguously ordered policy history.

P1 checks dispatch, receipt and the inclusive lifecycle through publication. The required actions are train, submit_update and aggregate. A relevant denial invalidates the original task even after regrant. Missing history fails closed; expiry is an explicit authority event rather than a hard wall-clock guarantee.

The coordinator forms a sample-weighted FedAvg candidate from eligible updates and stages it as a versioned S3 object. It verifies the exact object version, digest, size and availability before publication.

A single DynamoDB transaction guards the global authority sequence, contributing epochs, parent pointer, membership generation, pending-update finality and audit state. It advances the committed pointer and records outcomes and bindings. That transition is the release linearization point; S3 and DynamoDB are separate services, not one cross-service transaction.

Conflicts require refreshed histories and recomputation. Durable operation fingerprints resolve ambiguous responses, and duplicate delivery cannot contribute twice. Independent checking reconstructs eligibility, aggregation, version binding and audit consistency.

The experiment assumes correct identity mapping, controlled policy writers, trusted enforcement/order services, durable staged objects and separately protected audit commitments. A protected reference point is necessary for tamper evidence. The protocol neither proves truthful client training nor removes contributions from models already committed.
