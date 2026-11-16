# PCFL invariants and proof obligations

Protocol draft version: `0.1.0`. Logical order is authority assigned; timestamps alone do not establish causality. The authorized lifecycle begins when the client acknowledges its binding task authorization and ends when the manifest pointer transaction commits. For each required action/purpose, evaluate the state at the start and every relevant subsequent transition through the commit boundary. Unknown or incomplete history is indeterminate and fails closed.

## INV-1 — Continuous authorization

```text
Included(update, published_model)
    implies HistoryValid(update, [start_order, commit_order])
```

Identity, task, organization, round and purpose must match the acknowledged authorization. Deny overrides; absence of an applicable allow denies. A relevant denial at any point invalidates the original lifecycle permanently, including revoke–regrant. A fresh task authorization can begin a later valid lifecycle. Changes outside the requested purpose/action need not invalidate it. Expiry requires an explicit `EXPIRE` event.

Proof obligations: complete authoritative history; correct semantics; start binding; correct update membership; guarded commit preserves validated state until publication. Tests cover stable, start denial, mid-round revoke, regrant, purpose change, explicit expiry, unrelated changes and missing histories.

## INV-2 — Atomic publication consistency

```text
Publish(manifest) occurs only in one atomic transaction containing
guards for every included organization's observed policy epoch,
the parent/run/round state, the manifest pointer, and mandatory
accepted-outcome/audit metadata.
```

Policy mutations atomically update current state/epoch and append immutable history. Candidate bytes are staged and verified first but remain unpublished. A conflicting epoch forces fresh histories, eligibility recomputation, reaggregation and restaging as needed. Retrying an unchanged stale candidate is forbidden. Readers resolve only committed pointers. Tests cover both revoke/commit orderings, two publishers, crash boundaries and failed audit persistence.

## INV-3 — Final decision provenance

```text
Every unique attempted update has one attributable final outcome
with reconstructible evidence, or the attempt fails closed and
remains explicitly incomplete until recovery resolves it.
```

Identical retries reuse the outcome. Conflicting reuse of an update ID must never overwrite the original record or create an extra inclusion. A successful acceptance links update digest, policy version/history, rule hash, reason, manifest and commit order. Rejections also require idempotent evidence. Audit verification checks completeness separately from chain/digest integrity; a separately retained anchor is required for the modeled tampering claims.

## INV-4 — Prospective revocation

```text
A policy change prevents invalid future incorporation.
It does not rewrite a model already committed before that change.
```

Test a successful publication followed by revocation: the prior model remains published until a later valid revision, and the earlier contribution is not retrospectively labeled invalid. No federated-unlearning claim follows.

## Gate interpretation

Local reference checks are executable specification evidence only. G2 requires oracle fixtures and policy semantics; G3 additionally requires the actual guarded publication implementation; G5 additionally requires independent verifier and durability evidence. G1 and G4/G6 require deployment/comparative research evidence. No gate passes merely because this specification exists.
