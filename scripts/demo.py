"""Run a synthetic local race trace. No cloud services or patient data are used."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.contracts import ACTIONS, ModelUpdate, ORGANIZATIONS
from pcfl.oracle import evaluate_interval
from pcfl.state_model import ConditionalConflict, LocalProtocolModel
from pcfl.verifier import verify_chain


def run_demo() -> dict:
    model = LocalProtocolModel()
    rules = [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS]
    updates = []
    for i, org in enumerate(ORGANIZATIONS, 1):
        model.mutate(org, "GRANT", rules)
        task = model.authorize(org, "readmission", "demo-round")
        update = ModelUpdate.create(f"demo-update-{i}", task, i * 10, (float(i), float(i * 2)))
        model.present(update, org)
        updates.append(update)
    stale = model.prepare("demo-round")
    model.mutate("org_01", "REVOKE", [])
    blocked = False
    try:
        model.commit(stale)
    except ConditionalConflict:
        blocked = True
    if not blocked or model.read_published() is not None:
        raise AssertionError("stale candidate must not be published")
    fresh = model.prepare("demo-round")
    manifest = model.commit(fresh)
    evidence = model.evidence()
    presented = []
    for update in updates:
        query = {"org_id": update.task.org_id, "purpose": update.task.purpose,
                 "start_order": update.task.start_order, "commit_order": manifest["commit_order"],
                 "actions": list(ACTIONS)}
        decision = evaluate_interval(evidence["policy_events"], query)
        presented.append({"update_id": update.update_id, "query": query, "oracle": decision,
                          "included": update.update_id in manifest["update_ids"]})
    invalid = [p for p in presented if not p["oracle"]["valid"]]
    violations = [p for p in invalid if p["included"]]
    chain_valid = verify_chain(evidence["audit"], evidence["anchor"])
    if violations or len(invalid) != 1 or not chain_valid:
        raise AssertionError("local oracle/audit validation failed")
    # Raw authorization nonces are not exported even though all identities are synthetic.
    for task in evidence["tasks"]:
        task.pop("nonce", None)
    return {"schema_version": "0.1.0", "kind": "local_specification_demo",
            "publication_backend": "in_memory_state_model", "is_research_result": False,
            "summary": {"stale_candidate_blocked": blocked, "presented_unique_updates": len(presented),
                        "oracle_invalid_presented": len(invalid), "invalid_incorporations": len(violations),
                        "accepted_unique_updates": len(manifest["update_ids"]),
                        "rejected_unique_updates": sum(d["outcome"] == "rejected" for d in evidence["decisions"].values()),
                        "audit_chain_valid_against_supplied_anchor": chain_valid},
            "presented_updates": presented, "evidence": evidence}


def main():
    result = run_demo()
    destination = ROOT / "results/local/latest/demo.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))
    print(f"Saved local evidence: {destination.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
