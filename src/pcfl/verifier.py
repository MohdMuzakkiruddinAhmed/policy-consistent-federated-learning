"""Independent audit-chain integrity checker; caller supplies a protected anchor.

Integrity alone does not establish semantic policy correctness or confidentiality.
"""

import hashlib
import json


def verify_chain(records: list[dict], anchor: dict) -> bool:
    previous = "0" * 64
    seen_updates = set()
    try:
        if type(anchor["count"]) is not int or anchor["count"] != len(records):
            return False
        for number, record in enumerate(records, 1):
            if set(record) != {"sequence", "prev_hash", "payload", "event_hash"}:
                return False
            if (type(record["sequence"]) is not int or record["sequence"] != number
                    or record["prev_hash"] != previous):
                return False
            payload = record["payload"]
            if payload["update_id"] in seen_updates:
                return False
            seen_updates.add(payload["update_id"])
            content = {"sequence": number, "prev_hash": previous, "payload": payload}
            raw = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            previous = hashlib.sha256(raw).hexdigest()
            if previous != record["event_hash"]:
                return False
        return anchor["head"] == previous
    except (KeyError, TypeError, ValueError):
        return False
