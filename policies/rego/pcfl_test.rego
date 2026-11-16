package pcfl_test

import rego.v1

stable := data.pcfl_testdata.traces[0]

test_sixteen_oracle_gold_traces if {
    count(data.pcfl_testdata.traces) == 16
    every trace in data.pcfl_testdata.traces {
        actual := data.pcfl.decision with input as {"events": trace.events, "query": trace.query}
        actual.valid == trace.expected_valid
    }
}

test_missing_metadata_denies if {
    not data.pcfl.valid with input as {"events": stable.events, "query": stable.query} with data.pcfl_meta as {}
}

test_missing_query_denies if {
    actual := data.pcfl.decision with input as {"events": stable.events}
    actual.valid == false
}

test_unknown_event_order_denies if {
    actual := data.pcfl.decision with input as {"events": [{"order": "future"}], "query": stable.query}
    actual.valid == false
}

test_float_order_is_not_authority_integer if {
    event := object.union(stable.events[0], {"order": 1.0})
    actual := data.pcfl.decision with input as {"events": [event], "query": stable.query}
    actual.valid == false
}

test_duplicate_global_order_denies if {
    event := object.union(stable.events[0], {"event_id": "other", "org_id": "org_02"})
    actual := data.pcfl.decision with input as {"events": [stable.events[0], event], "query": stable.query}
    actual.valid == false
}

test_missing_initial_epoch_denies if {
    event := object.union(stable.events[0], {"epoch": 2})
    actual := data.pcfl.decision with input as {"events": [event], "query": stable.query}
    actual.valid == false
}

test_unknown_future_payload_does_not_change_past_commit if {
    event := {"order": stable.query.commit_order + 1, "kind": null}
    actual := data.pcfl.decision with input as {"events": array.concat(stable.events, [event]), "query": stable.query}
    actual.valid == true
}

test_all_three_actions_required if {
    query := object.union(stable.query, {"actions": ["train", "aggregate"]})
    actual := data.pcfl.decision with input as {"events": stable.events, "query": query}
    actual.valid == false
}
