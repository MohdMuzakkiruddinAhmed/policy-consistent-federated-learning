package pcfl

import rego.v1

# Full replacement-state histories; no policy data is cached inside OPA.
protocol_revision := "pcfl-interval-v1"
organizations := {"org_01", "org_02", "org_03", "org_04", "org_05", "org_06", "org_07", "org_08"}
lifecycle_actions := {"train", "submit_update", "aggregate"}
event_kinds := {"GRANT", "CHANGE", "REVOKE", "EXPIRE"}

positive_integer(value) if {
    is_number(value)
    value > 0
    regex.match("^[0-9]+$", json.marshal(value))
}

nonblank(value) if {
    is_string(value)
    trim_space(value) != ""
}

valid_query if {
    is_object(input.query)
    input.query.org_id in organizations
    nonblank(input.query.purpose)
    positive_integer(input.query.start_order)
    positive_integer(input.query.commit_order)
    input.query.start_order <= input.query.commit_order
    is_array(input.query.actions)
    count(input.query.actions) == 3
    {action | some action in input.query.actions} == lifecycle_actions
}

known_order(event) if {
    is_object(event)
    positive_integer(event.order)
}

valid_rule(rule) if {
    is_object(rule)
    nonblank(rule.purpose)
    rule.action in lifecycle_actions
    rule.effect in {"allow", "deny"}
}

valid_state_rules(event) if {
    event.kind in {"REVOKE", "EXPIRE"}
    count(event.rules) == 0
}

valid_state_rules(event) if {
    event.kind in {"GRANT", "CHANGE"}
}

valid_event(event) if {
    event.org_id in organizations
    nonblank(event.event_id)
    positive_integer(event.epoch)
    event.kind in event_kinds
    is_array(event.rules)
    valid_state_rules(event)
    every rule in event.rules { valid_rule(rule) }
}

past_events := [event |
    some event in input.events
    event.order <= input.query.commit_order
]

valid_history if {
    is_array(input.events)
    every event in input.events { known_order(event) }
    every event in past_events { valid_event(event) }
    count({event.event_id | some event in past_events}) == count(past_events)
    count({event.order | some event in past_events}) == count(past_events)
    every org in organizations {
        ordered := sort([[event.order, event.epoch] |
            some event in past_events
            event.org_id == org
        ])
        every index, entry in ordered {
            entry[1] == index + 1
        }
    }
}

valid_input if {
    is_object(input)
    valid_query
    valid_history
}

metadata_valid if {
    data.pcfl_meta.protocol_revision == protocol_revision
    regex.match("^[0-9a-f]{64}$", data.pcfl_meta.policy_sha256)
}

own_events := [event | some event in past_events; event.org_id == input.query.org_id]
start_orders := {event.order | some event in own_events; event.order <= input.query.start_order}

has_start if count(start_orders) > 0

start_state := event if {
    some event in own_events
    event.order == max(start_orders)
}

matching_allow(rules, action) if {
    some rule in rules
    rule.purpose == input.query.purpose
    rule.action == action
    rule.effect == "allow"
}

matching_deny(rules, action) if {
    some rule in rules
    rule.purpose == input.query.purpose
    rule.action == action
    rule.effect == "deny"
}

permits(state) if {
    every action in lifecycle_actions {
        matching_allow(state.rules, action)
        not matching_deny(state.rules, action)
    }
}

invalid_orders contains input.query.start_order if {
    has_start
    not permits(start_state)
}

invalid_orders contains event.order if {
    some event in own_events
    event.order > input.query.start_order
    event.order <= input.query.commit_order
    not permits(event)
}

default valid := false
valid if {
    metadata_valid
    valid_input
    has_start
    count(invalid_orders) == 0
}

reason := "policy_metadata_missing" if not metadata_valid
else := "malformed_history_or_query" if not valid_input
else := "missing_start_policy" if not has_start
else := "authorization_interrupted" if count(invalid_orders) > 0
else := "continuous_authorization"

default invalid_order := null
invalid_order := min(invalid_orders) if {
    valid_input
    has_start
    count(invalid_orders) > 0
}

decision := {
    "valid": valid,
    "reason": reason,
    "invalid_order": invalid_order,
    "rule_hash": data.pcfl_meta.policy_sha256,
    "protocol_revision": protocol_revision,
    "query": object.get(input, "query", null),
    "request_binding": object.get(input, "request_binding", ""),
    "request_hash": object.get(input, "request_hash", ""),
    "history_digest": object.get(input, "history_digest", ""),
}
