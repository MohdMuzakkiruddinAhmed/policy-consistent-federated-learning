package system.authz

import rego.v1

default allow := false

# The native TLS listener verifies the issuing CA. This policy limits a trusted
# coordinator certificate to decision evaluation, without policy/data writes.
allow if {
    input.identity == "CN=pcfl-coordinator"
    input.method == "POST"
    input.path == ["v1", "data", "pcfl", "decision"]
}
