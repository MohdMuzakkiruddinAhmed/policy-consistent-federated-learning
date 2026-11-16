package system.log

import rego.v1

# The authority retains complete immutable history for replay. Console traces
# retain the history digest and decision ID without repeating the full history.
mask contains "/input/events"
