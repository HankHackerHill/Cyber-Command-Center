package redops.rate

import rego.v1

default allow := false

# The caller supplies a single bucket snapshot before reserving one token.
allow if {
	limits := input.manifest.traffic_constraints
	positive_integer(limits.max_requests_per_second)
	positive_integer(limits.max_concurrent_workers)

	tokens := input.runtime.tokens
	is_number(tokens)
	tokens >= 1
	tokens <= limits.max_requests_per_second

	workers := input.runtime.active_workers
	is_number(workers)
	workers == floor(workers)
	workers >= 0
	workers < limits.max_concurrent_workers
}

positive_integer(value) if {
	is_number(value)
	value == floor(value)
	value > 0
}
