package redops.breaker

import rego.v1

default allow := false

allow if {
	threshold := input.manifest.traffic_constraints.circuit_breaker_5xx_threshold
	is_number(threshold)
	threshold == floor(threshold)
	threshold > 0

	errors := input.runtime.errors_5xx
	is_number(errors)
	errors == floor(errors)
	errors >= 0
	errors < threshold
}
