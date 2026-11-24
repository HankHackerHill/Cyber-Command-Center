package redops.breaker_test

import data.redops.breaker
import rego.v1

request(threshold, errors) := {
	"manifest": {"traffic_constraints": {"circuit_breaker_5xx_threshold": threshold}},
	"runtime": {"errors_5xx": errors},
}

test_breaker_allows[name] if {
	some name, pair in {
		"zero failures": [1, 0],
		"one below threshold": [5, 4],
	}
	breaker.allow with input as request(pair[0], pair[1])
}

test_breaker_denies_bad_threshold[value] if {
	some value in [null, true, "5", [], {}, -1, 0, 1.5]
	not breaker.allow with input as request(value, 0)
}

test_breaker_denies_bad_or_tripped_counter[value] if {
	some value in [null, true, "0", [], {}, -1, 0.5, 5, 6]
	not breaker.allow with input as request(5, value)
}

test_breaker_denies_missing_input[name] if {
	some name, invalid in {
		"empty": {},
		"missing manifest": {"runtime": {"errors_5xx": 0}},
		"missing limits": {"manifest": {}, "runtime": {"errors_5xx": 0}},
		"missing threshold": {"manifest": {"traffic_constraints": {}}, "runtime": {"errors_5xx": 0}},
		"missing runtime": {"manifest": {"traffic_constraints": {"circuit_breaker_5xx_threshold": 1}}},
		"missing counter": {"manifest": {"traffic_constraints": {"circuit_breaker_5xx_threshold": 1}}, "runtime": {}},
	}
	not breaker.allow with input as invalid
}
