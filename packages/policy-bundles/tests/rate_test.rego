package redops.rate_test

import data.redops.rate
import rego.v1

limits := {"max_requests_per_second": 4, "max_concurrent_workers": 2}
snapshot := {"tokens": 1, "active_workers": 0}

request(bounds, runtime) := {"manifest": {"traffic_constraints": bounds}, "runtime": runtime}

test_rate_allows[name] if {
	some name, runtime in {
		"one token and no workers": snapshot,
		"fractional refill above one": {"tokens": 1.5, "active_workers": 0},
		"full bucket and final free worker slot": {"tokens": 4, "active_workers": 1},
	}
	rate.allow with input as request(limits, runtime)
}

test_rate_denies_invalid_runtime[field][value] if {
	some field, values in {
		"tokens": [null, true, "1", [], {}, -1, 0, 0.99, 4.01],
		"active_workers": [null, true, "0", [], {}, -1, 0.5, 2, 3],
	}
	some value in values
	runtime := object.union(snapshot, {field: value})
	not rate.allow with input as request(limits, runtime)
}

test_rate_denies_invalid_limit[field][value] if {
	some field in ["max_requests_per_second", "max_concurrent_workers"]
	some value in [null, true, "2", [], {}, -1, 0, 1.5]
	bounds := object.union(limits, {field: value})
	not rate.allow with input as request(bounds, snapshot)
}

test_rate_denies_missing_runtime_field[field] if {
	some field in object.keys(snapshot)
	not rate.allow with input as request(limits, object.remove(snapshot, {field}))
}

test_rate_denies_missing_limit[field] if {
	some field in object.keys(limits)
	not rate.allow with input as request(object.remove(limits, {field}), snapshot)
}

test_rate_denies_missing_input_sections[name] if {
	some name, invalid in {
		"empty": {},
		"missing manifest": {"runtime": snapshot},
		"missing limits": {"manifest": {}, "runtime": snapshot},
		"missing runtime": {"manifest": {"traffic_constraints": limits}},
	}
	not rate.allow with input as invalid
}
