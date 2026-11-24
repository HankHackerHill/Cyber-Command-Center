package redops.window_test

import data.redops.window
import rego.v1

baseline := {
	"not_before": "2026-12-01T08:00:00Z",
	"not_after": "2026-12-10T08:00:00Z",
	"allowed_days_utc": ["MON", "TUE", "WED", "THU", "FRI"],
}

inside := "2026-12-02T12:00:00Z"

# Apply each case independently to the client and service clock.
test_timestamp_bounds[scenario][clock] if {
	cases := {
		"inclusive start": ["2026-12-01T08:00:00Z", true],
		"before start": ["2026-12-01T07:59:59.999999999Z", false],
		"last nanosecond": ["2026-12-10T07:59:59.999999999Z", true],
		"exclusive end": ["2026-12-10T08:00:00Z", false],
		"after end": ["2026-12-10T08:00:00.000000001Z", false],
		"UTC Friday local Saturday": ["2026-12-05T00:01:00+02:00", true],
		"UTC Saturday local Friday": ["2026-12-04T23:59:00-02:00", false],
		"different offsets same start": ["2026-12-01T03:00:00-05:00", true],
		"invalid date": ["2026-11-31T12:00:00Z", false],
		"absent zone": ["2026-12-02T12:00:00", false],
		"invalid offset": ["2026-12-02T12:00:00+00:90", false],
		"subnanosecond": ["2026-12-02T12:00:00.0000000001Z", false],
		"null": [null, false],
		"numeric": [12345, false],
	}
	some scenario, example in cases
	some clock, pair in {"request": [example[0], inside], "now": [inside, example[0]]}
	doc := {"manifest": {"valid_window": baseline}, "request": {"ts": pair[0]}, "now": pair[1]}
	decision := window.allow with input as doc
	decision == example[1]
}

test_invalid_window[scenario] if {
	cases := {
		"missing open": object.remove(baseline, {"not_before"}),
		"missing close": object.remove(baseline, {"not_after"}),
		"missing weekdays": object.remove(baseline, {"allowed_days_utc"}),
		"malformed bound": object.union(baseline, {"not_before": "never"}),
		"reversed interval": object.union(baseline, {"not_after": "2026-11-01T08:00:00Z"}),
		"empty interval": object.union(baseline, {"not_after": baseline.not_before}),
		"empty weekdays": object.union(baseline, {"allowed_days_utc": []}),
		"invalid weekday included": object.union(baseline, {"allowed_days_utc": ["WED", "BAD"]}),
		"invalid weekdays type": object.union(baseline, {"allowed_days_utc": "WED"}),
	}
	some scenario, invalid in cases
	doc := {"manifest": {"valid_window": invalid}, "request": {"ts": inside}, "now": inside}
	not window.allow with input as doc
}

test_missing_input[scenario] if {
	valid := {"manifest": {"valid_window": baseline}, "request": {"ts": inside}, "now": inside}
	some scenario, doc in {
		"missing server clock": object.remove(valid, {"now"}),
		"missing request ts": {"manifest": valid.manifest, "request": {}, "now": inside},
		"missing manifest": object.remove(valid, {"manifest"}),
	}
	not window.allow with input as doc
}
