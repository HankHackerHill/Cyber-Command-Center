package redops.window

import rego.v1

default allow := false

weekdays := {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}

# OPA compares UTC instants at nanosecond precision. Reject malformed offsets
# and excess precision before parsing so neither can change a boundary decision.
timestamp_ns(value) := ns if {
	is_string(value)
	wire := upper(value)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`, wire)
	ns := time.parse_rfc3339_ns(wire)
}

allow if {
	window := input.manifest.valid_window
	start := timestamp_ns(window.not_before)
	end := timestamp_ns(window.not_after)
	is_array(window.allowed_days_utc)
	every day in window.allowed_days_utc {
		day in weekdays
	}

	# The caller supplies request.ts. The service supplies now independently.
	instants := [timestamp_ns(input.request.ts), timestamp_ns(input.now)]
	every instant in instants {
		instant >= start
		instant < end
		weekday := time.weekday([instant, "UTC"])
		upper(substring(weekday, 0, 3)) in window.allowed_days_utc
	}
}
