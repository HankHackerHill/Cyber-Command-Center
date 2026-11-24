package redops.scope_test

import data.redops.scope
import rego.v1

# Fields from the staged synthetic RoE used by the scope decision.
boundaries := {
	"allowed_cidrs": ["198.51.100.0/24"],
	"allowed_identifiers": ["api.staging.example.com", "web-app.staging.example.internal", "arn:aws:iam::123456789012:role/*"],
	"excluded_paths": ["/v1/billing/charge", "/admin/reset-tenant"],
	"allowed_http_methods": ["GET", "HEAD", "OPTIONS", "POST"],
}

request := {"host": "api.staging.example.com", "ip": "198.51.100.42", "method": "GET", "path": "/v1/users/usr_102", "ts": "2026-12-01T09:15:22.481Z"}

decision(scope_boundaries, req) := result if {
	document := {"manifest": {"scope_boundaries": scope_boundaries}, "request": req}
	result := scope.allow with input as document
}

test_fixture_scope if {
	every row in [
		[{}, true],
		[{"host": "WEB-app.STAGING.EXAMPLE.INTERNAL.", "method": "POST", "path": "/v1/reports"}, true],
		[{"host": "unlisted.example.com"}, false],
		[{"host": "arn:aws:iam::123456789012:role/*"}, false],
		[{"host": "api.staging.example.com:443"}, false],
		[{"host": "api.staging.example.com.."}, false],
		[{"ip": "192.0.2.1"}, false],
		[{"ip": "198.51.100.7/32"}, false],
		[{"ip": "bogus"}, false],
		[{"method": "DELETE"}, false],
		[{"method": "get"}, false],
		[{"path": "/admin/reset-tenant", "method": "POST"}, false],
		[{"path": "/v1/billing/charge/confirm"}, false],
		[{"path": "/v1/billing/charges"}, true],
		[{"path": "/"}, true],
		[{"path": "/v1/reports/"}, true],
	] {
		decision(boundaries, object.union(request, row[0])) == row[1]
	}
}

test_deny_ambiguous_paths if {
	every path in ["", "v1/users", "//admin", "/x//y", "/x/../admin", "/./admin", "/a/%2e", "/a%2fb", "/%252e", "/a?x=1", "/a#b", "/a;b", "/a\\b", "/a\nb"] {
		not decision(boundaries, object.union(request, {"path": path}))
	}
}

test_exclusions_apply_with_trailing_slash_or_at_root if {
	every row in [
		["/admin/", "/admin", false],
		["/admin/", "/admin/child", false],
		["/admin/", "/admins", true],
		["/", "/anything", false],
		["/", "/", false],
		["admin", "/v1/reports", false],
	] {
		decision(object.union(boundaries, {"excluded_paths": [row[0]]}), object.union(request, {"path": row[1]})) == row[2]
	}
}

test_dns_wildcard_matches_one_label if {
	b := object.union(boundaries, {"allowed_identifiers": ["*.Staging.Example.com"]})
	every row in [
		["www.staging.example.com.", true],
		["two.names.staging.example.com", false],
		["staging.example.com", false],
		["api.badstaging.example.com", false],
		["-bad.staging.example.com", false],
		["evil@api.staging.example.com", false],
	] {
		decision(b, object.union(request, {"host": row[0]})) == row[1]
	}
}

test_dns_name_length_boundary if {
	label := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk"
	at_limit := concat(".", [label, label, label, substring(label, 0, 61)])
	over_limit := concat("", [at_limit, "a"])
	count(at_limit) == 253
	count(over_limit) == 254
	b := object.union(boundaries, {"allowed_identifiers": [at_limit, over_limit]})
	decision(b, object.union(request, {"host": at_limit}))
	decision(b, object.union(request, {"host": concat("", [at_limit, "."])}))
	not decision(b, object.union(request, {"host": over_limit}))
}

test_ip_identifiers if {
	b := object.union(boundaries, {
		"allowed_cidrs": ["198.51.100.0/24", "2001:db8::/32"],
		"allowed_identifiers": ["198.51.100.1", "2001:db8::1", "*.51.100.2"],
	})
	every row in [
		["198.51.100.1", "198.51.100.1", true],
		["198.51.100.1", "198.51.100.2", false],
		["198.51.100.2", "198.51.100.2", false],
		["2001:DB8::1", "2001:db8::1", true],
		["2001:db8::1", "2001:db8::2", false],
	] {
		decision(b, object.union(request, {"host": row[0], "ip": row[1]})) == row[2]
	}
}

test_deny_malformed_fields if {
	every field in object.keys(request) {
		not decision(boundaries, object.remove(request, [field]))
		not decision(boundaries, object.union(request, {field: null}))
	}
	every field in object.keys(boundaries) {
		not decision(object.remove(boundaries, [field]), request)
		not decision(object.union(boundaries, {field: {}}), request)
	}
	not decision(boundaries, object.union(request, {"extra": true}))
	every ts in ["not a timestamp", "2026-12-01T09:15:22+01:60", "2026-12-01T9:15:22Z", "2026-12-01T09:15:22,481Z"] {
		not decision(boundaries, object.union(request, {"ts": ts}))
	}
	not decision(boundaries, [])
}
