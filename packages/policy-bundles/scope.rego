package redops.scope

import data.redops.window.timestamp_ns
import rego.v1

default allow := false

allow if {
	r := input.request
	object.keys(r) == {"host", "ip", "method", "path", "ts"}
	is_number(timestamp_ns(r.ts))

	scope := input.manifest.scope_boundaries
	regex.match("^[A-Z][A-Z0-9-]*$", r.method)
	is_array(scope.allowed_http_methods)
	r.method in scope.allowed_http_methods

	is_string(r.ip)
	not contains(r.ip, "/")
	is_array(scope.allowed_cidrs)
	some cidr in scope.allowed_cidrs
	net.cidr_contains(cidr, r.ip)

	is_array(scope.allowed_identifiers)
	some identifier in scope.allowed_identifiers
	host_matches(r, identifier)

	valid_path(r.path)
	is_array(scope.excluded_paths)
	every exclusion in scope.excluded_paths {
		valid_path(exclusion)
		not excluded(r.path, exclusion)
	}
}

# DNS names are ASCII wire names. Accept one final root dot, and exclude
# numeric TLDs so an alternate spelling of an IP cannot match a DNS wildcard.
dns_name(raw) := lower(name) if {
	name := trim_suffix(raw, ".")
	count(name) <= 253
	regex.match(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`, name)
}

# An IP literal must also identify the address evaluated by the CIDR check.
host_matches(r, identifier) if {
	lower(r.host) == lower(r.ip)
	lower(r.host) == lower(identifier)
}

host_matches(r, identifier) if dns_name(r.host) == dns_name(identifier)

# A leading "*." represents exactly one DNS label. Bare suffixes, nested
# subdomains, arbitrary globs, and cloud resource identifiers cannot match.
host_matches(r, identifier) if {
	startswith(identifier, "*.")
	base := dns_name(trim_prefix(identifier, "*."))
	name := dns_name(r.host)
	labels := split(name, ".")
	count(labels) == count(split(base, ".")) + 1
	endswith(name, concat("", [".", base]))
}

# Match exclusions on an unambiguous absolute path. Reject encodings, query
# strings, path parameters, separators other than "/", and relative segments.
valid_path(path) if {
	regex.match(`^/([A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*$`, path)
	segments := split(path, "/")
	not "." in segments
	not ".." in segments
}

excluded(path, exclusion) if path == trim_suffix(exclusion, "/")

excluded(path, exclusion) if startswith(path, concat("", [trim_suffix(exclusion, "/"), "/"]))
