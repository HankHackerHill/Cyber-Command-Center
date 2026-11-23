# ADR-0003: Scoped Proxy in Rust, Deny-by-Default Egress
**Status:** Accepted — All target traffic flows through a Rust hyper
proxy. Default posture is deny; every request is policy-checked,
attributed, rate-limited, and evidence-logged. Killswitch flips the proxy
to deny-all in O(1).
