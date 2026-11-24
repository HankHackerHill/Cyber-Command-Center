# ADR-0011: Deferred Transition Paths (M2 Placeholder)
**Status:** Accepted (tracked debt). POST /engagements/{id}/transition returns 403 TRANSITION_UNAVAILABLE for deferred transitions; engagement state and ledger remain intact. Implemented at 34fcdf7, live-tested.
**Deferred scope:** The transition-graph edges advancing an engagement through assessment progression toward active validation.
**Resolution requirement:** Must be resolved before MS1 integration sign-off (signed engagement reaching CONTROLLED_VALIDATION through the governed proxy). Resolution via fresh session or lane-exception ADR.
**Rationale:** Human-owner directive to continue the build without stopping. The placeholder fails safe (deny-by-default), is documented in the API, and preserves all invariants.
