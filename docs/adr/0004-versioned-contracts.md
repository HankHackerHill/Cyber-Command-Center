# ADR-0004: Versioned Pydantic Contracts, No Ad-Hoc JSON
**Status:** Accepted — All inter-service messages are frozen Pydantic v2
models with extra='forbid'. TS types are generated, never hand-written.
Prevents contract drift between parallel build lanes.
