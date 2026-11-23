# ADR-0009 — Task dispatch modes

**Status: Accepted**

`TaskMode` has three values: `MANUAL_ONLY`, `AI_AUTONOMOUS_PASSIVE`, and
`AI_PROPOSED_HITL_GATED`. The M5 supervisor and M10 task board use the
task's mode to distinguish manual work, autonomous passive work, and an AI
proposal that requires a human dispatch decision.

`blast_radius` determines approval depth. A task's dispatch mode and its
plan's approval depth are independent.
