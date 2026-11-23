# ADR-0001: Monorepo Layout and Package Boundaries
**Status:** Accepted — apps/ (one dir per service, one owning model each),
packages/contracts-py (single source of truth, frozen after MS0),
packages/contracts-ts (generated, never hand-edited),
packages/policy-bundles, db/, docs/, tests/. Toolchain: pnpm + Nx,
uv workspaces, Cargo, Atlas. Supports the platform's authorization model:
contracts and policy packages are the enforcement surface for signed RoE.
