# Contributing

Thanks for your interest in this workspace. It's a Sui-ecosystem monorepo whose
centrepiece is a machine-checked FIPS-205 SLH-DSA-SHA2-128s verifier (Move +
TypeScript + a Lean 4 formal spec). A few conventions keep it coherent.

## Setup

```bash
pnpm install          # workspaces; never npm/yarn
pnpm setup            # optional: installs Sui + Walrus CLIs, configures testnet
```

Use **pnpm** exclusively (the repo pins `pnpm@10.x` via the `packageManager`
field). Cross-package imports go through `@sui-gen/<pkg>`, never relative paths
across package boundaries. See `CLAUDE.md` for the full house rules.

## Before you push

CI runs three jobs (`.github/workflows/ci.yml`); reproduce them locally:

```bash
pnpm lint            # biome check . — must be clean
pnpm typecheck       # tsc --noEmit across packages
pnpm build
pnpm test            # vitest
pnpm move:test       # sui move test across move/*
pnpm verify          # the full FIPS-205 verification pipeline (see below)
```

A green `pnpm lint && pnpm typecheck && pnpm build && pnpm test` is the bar for
the TypeScript job; `pnpm verify` is the bar for the formal-verification job.

## The formal-verification project (`proofs/`)

`pnpm verify` runs, in order: `lake build` (all Lean proofs), the NIST ACVP
exe cross-check, the noble + fixture + three-way differentials, and the
spec-vs-100%-bytecode differential. If you touch:

- **the Lean spec** (`proofs/Fips205/*.lean`) — keep it a faithful, dependency-free
  transcription of FIPS 205; no Mathlib (the spec *is* the trusted base).
- **the Move source** (`move/slh_dsa_128s/sources/sha2_128s.move`) — regenerate
  KATs (`gen-lean-kat.ts`, `gen-lean-nist-kat.ts`) and re-run `pnpm verify`. If
  you change a function's compiled bytecode, update its `Move/*Real.lean`
  encoding (it's pinned opcode-for-opcode to `sui move disassemble`).
- **the TS reference** (`packages/pqc/src/*-ref.ts`) — the three-way
  differential must still show zero mismatches.

See [`VERIFICATION.md`](./VERIFICATION.md) and [`proofs/README.md`](./proofs/README.md)
for the full picture of what's machine-checked vs human-reviewed.

## Commits & PRs

- Small, focused commits with imperative subject lines.
- Don't commit secrets, `sui_config/`, `keystore.json`, or build artefacts
  (`.gitignore` covers these, plus Lean's `.lake/` and Move `build/`).
- Don't pin Move dependencies to `framework/main` — use `framework/mainnet`.
- Keep docs in sync with code; broken internal links fail review.

## License

By contributing you agree your contributions are licensed under the
[MIT License](./LICENSE).
