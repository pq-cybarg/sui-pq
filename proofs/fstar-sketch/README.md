# F\* port skeleton — what verified extraction looks like

This directory exists to make the path B option (F\*/KaRaMeL/CompCert) of
`proofs/EXTRACTION.md` concrete rather than abstract. Nothing here is
expected to compile inside this workspace — the F\*/KaRaMeL/CompCert
toolchain isn't installed locally and isn't needed for our current
verification ambitions.

## Why F\*, not just keep using Lean

Lean's native compiler produces C that depends on Lean's runtime:
heap-allocated `lean_object*` values, reference counting, an allocator,
compiler-specific pragmas, `extern "C"` for linking. We can confirm this
by inspecting `.lake/build/ir/Fips205/Verify.c`:

```c
#include <lean/lean.h>           // <-- Lean runtime header
#pragma clang diagnostic ignored ...
#pragma GCC diagnostic ignored ...
LEAN_EXPORT lean_object* lp_fips205_Fips205_Verify_verify(...);
                                  // <-- everything is lean_object*
extern "C" { ... }                // <-- not even C, this is C++ linkage
```

CompCert accepts a strict subset of C99 with no GCC/Clang extensions, no
`extern "C"`, no runtime dependencies. Lean's output is fundamentally
incompatible. To get an end-to-end verified path from spec to native, we
need a different extractor — one designed to produce CompCert-compatible C.

F\* + KaRaMeL is the production-grade tool that does exactly this. HACL\*
uses it. Project Everest uses it. Mozilla's NSS, Microsoft's Quick TLS, and
many others ship the resulting verified C.

## What the port looks like concretely

`Fips205.Bytes.fst` shows the F\* equivalent of `Fips205/Bytes.lean`.
Key differences from the Lean version:

1. **Buffer-based, not value-based.** The Lean `slice` returns a fresh
   `ByteArray`; the F\* version takes a destination buffer (`out`) and
   writes into it. This avoids malloc, which KaRaMeL forbids in extracted
   code.

2. **Effects are explicit.** `ST.Stack unit` (read: "stateful, stack-only,
   no heap") makes the side-effect explicit in the type. Stack-only is
   the most restrictive effect tier; KaRaMeL extracts it to plain C with
   no allocation.

3. **Pre- and post-conditions in types.** Functions carry their proof
   obligations as part of the signature (`requires`, `ensures`). F\*'s
   SMT solver (Z3) discharges most of these automatically; manual proof
   obligations only arise where the math gets non-trivial.

4. **Refinement types replace ad-hoc checks.** Where Lean uses runtime
   bounds checks (`if i < arr.size then ...`), F\* uses refinement types
   (`i: U32.t { U32.v i < B.length buf }`) so the check is moved to the
   type system. Extracted C has no runtime check; CompCert proves the
   absence of out-of-bounds at compile time.

## Estimated porting effort

| Module | Lean LOC | Est. F\* LOC | Difficulty |
| --- | ---: | ---: | --- |
| `Params.lean` | 65 | ~80 | Easy (just constants) |
| `Bytes.lean` | 80 | ~150 | Easy (byte primitives) |
| `Adrs.lean` | 50 | ~120 | Easy (struct → buffer layout) |
| `Sha256.lean` | 135 | reuse HACL\* | **Zero** (HACL\* ships verified SHA-256) |
| `Thash.lean` | 50 | ~120 | Easy (composition) |
| `Wots.lean` | 75 | ~180 | Medium (loop invariants) |
| `Verify.lean` | 125 | ~300 | Medium (multiple nested loops) |
| KATs / equivalence proofs | — | — | trivial port |
| Total | ~580 | ~950 | — |

**Total estimated effort:** 4–8 person-months for someone fluent in F\*.
The bulk of the time goes into proving the loop invariants for the
hypertree walk and FORS verification; once those are in place,
extraction to verified C is fully automatic.

## What you get at the end

A C source file (`fips205_verify.c`) plus a CompCert proof object
showing it compiles to a binary that:

1. Computes the FIPS-205 SLH-DSA-SHA2-128s verify function exactly.
2. Has no undefined behaviour, no buffer overflows, no allocation.
3. Runs in time bounded by the input size (no infinite loops).

This binary can then be linked into Sui's native module surface and
exposed as `sui::pqc::slh_dsa_sha2_128s_verify`. The cost-per-call drops
from the current ~1.572 SUI (pure-Move via Lean spec) to ~0.002 SUI
(native verified), and ships with a machine-checked proof from FIPS-205
spec to assembly.

## Why we haven't done this

It would take 4–8 person-months of focused F\* work, and the existing
pure-Lean spec + Move integration covers the Sui PQ-authorization use
case at ~750× the cost but zero additional engineering. The cost
difference matters for high-throughput use (per-tx PQ auth) but not for
the current "high-value attestation" deployment.

If/when Sui's roadmap requires native PQ verification at protocol scale
(e.g., validator-level PQ aggregate sigs), this F\* port is the
recommended Path B from `EXTRACTION.md`.

## What's in this directory now

```
fstar-sketch/
├── README.md                    — this file
├── Fips205.Bytes.fst             — F* port of Bytes.lean with
│                                   `requires` / `ensures` clauses for
│                                   every function, plus worked F*
│                                   implementations that the SMT solver
│                                   discharges by induction over the loop
│                                   counter. Read this side-by-side with
│                                   `proofs/Fips205/Bytes.lean` to see
│                                   the language correspondence.
└── Fips205.Bytes.c.expected      — what KaRaMeL would emit from the F*
                                    after extraction. CompCert-compatible
                                    plain C99; no runtime deps. Compare
                                    to `proofs/.lake/build/ir/Fips205/
                                    Bytes.c` to see how Lean's `lean_object*`
                                    extraction differs from KaRaMeL's
                                    "Low\*" extraction.
```

The two files together demonstrate the proper verified-extraction pipeline:

  F\* source (this) → KaRaMeL → plain C (`.c.expected`) → CompCert → assembly

Every link except the verification of CompCert itself has been done
production-grade in HACL\*. CompCert's own correctness has been verified
in Coq independently.

The remaining 7 Fips205 modules (Adrs, Sha256, Thash, Wots, Verify, MoveEquiv,
Structural) would each get a parallel `.fst` file following the same pattern.
The structural translation is mechanical; the proof obligations are similar
to those already discharged in the Lean development.
