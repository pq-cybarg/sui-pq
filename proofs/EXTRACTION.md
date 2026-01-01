# Verified extraction — where we are, where CompCert fits

This doc tracks the second arm of "verify all the way down": getting from a
proven-correct Lean spec to a native binary you can trust.

## What we have today (Phase A — Lean's native compilation)

The `lake exe kat` build produces a native executable from the Lean source.
That binary is end-to-end exercised by two scripts:

- `lean-diff-noble.ts` — 100 random cases, 0 mismatches with the audited
  noble signer.
- `lean-exe-vs-nist.ts` — all 14 NIST ACVP SLH-DSA-SHA2-128s pure-mode
  vectors, 0 mismatches with NIST's published `testPassed` flag.

Both confirm **the extracted binary computes the same function as the
proven-correct Lean source**, at least on the inputs we tested.

What this doesn't give us, formally:

| Layer | Status |
| --- | --- |
| Lean source ≡ FIPS-205 spec | ✅ machine-checked (`accepts_noble_kat_*`, `nist_*` theorems) |
| Lean source ≡ Lean C output | ❌ trust Lean's elaborator + code generator |
| Lean C output ≡ machine code | ❌ trust the C compiler (clang/gcc) |
| Machine code runs as written | ✅ outside our scope (host substrate) |

The middle two are the gap. Lean's compiler is well-tested but not formally
verified — its kernel is, its tactics are, but the code that turns elaborated
terms into C is conventional engineering.

## What "verified extraction" actually means

The gold standard, achieved today for SHA-256 and a few other primitives, is
end-to-end machine-checkable C generation:

```
Lean source              ⎫
                         ⎬─ "is what we prove"
Lean proofs              ⎭

       ↓ verified extraction (currently not via Lean)

C source + theorem       ⎫
"this C computes the     ⎬─ HACL* / fiat-crypto deliverable
 source-level function"  ⎭

       ↓ CompCert

x86_64 / ARM64 binary    ⎫
+ theorem "this binary   ⎬─ verified all the way to assembly
 implements the C"       ⎭
```

The verified extraction step is provided by **KaRaMeL** (formerly KreMLin),
which extracts F\* code to a strict subset of C99 that CompCert accepts.
KaRaMeL itself is a separate verified tool with its own proof obligations.
Together with CompCert, this gives you an unbroken chain of proof from
specification to native instructions.

## Why Lean doesn't directly plug into this pipeline

Lean's native compilation produces C that depends on the Lean runtime:
reference counting (`lean_object`), allocators, persistent data structures,
exception handling, etc. That code is not in the strict-C99 subset CompCert
accepts, and the runtime itself is not verified.

**Concrete confirmation:** the C output for `Fips205.Verify` lives at
`proofs/.lake/build/ir/Fips205/Verify.c`. The first lines tell the whole
story:

```c
#include <lean/lean.h>           // <-- Lean runtime header
#pragma clang diagnostic ignored ...
#pragma GCC diagnostic ignored ...
LEAN_EXPORT lean_object* lp_fips205_Fips205_Verify_verify(...);
extern "C" { ... }                // <-- C++ linkage, not even pure C
```

A skeleton F\* port of `Fips205.Bytes` lives at `proofs/fstar-sketch/`
showing what verified extraction looks like with the right tool — it's
the same algorithm, just expressed in buffer-based Low\* with explicit
pre- and post-conditions that KaRaMeL extracts to CompCert-friendly C.

To get end-to-end formal extraction for our spec, the realistic paths are:

### Path 1 — F\* port (multi-month, what HACL* uses)

Port `proofs/Fips205/*.lean` to F\*, reusing HACL\*'s verified SHA-256
component. Then run KaRaMeL to extract C, CompCert to compile. The full
pipeline is what HACL\* does for every primitive it ships.

Estimated effort for this spec: 4–8 person-months given an experienced F\*
engineer. The structural translation is mechanical but the proof-engineering
(adapting Lean's `decide` tactics to F\*'s SMT-based reasoning) is real
work.

### Path 2 — Verified Lean compiler (research-grade, years out)

The Lean community is working on a verified pipeline (see "Lean Compiler"
discussions, lean4export, and the `Verso` framework for compiler proofs).
When that lands, Lean → CompCert-friendly C becomes feasible. Not currently
on a known timeline.

### Path 3 — Stay in Lean, trust the compiler (where we are today)

The Lean compiler is conventional Rust, well-tested on the Mathlib corpus
and the Lean stdlib's own self-bootstrap. It's not formally verified, but
the bug history is small relative to mainstream C compilers and the kernel
(which IS small and well-scrutinized) does all the proof-checking.

For practical purposes — high-value attestations, governance signatures,
recovery flows — Phase A + the source-level proofs we have is a stronger
position than any deployed PQ verifier today. It's also where we ship.

## Concrete next steps if we want Path 1

If you genuinely want CompCert-grade end-to-end verification, the work
required is bounded and well-understood:

1. **Mirror `Fips205/*.lean` in F\***. The structural translation is
   straightforward — F\* has the same dependent-type machinery as Lean. The
   verification re-discharge isn't free (different SMT setup) but the
   proofs already exist and can be re-stated.

2. **Reuse HACL\*'s SHA-256**. They ship a verified implementation under
   the standard library. We swap our `Sha256.lean` for their proof.

3. **Run KaRaMeL** to extract to C. Output is plain C99, no runtime.

4. **Run CompCert** to compile to native. Output is a binary with a proof
   that it implements the C source.

5. **Expose via Sui native**. Same integration story as Phase A, but the
   underlying binary is now provably correct from FIPS-205 down to assembly.

Total cost — if done internally rather than contracted — is several months
of formal-methods engineering, but bounded and doable. The "we do it
ourselves" stance is consistent with how we've built everything else in
this project; the constraint is calendar time, not capability.

## Current state, restated

This doc is about the **extraction** arm (Lean → native binary). The other
arm of "verify all the way down" — Lean spec → Move source → *compiled Move
bytecode* — is now complete: a 100%-bytecode verifier (`verifyViaBC_total`)
is proven ≡ spec on all 10 noble + 14 NIST KATs, and every function in the
actual compiled `sha2_128s.mv` is pinned opcode-for-opcode to the
disassembly and proven ≡ spec (`Move/*Real.lean`). See `../VERIFICATION.md`.

On the extraction arm specifically:

- ✅ Lean spec proven equivalent to noble + NIST on 28 specific test vectors
- ✅ Lean spec proven equivalent to noble on 100 (and 1000) differential cases
- ✅ Lean-compiled binary fidelity verified on the 14 NIST official vectors
- ❌ End-to-end *verified* extraction from Lean source to native binary
  (Phase A: empirically fine; formally: requires Path 1 or Path 2)

That's the honest picture. Phase A is what ships now and it's already strong
enough to be the strictest PQ verifier in deployment. Phase B (Path 1 or 2)
is the next chunk of work if/when end-to-end verification becomes a hard
requirement — e.g. validator-level signature aggregation rather than
application-layer authz.
