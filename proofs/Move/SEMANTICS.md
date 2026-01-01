# The Move VM model: trusted semantics and the refinement obligation

This document specifies the Move VM model in `proofs/Move/` precisely enough to
audit, and states exactly where it is **trusted** rather than proven. It is the
companion to the machine-checked bytecode-equivalence proofs: those proofs show
"the compiled bytecode of `sha2_128s.mv` computes the FIPS-205 spec *under this
VM*"; this document pins down what "this VM" assumes about the real Sui Move VM.

## Why this is a document, not a theorem

`step` and `run` in `Move/Step.lean` are `partial def`. They have to be: the
`Call` opcode runs a callee via `run`, and a callee may itself contain `Call`s,
so `step` and `run` are mutually recursive with no structural decreasing
argument the kernel can see. Lean does not generate equational lemmas for
`partial def`s, so we cannot state or prove universally-quantified metatheorems
about `step`/`run` (e.g. "∀ s, …"). Every equivalence in this project is instead
a **`native_decide`** fact about a *closed* term — the VM compiled to native
code and run to completion on concrete inputs. That is sound (it goes through
Lean's compiler + kernel `ofReduceBool`) and is what gives us per-function,
per-vector guarantees. It does **not** give a general refinement theorem; that
is the open obligation stated at the end.

## State

```
Value  := u8 | u32 | u64 | bool | vecU8 ByteArray | vecU32 (Array UInt32)
        | locRef Nat | vecElemRef Nat Nat            -- references (see below)
State  := { stack : Array Value, locals : Array Value, pc : Nat, error : Option String }
```

`step op s` returns the next `State`; an `error` is a stuck/aborted machine.
`run code s fuel` iterates `step` until `Ret`, an error, `pc` out of bounds, or
fuel exhaustion. `runDefault` uses fuel `10^6`. The first line of `step` is
`if s.error.isSome then s` — errors are absorbing.

## Opcode semantics

`Bytecode := Array Opcode`. We model the subset the compiled
`sha2_128s.mv` actually uses (49 constructors). Each row: our semantics, and the
correspondence to the Move binary-format instruction it stands for.

### Stack / locals
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `Pop` | pop, discard | `Pop` |
| `LdU8/LdU32/LdU64 n` | push integer literal | `LdU8/LdU64/…` (+ `LdConst` for u32 in real code) |
| `LdTrue/LdFalse` | push bool | `LdTrue/LdFalse` |
| `LdConst v` | push the constant `v` | `LdConst[k]` (we inline the pool value) |
| `CopyLoc i` | push copy of `locals[i]` | `CopyLoc` (copy ability assumed) |
| `MoveLoc i` | push `locals[i]` | `MoveLoc` — **we don't invalidate the local** (see §Simplifications) |
| `StLoc i` | pop into `locals[i]` | `StLoc` |

### Integer ops (polymorphic over u8/u32/u64)
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `Add/Sub/Mul` | `wrapLikeInt a (a ⊙ b)` over `Nat` payloads; result type = LHS type | `Add/Sub/Mul` — **Nat arithmetic, see §Overflow** |
| `Div/Mod` | as above; `b=0` → `error` | `Div/Mod` (Move aborts on /0; we error) |
| `Eq/Neq` | tagged structural (in)equality | `Eq/Neq` |
| `Lt/Gt` | compare `asNat` | `Lt/Gt` |
| `Shl/Shr` | shift `asNat a` by `asNat b`, retype to LHS | `Shl/Shr` |
| `BitAnd/BitOr` | bitwise on `asNat`, retype to LHS | `BitAnd/BitOr` |
| `CastU8/CastU32/CastU64` | mask to width, retag | `CastU8/CastU32/CastU64` |

### Control flow
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `Branch off` | `pc := off` | `Branch` |
| `BrTrue/BrFalse off` | pop bool; jump on true/false | `BrTrue/BrFalse` |
| `Ret` | `run` stops; stack top(s) are the return value(s) | `Ret` |

### Vectors (`vector<u8>` and `vector<u32>`)
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `VecEmpty / VecU32Empty` | push empty vector | `VecPack 0` |
| `VecLen / VecU32Len` | push length (`u64`); derefs a `locRef` operand | `VecLen` |
| `VecPushBack / VecU32PushBack` | append; **write-through if the vec is a `locRef`** | `VecPushBack` on `&mut v` |
| `VecPopBack` | on a `locRef`: remove last in place, push it; on a value: push (rest, last) | `VecPopBack` on `&mut v` |
| `VecImmBorrow / VecU32ImmBorrow` | push `vec[idx]` value; derefs a `locRef` operand | `VecImmBorrow` + `ReadRef` |
| `VecMutBorrow` | on a `locRef`: push `vecElemRef`; else push the element value | `VecMutBorrow` |
| `VecAppend` | `vec1 ++ vec2`; derefs `locRef` operands | `vector::append` (also modeled as a `Call`, see `MoveStdlib.lean`) |
| `VecSet` | write `vec[idx] := val`, push the vec | `MutBorrowLoc; …; WriteRef` idiom |

### References
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `MutBorrowLoc i` / `ImmBorrowLoc i` | push `locRef i` | `MutBorrowLoc` / `ImmBorrowLoc` |
| `ReadRef` | deref `locRef`→`locals[i]`; **no-op on a non-ref value** | `ReadRef` |
| `WriteRef` | `*locRef := v` (write local) or `*vecElemRef := v` (write byte) | `WriteRef` |
| `FreezeRef` | identity (a `&mut` and `&` are the same `locRef` here) | `FreezeRef` |

### Calls
| Opcode | Our semantics | Move correspondence |
| --- | --- | --- |
| `CallNative name arity` | pop args, apply the modeled native (below) | `Call` into a native function |
| `Call callee localsTail arity` | run `callee` in a fresh frame; **copy-in/copy-out** for `&mut`/`&` args (see below) | `Call` into a Move function |

## Native functions (trusted)

`applyNative` (`Move/Native.lean`) models five natives as mathematical
functions. These are **trusted**, not modeled at the bit level inside the VM:

| Native | Model | Trust basis |
| --- | --- | --- |
| `sha2_256(vector<u8>) : vector<u8>` | `Fips205.Sha256.sha256` (pure-Lean, self-checked vs FIPS 180-4 KATs) | the Lean SHA-256 is itself in the TCB and KAT-checked |
| `u64_to_u8`, `u64_to_u32`, `u8_to_u64`, `u32_to_u64` | width truncation / zero-extension | trivial integer casts |

The assumption is that Sui's Rust `hash::sha2_256` and integer casts compute the
same mathematical functions. SHA-256 specifically is exercised against FIPS
180-4 KATs in `Fips205/Sha256.lean`.

## The reference model — the largest simplification

Real Move references carry a borrow path and a borrow-checker record. We model a
mutable/immutable reference as `locRef i` (a reference to local `i` in the
current frame) and a byte-level reference as `vecElemRef loc elem`. There is **no
runtime borrow checking** — Move's verifier enforces aliasing/borrow rules
*offline*, before execution, so a program that passed the bytecode verifier
never exhibits the aliasing our model would mishandle. We rely on that
precondition.

Cross-frame references in `Call` use **copy-in/copy-out**: a `locRef` argument is
resolved to its caller value, written into a fresh backing slot in the callee
frame, and the callee receives a `locRef` to that slot; on return the slot is
copied back to the caller local. This faithfully reproduces single-threaded
`&mut` semantics (no aliasing) and is proven to compose to 6-deep nesting
(`ht_root_from_sig` → … → `write_u32_be`) by `native_decide` in the `*Real`
modules.

## Simplifications vs. the production VM, and why each is sound *here*

1. **Integer overflow.** We compute `Add/Sub/Mul` over `Nat` and retype. The real
   Move VM **aborts** on overflow/underflow. Soundness here is *empirical per
   input*: the `*Real` proofs run the actual bytecode on representative inputs
   and match the spec, and the spec's own arithmetic stays in range — no
   reachable state in the verified runs overflows. A general proof would need a
   range invariant; we do not claim one.
2. **`MoveLoc` does not invalidate the source local.** Move marks a moved local
   unusable. Our bytecodes never read a moved-from local before reassigning it
   (the compiler guarantees this), so the distinction is unobservable on the
   programs we run.
3. **No runtime borrow check** (see §References). Offloaded to Move's offline
   bytecode verifier as a precondition.
4. **Fuel, not gas.** `run` bounds steps by fuel (`10^6`); the VM bounds by gas.
   Both are termination/resource cutoffs; neither affects the computed result on
   terminating runs, and all verified runs terminate well under the fuel bound.
5. **`ReadRef` is a no-op on non-references.** Real `ReadRef` requires a
   reference. Some compiled sequences (`VecImmBorrow; ReadRef`) reach `ReadRef`
   with a value in our model because our `VecImmBorrow` already returns the
   element value; making `ReadRef` an identity there keeps such sequences
   faithful without changing results.
6. **Natives are trusted** (see §Natives).

## The open refinement obligation

> Let `⟦·⟧` be Sui's production Move VM `execute` relation on
> `slh_dsa_128s::sha2_128s` functions, and `run` ours. The obligation is:
> for every function `f` in the module and every well-typed input that passes
> the offline bytecode verifier, `run (disasm f) σ` and `⟦f⟧ σ` agree on the
> returned value(s).

What this project *has* established, short of that theorem:

- `disasm f` (the bytecode we run) is the **actual compiled bytecode** of `f`,
  pinned opcode-for-opcode to `sui move disassemble` output (`Move/*Real.lean`).
- `run (disasm f) σ` equals the FIPS-205 spec on every tested input
  (`native_decide`), for every `f` in the module.

The remaining edge is purely "`run` ≡ `⟦·⟧`", i.e. that the opcode semantics in
this document match Sui's Rust implementation. Discharging it mechanically would
mean (a) refactoring `step`/`run` to total, fuel-structural definitions so
metatheorems become provable, and (b) building or importing a model of Sui's VM
to refine against — a multi-month effort tracked in `../../docs/pq-validator-roadmap.md`
and `../../VERIFICATION.md`.
