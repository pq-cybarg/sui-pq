import Move.Value
import Move.Native
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Example
import Move.Slice
import Move.SliceReal
import Move.PkSeedPadded
import Move.PkSeedPaddedReal
import Move.BytesEqReal
import Move.ConcatReal
import Move.Thash
import Move.MoveStdlib
import Move.ThashReal
import Move.ChainReal
import Move.WotsPkFromSigReal
import Move.ForsPkFromSigReal
import Move.XmssPkFromSigReal
import Move.HtRootFromSigReal
import Move.AdrsSetTreeIndex
import Move.AdrsSetters
import Move.AdrsSetTypeReal
import Move.WriteU32BeReal
import Move.AdrsSetKeypairReal
import Move.WriteU64BeReal
import Move.AdrsNewAppendSliceReal
import Move.ExtractForsIndices
import Move.ExtractForsIndicesReal
import Move.SplitDigest
import Move.SplitDigestReal
import Move.BaseW
import Move.BaseWReal
import Move.WotsChecksum
import Move.WotsChecksumReal
import Move.MsgToChainDigitsReal
import Move.Mgf1
import Move.Hmsg
import Move.HmsgReal
import Move.HmsgCall
import Move.Composition

/-! # Move VM semantics + bytecode equivalence

Top-level entry point for the `Move` library: a Move abstract machine in Lean
(`Value`/`Stack`/`Opcode`/`Step`/`Native`, ~49 opcodes including mutable &
immutable references, cross-frame `Call`, `FreezeRef`, and polymorphic integer
ops) plus the proofs built on it.

Layers, smallest to largest:
  * `Example.lean` — the original proof-of-concept (`byteEq` bytecode ≡ spec).
  * Per-primitive structural bytecode ≡ spec: `Slice`, `PkSeedPadded`, `Thash`,
    `BaseW`, `WotsChecksum`, `Mgf1`, `Hmsg`, `SplitDigest`,
    `ExtractForsIndices`, the ADRS setters.
  * `Composition.lean` — `verifyViaBC` / `_full` / `_total`. `verifyViaBC_total`
    is a 100%-bytecode FIPS-205 verifier proven ≡ `Verify.verify` on all 10
    noble + 14 NIST KATs (19 capstones).
  * `*Real.lean` (21 modules) — every function in the *actual compiled*
    `move/slh_dsa_128s/.../sha2_128s.mv` (via `sui move disassemble`), encoded
    opcode-for-opcode and proven ≡ spec under this VM, up to 6-deep `Call`
    nesting. `MoveStdlib.lean` models `vector::append` as a `Call` callee.
-/
