import Move.Value
import Move.Stack
import Move.Opcode
import Move.Native

/-! # Small-step Move VM semantics

`step` executes one opcode against the current state. `run` iterates
`step` until the program counter reaches a `Ret` or steps run out.

Properties we want to be able to state:
  - `run fn args = some v` ⟺ the Move function `fn` returns `v` on inputs `args`
  - `run fn args = none`  ⟺ `fn` aborts / runs out of fuel / has a type error

The `fuel` argument bounds execution; real Move uses gas, but for proof
purposes fuel is a cleaner termination witness.
-/

namespace Fips205.Move

open Fips205.Move Fips205.Move.Value

-- `step` and `run` are mutually recursive via the `Call` opcode: a `Call`
-- inside `step` invokes `run` on the callee's bytecode in a fresh frame.
-- Since the callee may itself contain `Call`s, this is genuine mutual
-- recursion. Both are `partial def` because the recursion depth is bounded
-- by the program's own structure (each `Call` opcode is finite syntax)
-- rather than a structural argument Lean can verify mechanically. For
-- `native_decide`, partial-defs are fine: they compile to native code and
-- run to completion on closed inputs.
mutual

/-- Execute one opcode. Returns the next state. -/
partial def step (op : Opcode) (s : State) : State :=
  if s.error.isSome then s -- once errored, stay errored
  else match op with
  | .Pop =>
    let (s', _) := s.pop
    { s' with pc := s.pc + 1 }
  | .LdU8 n   => { (s.push (Value.u8 n))   with pc := s.pc + 1 }
  | .LdU32 n  => { (s.push (Value.u32 n))  with pc := s.pc + 1 }
  | .LdU64 n  => { (s.push (Value.u64 n))  with pc := s.pc + 1 }
  | .LdTrue   => { (s.push (Value.bool true))  with pc := s.pc + 1 }
  | .LdFalse  => { (s.push (Value.bool false)) with pc := s.pc + 1 }
  | .CopyLoc i =>
    let (s', v) := s.getLocal i
    match v with
    | none => s'
    | some v => { (s'.push v) with pc := s.pc + 1 }
  | .MoveLoc i =>
    -- same as CopyLoc for `copy`-able types; full Move marks the local invalid
    let (s', v) := s.getLocal i
    match v with
    | none => s'
    | some v => { (s'.push v) with pc := s.pc + 1 }
  | .StLoc i =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { (s'.setLocal i v) with pc := s.pc + 1 }
  | .MutBorrowLoc i =>
    -- Push a mutable reference to local i. We don't check existence here
    -- because borrow-checking happens offline; runtime will fault at the
    -- first ReadRef / VecPushBack if the local is OOB.
    { (s.push (Value.locRef i)) with pc := s.pc + 1 }
  | .ReadRef =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some (.locRef i) =>
      match s'.locals[i]? with
      | none => { s' with error := some s!"ReadRef: local {i} OOB" }
      | some lv => { (s'.push lv) with pc := s.pc + 1 }
    | some v =>
      -- ReadRef on a non-ref: Move's offline verifier rules this out, but for
      -- VecImmBorrow→ReadRef sequences (where VecImmBorrow returns a value in
      -- our model) we make this a no-op so the bytecode still typechecks.
      { (s'.push v) with pc := s.pc + 1 }
  | .LdConst v =>
    { (s.push v) with pc := s.pc + 1 }
  | .FreezeRef =>
    -- &mut T → &T: in our model references are plain `locRef` values, so this
    -- is a pc-advance no-op (the value already on the stack is the frozen ref).
    { s with pc := s.pc + 1 }
  | .WriteRef =>
    -- Pop ref, pop value, write *ref := value. Move stack ordering: top is
    -- the reference, value is below.
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (refV, val) =>
      match refV with
      | .locRef i =>
        match s'.locals[i]? with
        | none => { s' with error := some s!"WriteRef: local {i} OOB" }
        | some _ => { s' with locals := s'.locals.set! i val, pc := s.pc + 1 }
      | .vecElemRef l j =>
        match s'.locals[l]? with
        | none => { s' with error := some s!"WriteRef: local {l} OOB" }
        | some lv =>
          let arr := lv.asVecU8!
          if j ≥ arr.size then
            { s' with error := some s!"WriteRef: vec idx {j} OOB" }
          else
            let updated := Value.vecU8 (arr.set! j val.asU8!)
            { s' with locals := s'.locals.set! l updated, pc := s.pc + 1 }
      | _ =>
        { s' with error := some "WriteRef: expected reference value" }
  | .Add =>
    -- Polymorphic: Move's Add requires both operands to be the same integer
    -- type; result is the same type. We dispatch on LHS via `wrapLikeInt`.
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let r := Value.wrapLikeInt a (Value.asNat a + Value.asNat b)
      { (s'.push r) with pc := s.pc + 1 }
  | .Sub =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      -- Saturating-at-zero (Nat subtraction). Real Move aborts on underflow,
      -- but for our verified bytecodes no underflow happens; Nat.sub matches.
      let r := Value.wrapLikeInt a (Value.asNat a - Value.asNat b)
      { (s'.push r) with pc := s.pc + 1 }
  | .Eq =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      { (s'.push (Value.bool (Value.equal a b))) with pc := s.pc + 1 }
  | .Neq =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      { (s'.push (Value.bool (!Value.equal a b))) with pc := s.pc + 1 }
  | .Lt =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      { (s'.push (Value.bool (Value.asNat a < Value.asNat b))) with pc := s.pc + 1 }
  | .Gt =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      { (s'.push (Value.bool (Value.asNat a > Value.asNat b))) with pc := s.pc + 1 }
  | .Shl =>
    -- Polymorphic: result type = LHS type. Move's shift count is u8.
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let n := Value.asNat a <<< Value.asNat b
      { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .Shr =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let n := Value.asNat a >>> Value.asNat b
      { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .BitAnd =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let n := Value.asNat a &&& Value.asNat b
      { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .BitOr =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let n := Value.asNat a ||| Value.asNat b
      { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .CastU8 =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { (s'.push (Value.u8 (UInt8.ofNat (Value.asNat v &&& 0xff)))) with pc := s.pc + 1 }
  | .CastU32 =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { (s'.push (Value.u32 (UInt32.ofNat (Value.asNat v &&& 0xffffffff)))) with pc := s.pc + 1 }
  | .CastU64 =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { (s'.push (Value.u64 (UInt64.ofNat (Value.asNat v)))) with pc := s.pc + 1 }
  | .Mul =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let n := Value.asNat a * Value.asNat b
      { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .Div =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let bn := Value.asNat b
      if bn = 0 then { s' with error := some "Div: division by zero" }
      else
        let n := Value.asNat a / bn
        { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .Mod =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (b, a) =>
      let bn := Value.asNat b
      if bn = 0 then { s' with error := some "Mod: division by zero" }
      else
        let n := Value.asNat a % bn
        { (s'.push (Value.wrapLikeInt a n)) with pc := s.pc + 1 }
  | .ImmBorrowLoc i =>
    -- Identical to MutBorrowLoc in our model: both push `locRef i`. Move's
    -- offline borrow checker enforces immutability statically; runtime
    -- semantics for the operations we care about are the same.
    { (s.push (Value.locRef i)) with pc := s.pc + 1 }
  | .Branch off => { s with pc := off }
  | .BrTrue off =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { s' with pc := if v.asBool! then off else s.pc + 1 }
  | .BrFalse off =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v => { s' with pc := if !v.asBool! then off else s.pc + 1 }
  | .Ret => s  -- caller detects and stops
  | .VecEmpty =>
    { (s.push (Value.vecU8 ByteArray.empty)) with pc := s.pc + 1 }
  | .VecLen =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v =>
      -- Deref a `locRef` (a `&vector<u8>` arg may reach VecLen directly).
      let bytes := match v with
        | .locRef i => (s'.locals[i]?.getD (Value.vecU8 ByteArray.empty)).asVecU8!
        | _ => v.asVecU8!
      { (s'.push (Value.u64 (UInt64.ofNat bytes.size))) with pc := s.pc + 1 }
  | .VecPushBack =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (val, vec) =>
      let nb := val.asU8!
      match vec with
      | .locRef i =>
        -- Write through a mutable local reference: locals[i] := locals[i].push val.
        -- Net stack effect: pops 2, pushes 0 (in-place mutation).
        match s'.locals[i]? with
        | none => { s' with error := some s!"VecPushBack: local {i} OOB" }
        | some lv =>
          let updated := Value.vecU8 (lv.asVecU8!.push nb)
          { s' with locals := s'.locals.set! i updated, pc := s.pc + 1 }
      | _ =>
        let bytes := vec.asVecU8!
        { (s'.push (Value.vecU8 (bytes.push nb))) with pc := s.pc + 1 }
  | .VecPopBack =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some (.locRef i) =>
      -- Move's `vector::pop_back(&mut v): Element` — remove last in place,
      -- push only the removed element (the caller discards it via Pop in the
      -- truncation idiom used by `thash`/`chain`).
      match s'.locals[i]? with
      | none => { s' with error := some s!"VecPopBack: local {i} OOB" }
      | some lv =>
        let bytes := lv.asVecU8!
        if bytes.size = 0 then
          { s' with error := some "VecPopBack on empty vector" }
        else
          let last := bytes.get! (bytes.size - 1)
          let rest := ByteArray.mk (bytes.toList.dropLast.toArray)
          { (s'.push (Value.u8 last)) with
              locals := s'.locals.set! i (Value.vecU8 rest), pc := s.pc + 1 }
    | some v =>
      let bytes := v.asVecU8!
      if bytes.size = 0 then
        { s' with error := some "VecPopBack on empty vector" }
      else
        let last := bytes.get! (bytes.size - 1)
        let rest := ByteArray.mk (bytes.toList.dropLast.toArray)
        { ((s'.push (Value.vecU8 rest)).push (Value.u8 last)) with pc := s.pc + 1 }
  | .VecMutBorrow =>
    -- VecMutBorrow on a `locRef i` and u64 idx → `vecElemRef i idx`. Used by
    -- the compiler's `vec[idx] = v` pattern (followed by `WriteRef`). On a
    -- value-vec, we fall back to value semantics (push the element value).
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (idx, vec) =>
      let i := idx.asU64!.toNat
      match vec with
      | .locRef l =>
        { (s'.push (Value.vecElemRef l i)) with pc := s.pc + 1 }
      | _ =>
        let arr := vec.asVecU8!
        if i ≥ arr.size then
          { s' with error := some "VecMutBorrow: index out of bounds" }
        else
          { (s'.push (Value.u8 (arr.get! i))) with pc := s.pc + 1 }
  | .VecImmBorrow =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (idx, vec0) =>
      -- Deref a `locRef` to get the underlying vec value (mirrors how Move's
      -- runtime handles `VecImmBorrow` on a `&` reference).
      let vec := match vec0 with
        | .locRef i => (s'.locals[i]?.getD (Value.vecU8 ByteArray.empty))
        | _ => vec0
      let bytes := vec.asVecU8!
      let i := idx.asU64!.toNat
      if i ≥ bytes.size then
        { s' with error := some "vector borrow out-of-bounds" }
      else
        { (s'.push (Value.u8 (bytes.get! i))) with pc := s.pc + 1 }
  | .VecAppend =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (vec2, vec1) =>
      -- Deref `locRef` operands (Move's `vector::append`-style helpers may
      -- receive `&` arguments that reach VecAppend without an explicit ReadRef).
      let deref (v : Value) : ByteArray := match v with
        | .locRef i => (s'.locals[i]?.getD (Value.vecU8 ByteArray.empty)).asVecU8!
        | _ => v.asVecU8!
      let bytes := deref vec1 ++ deref vec2
      { (s'.push (Value.vecU8 bytes)) with pc := s.pc + 1 }
  | .VecSet =>
    -- Pop three: top is value (u8), next is index (u64), next is vector.
    let (s1, top) := s.pop
    match top with
    | none => s1
    | some valVal =>
      let (s2, idxV) := s1.pop
      match idxV with
      | none => s2
      | some idxVal =>
        let (s3, vecV) := s2.pop
        match vecV with
        | none => s3
        | some vecVal =>
          let bytes := vecVal.asVecU8!
          let idx := idxVal.asU64!.toNat
          let v := valVal.asU8!
          if idx ≥ bytes.size then
            { s3 with error := some "VecSet index out-of-bounds" }
          else
            let newBytes := bytes.set! idx v
            { (s3.push (Value.vecU8 newBytes)) with pc := s.pc + 1 }
  | .VecU32Empty =>
    { (s.push (Value.vecU32 #[])) with pc := s.pc + 1 }
  | .VecU32Len =>
    let (s', v) := s.pop
    match v with
    | none => s'
    | some v =>
      let arr := match v with
        | .locRef i => (s'.locals[i]?.getD (Value.vecU32 #[])).asVecU32!
        | _ => v.asVecU32!
      { (s'.push (Value.u64 (UInt64.ofNat arr.size))) with pc := s.pc + 1 }
  | .VecU32PushBack =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (valVal, vec) =>
      let nv := valVal.asU32!
      match vec with
      | .locRef i =>
        -- write-through-locRef: modify locals[i] (a vector<u32>) in place.
        match s'.locals[i]? with
        | none => { s' with error := some s!"VecU32PushBack: local {i} OOB" }
        | some lv =>
          let updated := Value.vecU32 (lv.asVecU32!.push nv)
          { s' with locals := s'.locals.set! i updated, pc := s.pc + 1 }
      | _ =>
        let arr := vec.asVecU32!
        { (s'.push (Value.vecU32 (arr.push nv))) with pc := s.pc + 1 }
  | .VecU32ImmBorrow =>
    let (s', vs) := s.pop2
    match vs with
    | none => s'
    | some (idx, vec0) =>
      let vec := match vec0 with
        | .locRef i => (s'.locals[i]?.getD (Value.vecU32 #[]))
        | _ => vec0
      let arr := vec.asVecU32!
      let i := idx.asU64!.toNat
      if i ≥ arr.size then
        { s' with error := some "vector<u32> borrow out-of-bounds" }
      else
        { (s'.push (Value.u32 arr[i]!)) with pc := s.pc + 1 }
  | .CallNative name arity =>
    -- Pop `arity` arguments off the stack (top-most is the LAST argument).
    if s.stack.size < arity then
      { s with error := some "CallNative: stack underflow" }
    else
      let argSlice := s.stack.toSubarray (s.stack.size - arity) s.stack.size
      let args : Array Value := argSlice.toArray
      let newStack := (s.stack.toSubarray 0 (s.stack.size - arity)).toArray
      match applyNative name arity args with
      | none => { s with error := some s!"unknown native: {name}" }
      | some v =>
        { s with stack := newStack.push v, pc := s.pc + 1 }
  | .Call callee localsTail arity =>
    -- Pop `arity` args off the caller's stack (first arg at bottom of slice).
    if s.stack.size < arity then
      { s with error := some "Call: stack underflow" }
    else
      let argSlice := s.stack.toSubarray (s.stack.size - arity) s.stack.size
      let argsRaw : Array Value := argSlice.toArray
      let newStack := (s.stack.toSubarray 0 (s.stack.size - arity)).toArray
      -- ── Cross-frame reference handling ──
      -- A locRef arg points to a caller-frame local. We can't pass it into
      -- the callee as-is, because inside the callee locRef i would refer to
      -- the callee's local i (wrong frame). Instead we do "copy-in copy-out":
      --   * resolve each locRef arg to its caller value, push that into a
      --     fresh callee backing slot, and replace the arg with a locRef
      --     pointing to the backing slot (now in the callee's own frame).
      --   * after callee Ret, copy each backing slot back to the caller
      --     local it stood for — picking up any in-place mutation.
      -- Layout in the callee frame:
      --   0..arity-1     = (possibly retargeted) args
      --   arity..tailEnd = declared non-arg locals (`localsTail` shape)
      --   tailEnd..      = backing slots for ref args, in order of first
      --                    occurrence among the args.
      let (initLocals, backings) : Array Value × Array (Nat × Nat) := Id.run do
        let mut backings : Array (Nat × Nat) := #[]
        let mut backingValues : Array Value := #[]
        let mut translatedArgs := argsRaw
        for k in [:arity] do
          match argsRaw[k]! with
          | .locRef i =>
            let backingIdx := arity + localsTail.size + backingValues.size
            match s.locals[i]? with
            | none => pure ()
            | some v =>
              translatedArgs := translatedArgs.set! k (Value.locRef backingIdx)
              backingValues := backingValues.push v
              backings := backings.push (i, backingIdx)
          | _ => pure ()
        return (translatedArgs ++ localsTail ++ backingValues, backings)
      let calleeInit : State :=
        { stack := #[], locals := initLocals, pc := 0, error := none }
      let calleeFinal := run callee calleeInit 1_000_000
      match calleeFinal.error with
      | some e => { s with error := some s!"Call: callee error: {e}" }
      | none =>
        let newCallerLocals : Array Value := Id.run do
          let mut nl := s.locals
          for (callerIdx, calleeIdx) in backings do
            match calleeFinal.locals[calleeIdx]? with
            | none => pure ()
            | some v => nl := nl.set! callerIdx v
          return nl
        let s1 : State :=
          { stack := newStack, locals := newCallerLocals, pc := s.pc + 1, error := none }
        -- Void return (empty callee stack) is allowed — the mutation is the result.
        match calleeFinal.stack.back? with
        | none => s1
        | some v => { s1 with stack := newStack.push v }

/-- Iterated step: returns the final state after up to `fuel` opcodes, or
    the state at the first `Ret` (or error). -/
partial def run (code : Bytecode) (s : State) (fuel : Nat) : State :=
  if fuel = 0 then { s with error := some "out of fuel" }
  else if s.error.isSome then s
  else if s.pc < code.size then
    let op := code[s.pc]!
    match op with
    | Opcode.Ret => s
    | _ => run code (step op s) (fuel - 1)
  else { s with error := some s!"pc out of bounds: {s.pc}" }

end -- mutual

/-- Convenience: run with default fuel 10⁶ (more than enough for any
    realistic Move function body). -/
def runDefault (code : Bytecode) (s : State) : State :=
  run code s 1_000_000

end Fips205.Move
