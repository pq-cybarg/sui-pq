import Move.Value

/-! # Move VM execution state

A small-step operational-semantics state for a Move-like stack machine,
restricted to the opcodes our FIPS-205 verifier actually uses. Reading
order is bottom-of-state → top-of-state, with comments calling out where
this differs from the real Move VM (which has more elaborate handling of
references, abilities, modules, etc.).

This is intentionally a "small" semantics: enough to reason about a
single function call within a single module. We don't model cross-module
calls, the module loader, the verifier (Move's bytecode static checks),
or persistent state. Anything our verifier needs is in scope; everything
else is omitted.
-/

namespace Fips205.Move

open Fips205.Move Fips205.Move.Value

/-- Total execution state during evaluation of a single function:
      `stack`   – operand stack (top is at the end of the array)
      `locals`  – this frame's locals (mutable by `StLoc` opcode)
      `pc`      – program counter (index into the function's bytecode)
      `error`   – set on type mismatch, stack underflow, etc.

    Locals are an `Array Value`: untyped at runtime (type safety is statically
    checked offline by Move's bytecode verifier). We deliberately make errors
    an explicit `Option String` rather than panicking: this lets our
    equivalence proofs reason about reject paths as well as accept paths. -/
structure State where
  stack  : Array Value := #[]
  locals : Array Value := #[]
  pc     : Nat := 0
  error  : Option String := none
  deriving Inhabited

namespace State

/-- Push `v` onto the operand stack. -/
def push (s : State) (v : Value) : State :=
  { s with stack := s.stack.push v }

/-- Pop the operand stack. On underflow, set the error flag and leave the
    state otherwise unchanged. -/
def pop (s : State) : State × Option Value :=
  if s.stack.isEmpty then
    ({ s with error := some "stack underflow" }, none)
  else
    let v := s.stack.back!
    ({ s with stack := s.stack.pop }, some v)

/-- Pop two values; useful for binary operations. Returns them in
    pop-order: first-popped is the *top* (which was pushed last). -/
def pop2 (s : State) : State × Option (Value × Value) :=
  let (s1, v1) := pop s
  match v1 with
  | none => (s1, none)
  | some a =>
    let (s2, v2) := pop s1
    match v2 with
    | none => (s2, none)
    | some b => (s2, some (a, b))

/-- Read a local. Out-of-bounds is an error. -/
def getLocal (s : State) (i : Nat) : State × Option Value :=
  if i < s.locals.size then
    (s, some s.locals[i]!)
  else
    ({ s with error := some s!"local out-of-bounds: {i}" }, none)

/-- Write a local. Out-of-bounds is an error. -/
def setLocal (s : State) (i : Nat) (v : Value) : State :=
  if i < s.locals.size then
    { s with locals := s.locals.set! i v }
  else
    { s with error := some s!"local out-of-bounds: {i}" }

end State
end Fips205.Move
