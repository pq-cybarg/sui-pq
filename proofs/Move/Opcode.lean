import Move.Value
import Move.Stack

/-! # Move opcodes — the subset our verifier uses

Move's bytecode has ~100 opcodes. We model the subset that actually
appears in the compiled bytecode of `slh_dsa_128s::sha2_128s::verify`
and its callees. The encoding (`Opcode`) is an inductive type so
machine-checked properties of any program in this subset reduce to
case-analysis on the constructors.

Real Move opcodes have additional metadata (type tags, module hashes,
function indices) that we mostly ignore — those are handled by the
static verifier before runtime, so our small-step semantics doesn't
need to re-check them.

Reference: <https://github.com/move-language/move/blob/main/language/move-binary-format/src/file_format.rs>
search for `enum Bytecode`. We've named our constructors to match.
-/

namespace Fips205.Move

inductive Opcode where
  -- ── stack / locals ──
  | Pop                        -- discard top of stack
  | LdU8  (n : UInt8)          -- push literal u8
  | LdU32 (n : UInt32)         -- push literal u32
  | LdU64 (n : UInt64)         -- push literal u64
  | LdTrue                     -- push true
  | LdFalse                    -- push false
  | CopyLoc (idx : Nat)        -- copy local idx → top of stack (must have `copy` ability)
  | MoveLoc (idx : Nat)        -- move local idx → top of stack
  | StLoc   (idx : Nat)        -- pop, store into local idx
  | MutBorrowLoc (idx : Nat)   -- push a mutable reference (`Value.locRef idx`) to local idx
  | ReadRef                    -- pop a reference, push the referenced value (no-op on non-refs)
  | FreezeRef                  -- convert &mut T → &T; identity on the stack value in our model
  | LdConst (v : Value)        -- push a constant value (models the Move bytecode pool's LdConst[k])
  | WriteRef                   -- pop ref (locRef|vecElemRef), pop value, do an in-place write
  -- ── arithmetic + comparison (u64) ──
  | Add                        -- pop b, pop a, push (a + b)
  | Sub                        -- pop b, pop a, push (a - b) [saturates per Move semantics]
  | Eq                         -- pop b, pop a, push (a == b)  works on any type
  | Neq                        -- pop b, pop a, push (a != b)
  | Lt                         -- pop b, pop a, push (a < b)   (u64)
  | Gt                         -- pop b, pop a, push (a > b)   (u64)
  | Mul                        -- pop b, pop a, push (a * b)   (polymorphic, LHS type preserved)
  | Div                        -- pop b, pop a, push (a / b)   (polymorphic; b == 0 → error)
  | Mod                        -- pop b, pop a, push (a % b)   (polymorphic; b == 0 → error)
  | CastU8                     -- pop integer, push (value & 0xff) as u8
  | CastU32                    -- pop integer, push (value & 0xffffffff) as u32
  | CastU64                    -- pop integer, push value as u64
  | ImmBorrowLoc (idx : Nat)   -- push immutable ref to local idx (we model identically to MutBorrowLoc)
  -- ── bitwise (u64) ──
  | Shl                        -- pop b, pop a, push (a << b)
  | Shr                        -- pop b, pop a, push (a >> b)
  | BitAnd                     -- pop b, pop a, push (a & b)
  | BitOr                      -- pop b, pop a, push (a | b)
  -- ── control flow ──
  | Branch (offset : Nat)      -- unconditional jump to bytecode index
  | BrTrue (offset : Nat)      -- pop; if true → jump
  | BrFalse (offset : Nat)     -- pop; if false → jump
  | Ret                        -- terminate function; result is the stack top
  -- ── vector primitives (subset our verifier touches) ──
  | VecEmpty                   -- push empty vector<u8>
  | VecLen                     -- pop vec, push (length : u64)
  | VecPushBack                -- pop value, pop vec, push (vec with value appended)
  | VecPopBack                 -- pop vec, push popped value, push (vec with last elem removed)
  | VecImmBorrow               -- pop idx, pop vec, push (vec[idx] : value); derefs a `locRef` vec
  | VecMutBorrow               -- pop idx, pop vec; on a `locRef` produces `vecElemRef loc idx` (for WriteRef), else the element value
  | VecAppend                  -- pop vec2, pop vec1, push (vec1 ++ vec2). Equivalent to Move's vector::append.
  | VecSet                     -- pop u8 val, pop u64 idx, pop vec<u8>, push vec' where vec'[idx]=val.
                               -- Models Move's MutBorrow + WriteRef on a vector<u8> element.
  | VecU32Empty                -- push empty vector<u32>
  | VecU32PushBack             -- pop u32 val, pop vec<u32>, push (vec ++ [val])
  | VecU32Len                  -- pop vec<u32>, push (length : u64)
  | VecU32ImmBorrow            -- pop u64 idx, pop vec<u32>, push (vec[idx] : u32)
  -- ── function calls ──
  -- Real Move has Call (function handle index, arg count) — we model it abstractly
  -- by passing the callee's bytecode directly.
  --
  -- `CallNative` invokes a native function by symbolic name. We only model
  -- the natives our verifier actually uses (currently just sha2_256).
  --
  -- `Call` invokes user-defined Move code: the callee runs in a fresh frame
  -- with the popped arguments as its locals, then returns its top-of-stack to
  -- the caller. The fresh-frame model matches the real Move VM exactly except
  -- that we don't model module-level type checks (those happen offline in the
  -- bytecode verifier, before runtime).
  | CallNative (name : String) (arity : Nat)
  -- `Call` invokes user-defined Move bytecode as a subroutine. The callee's
  -- initial state has `arity` args (popped from the caller's stack) as its
  -- first locals (low-index first), followed by `localsTail` (the callee's
  -- declared non-arg locals, initialized to zero/empty per Move semantics).
  -- The callee's top-of-stack at `Ret` is pushed onto the caller's stack.
  --
  -- Embedding the callee bytecode directly avoids a recursive symbol-table
  -- (which would create a circular import with the encoded primitives).
  -- This matches Move's actual call ABI except we elide the static type
  -- checks (those are handled by the offline bytecode verifier).
  | Call (callee : Array Opcode) (localsTail : Array Value) (arity : Nat)
  deriving Inhabited

/-- A function body is just a sequence of opcodes. Real Move bytecode also
    carries arg types, return types, and local types — we omit those for
    the small-step semantics; type-correctness is a precondition. We use a
    plain `abbrev` rather than `def` so type-class resolution sees through
    to `Array Opcode`'s instances. -/
abbrev Bytecode := Array Opcode

end Fips205.Move
