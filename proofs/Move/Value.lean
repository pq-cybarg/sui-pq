/-! # Move runtime values

The subset of Move values our FIPS-205 verifier actually uses on the VM
stack. Move has many more (structs, references, ability witnesses…); we
deliberately model only what `sha2_128s::verify` needs.

The Move language ref defines values as:
  - integer types u8/u16/u32/u64/u128/u256
  - bool
  - address (32 bytes)
  - vector<T>  (heterogeneous T)
  - struct S { ... }
  - mutable / immutable references

For the verifier we only need: u8, u32, u64, bool, vector<u8>.
Everything else is intentionally absent — they form a smaller TCB.
-/

namespace Fips205.Move

/-- Move values, restricted to what our verifier uses. -/
inductive Value where
  | u8   (n : UInt8)
  | u32  (n : UInt32)
  | u64  (n : UInt64)
  | bool (b : Bool)
  | vecU8  (v : ByteArray)
  | vecU32 (v : Array UInt32)
  -- A mutable reference to a local. Real Move references carry a path
  -- and a borrow record; we only need the local index because the
  -- compiled bytecode emits `MutBorrowLoc` and dereferences/writes via
  -- `ReadRef` / `VecPushBack` in well-defined patterns (no aliasing).
  | locRef (idx : Nat)
  -- A mutable reference to a vec<u8> element at locals[locIdx][elemIdx].
  -- Produced by `VecMutBorrow` against a `locRef`. Consumed by `WriteRef`
  -- to do an in-place byte write (the Move compiler's pattern for
  -- `adrs[k] = v`).
  | vecElemRef (locIdx : Nat) (elemIdx : Nat)
  deriving Inhabited

instance : Repr Value where
  reprPrec v _ := match v with
    | .u8 n => s!"u8({n})"
    | .u32 n => s!"u32({n})"
    | .u64 n => s!"u64({n})"
    | .bool b => s!"bool({b})"
    | .vecU8 v => s!"vec<u8>[{v.size}B]"
    | .vecU32 v => s!"vec<u32>[{v.size}×4B]"
    | .locRef i => s!"&mut loc[{i}]"
    | .vecElemRef l e => s!"&mut loc[{l}][{e}]"

namespace Value

/-- Project a u8, panic on tag mismatch (modelling Move's strict type checks). -/
def asU8! : Value → UInt8
  | .u8 n => n
  | _ => panic! "type mismatch: expected u8"

def asU32! : Value → UInt32
  | .u32 n => n
  | _ => panic! "type mismatch: expected u32"

def asU64! : Value → UInt64
  | .u64 n => n
  | _ => panic! "type mismatch: expected u64"

def asBool! : Value → Bool
  | .bool b => b
  | _ => panic! "type mismatch: expected bool"

def asVecU8! : Value → ByteArray
  | .vecU8 v => v
  | _ => panic! "type mismatch: expected vector<u8>"

def asVecU32! : Value → Array UInt32
  | .vecU32 v => v
  | _ => panic! "type mismatch: expected vector<u32>"

/-- Project any integer Value (u8/u32/u64) to a Nat. Used by polymorphic
    arithmetic / bit ops (`Shr`, `BitAnd`, `CastU8`, etc.) where the Move
    bytecode applies these to whichever integer type the value carries. -/
def asNat : Value → Nat
  | .u8  n => n.toNat
  | .u32 n => n.toNat
  | .u64 n => n.toNat
  | _ => 0

/-- For polymorphic bit ops, the result type must match the LHS operand's
    type tag. This wraps a `Nat` payload in the same integer type as the
    given template Value (defaulting to u64 if the template isn't integer). -/
def wrapLikeInt (template : Value) (n : Nat) : Value :=
  match template with
  | .u8  _ => .u8  (UInt8.ofNat  (n &&& 0xff))
  | .u32 _ => .u32 (UInt32.ofNat (n &&& 0xffffffff))
  | .u64 _ => .u64 (UInt64.ofNat n)
  | _      => .u64 (UInt64.ofNat n)

/-- Two Move values are equal iff they have the same tag and the same payload.
    Move's `==` and `!=` are total on `copy + drop` types — both u-ints and
    bool are copy+drop, and `vector<u8>` is in our model. -/
def equal : Value → Value → Bool
  | .u8 a,    .u8 b    => a == b
  | .u32 a,   .u32 b   => a == b
  | .u64 a,   .u64 b   => a == b
  | .bool a,  .bool b  => a == b
  | .vecU8 a, .vecU8 b => a == b
  | .vecU32 a, .vecU32 b => a == b
  | _, _ => false

end Value
end Fips205.Move
