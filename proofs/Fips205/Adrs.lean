import Fips205.Params
import Fips205.Bytes

/-! # Compressed 22-byte ADRS (FIPS-205 §11.2.1).

Byte layout (matches our Move + TS implementations):

    [0]      layer_addr      (1 byte)
    [1..9)   tree_addr       (8 bytes, BE)
    [9]      type            (1 byte)
    [10..14) keypair_addr    (4 bytes, BE — padding for non-WOTS types)
    [14..18) tree_height     (4 bytes, BE — chain_addr for WOTS_HASH)
    [18..22) tree_index      (4 bytes, BE — hash_addr for WOTS_HASH)

Every field is byte-aligned and BE-encoded; this matches the FIPS-205 compressed-
ADRS specification for SHA-2 variants.
-/

namespace Fips205.Adrs

open Fips205 Fips205.Bytes

/-- Strongly-typed view of an ADRS. We keep this as plain `Nat` fields rather
    than fixed-width unsigned ints — easier to reason about bounds. -/
structure Adrs where
  layer       : Nat
  tree        : Nat
  type        : UInt8
  keypair     : Nat
  treeHeight  : Nat
  treeIndex   : Nat
  deriving Repr

/-- A fresh, all-zero ADRS. -/
def empty : Adrs :=
  { layer := 0, tree := 0, type := 0, keypair := 0, treeHeight := 0, treeIndex := 0 }

/-- Serialise to the 22-byte compressed form. -/
def compress (a : Adrs) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat (a.layer &&& 0xff)]
    ++ u64BE a.tree
    ++ ByteArray.mk #[a.type]
    ++ u32BE a.keypair
    ++ u32BE a.treeHeight
    ++ u32BE a.treeIndex

example : (compress empty).size = adrs_bytes := by native_decide

/-- Helpers that mirror the field-setters in our Move impl. -/
def setType (a : Adrs) (t : UInt8) : Adrs := { a with type := t }
def setLayer (a : Adrs) (l : Nat) : Adrs := { a with layer := l }
def setTree (a : Adrs) (t : Nat) : Adrs := { a with tree := t }
def setKeypair (a : Adrs) (kp : Nat) : Adrs := { a with keypair := kp }
def setTreeHeight (a : Adrs) (h : Nat) : Adrs := { a with treeHeight := h }
def setTreeIndex (a : Adrs) (i : Nat) : Adrs := { a with treeIndex := i }

end Fips205.Adrs
