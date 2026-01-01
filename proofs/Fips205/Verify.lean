import Fips205.Params
import Fips205.Bytes
import Fips205.Adrs
import Fips205.Thash
import Fips205.Wots

/-! # Top-level FIPS-205 SLH-DSA-SHA2-128s verify (§10.3)

  forsPkFromSig:  reconstruct the FORS public key from a sig.
  xmssPkFromSig:  reconstruct an XMSS root (one HT layer) from a sig.
  htRootFromSig:  walk the d-layer hypertree, returning the top-level root.
  splitDigest:    H_msg output → (md, tree_idx, leaf_idx).
  verify:         §10.3 entry point with §10.2.2 context wrapping.
-/

namespace Fips205.Verify

open Fips205 Fips205.Bytes Fips205.Adrs Fips205.Thash Fips205.Wots

/-- Extract `k` FORS indices, each `a` bits wide, big-endian within `md`. -/
def extractForsIndices (md : ByteArray) : Array Nat := Id.run do
  let mut out : Array Nat := Array.empty
  let mut bitOff : Nat := 0
  for _ in [0:k] do
    let mut v : Nat := 0
    for b in [0:a] do
      let bitIdx := bitOff + b
      let byte := (md.get! (bitIdx >>> 3)).toNat
      let bit := (byte >>> (7 - (bitIdx &&& 7))) &&& 1
      v := (v <<< 1) ||| bit
    out := out.push v
    bitOff := bitOff + a
  return out

/-- FORS public key from sig (FIPS-205 §8.4). Input `adrs` already has
    layer/tree/keypair set; type=FORS_TREE. -/
def forsPkFromSig (sigFors md : ByteArray) (pk_seed : ByteArray) (adrs : Adrs) : ByteArray := Id.run do
  let chunkBytes : Nat := (1 + a) * n     -- 13 * 16 = 208 per FORS tree
  let indices := extractForsIndices md
  let mut rootsBuf := ByteArray.empty
  for i in [0:k] do
    let off := i * chunkBytes
    let skLeaf := slice sigFors off n
    let authPath := slice sigFors (off + n) (a * n)
    let idx := indices[i]!
    -- Leaf = F(pk_seed, adrs, sk) at height=0, index = i*2^a + idx
    let mut leafAdrs := setType adrs AdrsType.fors_tree
    leafAdrs := setTreeHeight leafAdrs 0
    leafAdrs := setTreeIndex leafAdrs (i * (2 ^ a) + idx)
    let mut node := thash pk_seed leafAdrs skLeaf
    -- Walk this FORS tree of depth a
    let mut cur := idx
    for j in [0:a] do
      let sib := slice authPath (j * n) n
      leafAdrs := setTreeHeight leafAdrs (j + 1)
      let nodesAtHeight := 2 ^ (a - j - 1)
      let parentIdx := i * nodesAtHeight + (cur >>> 1)
      leafAdrs := setTreeIndex leafAdrs parentIdx
      let bit := cur &&& 1
      let merged := if bit = 0 then node ++ sib else sib ++ node
      node := thash pk_seed leafAdrs merged
      cur := cur >>> 1
    rootsBuf := rootsBuf ++ node
  -- Compress all K roots via T_K (FORS_ROOTS); keypair inherited from adrs
  let rootsAdrs := setTreeIndex (setTreeHeight (setType adrs AdrsType.fors_roots) 0) 0
  return thash pk_seed rootsAdrs rootsBuf

/-- XMSS pubkey from sig (FIPS-205 §6.4). Input `adrs` has layer + tree set. -/
def xmssPkFromSig (idx : Nat) (sig msg_n : ByteArray) (pk_seed : ByteArray) (adrs : Adrs) : ByteArray := Id.run do
  let wotsSigLen := len * n
  let wotsSig := slice sig 0 wotsSigLen
  let authPath := slice sig wotsSigLen (h_prime * n)
  -- WOTS+ leaf
  let mut a := setKeypair (setType adrs AdrsType.wots_hash) idx
  let mut node := wotsPkFromSig wotsSig msg_n pk_seed a
  -- TREE auth-path walk (keypair field is padding for TREE type → zero)
  a := setKeypair (setType a AdrsType.tree) 0
  let mut curIdx := idx
  for i in [0:h_prime] do
    a := setTreeHeight a (i + 1)
    a := setTreeIndex a (curIdx >>> 1)
    let sibling := slice authPath (i * n) n
    let bit := (idx >>> i) &&& 1
    let merged := if bit = 0 then node ++ sibling else sibling ++ node
    node := thash pk_seed a merged
    curIdx := curIdx >>> 1
  return node

/-- Hypertree root from sig (FIPS-205 §7.2). Walks the d layers. -/
def htRootFromSig (sigHt msg_n : ByteArray) (treeIdx0 leafIdx0 : Nat) (pk_seed : ByteArray) : ByteArray := Id.run do
  let xmssSigBytes := (len + h_prime) * n
  let mut node := msg_n
  let mut curTree := treeIdx0
  let mut curLeaf := leafIdx0
  for j in [0:d] do
    let mut a := empty
    a := setLayer a j
    a := setTree a curTree
    let sliceJ := slice sigHt (j * xmssSigBytes) xmssSigBytes
    node := xmssPkFromSig curLeaf sliceJ node pk_seed a
    -- promote: next layer's leaf is the low h' bits of current tree
    let leafMask := 2 ^ h_prime - 1
    curLeaf := curTree &&& leafMask
    curTree := curTree >>> h_prime
  return node

/-- Split the H_msg output into (md, tree_idx, leaf_idx) per §10.2. -/
def splitDigest (digest : ByteArray) : ByteArray × Nat × Nat := Id.run do
  let mdBytes := (k * a + 7) / 8         -- 21
  let treeBits := h - h_prime            -- 54
  let treeBytes := (treeBits + 7) / 8    -- 7
  let leafBytes := (h_prime + 7) / 8     -- 2
  let md := slice digest 0 mdBytes
  let mut treeIdx : Nat := 0
  for i in [0:treeBytes] do
    treeIdx := (treeIdx <<< 8) ||| (digest.get! (mdBytes + i)).toNat
  treeIdx := treeIdx &&& (2 ^ treeBits - 1)
  let mut leafIdx : Nat := 0
  for i in [0:leafBytes] do
    leafIdx := (leafIdx <<< 8) ||| (digest.get! (mdBytes + treeBytes + i)).toNat
  leafIdx := leafIdx &&& (2 ^ h_prime - 1)
  return (md, treeIdx, leafIdx)

/-- §10.3 verify, with §10.2.2 message wrapping `M' = [0x00, |ctx|] ++ ctx ++ M`.

   This is the **formal FIPS-205 SLH-DSA-SHA2-128s verify** in pure Lean.
   Returns `true` iff `sig` is a valid signature on `msg` (with optional context
   `ctx`, ≤ 255 bytes) under `pk`. -/
def verify (pk msg sig : ByteArray) (ctx : ByteArray := ByteArray.empty) : Bool := Id.run do
  if pk.size ≠ pk_bytes then return false
  if sig.size ≠ sig_bytes then return false
  if ctx.size > 255 then return false
  let pkSeed := slice pk 0 n
  let pkRoot := slice pk n n
  -- §10.2.2 wrapping: M' = [0x00, |ctx|] ++ ctx ++ M
  let wrapped := (ByteArray.mk #[0, UInt8.ofNat ctx.size]) ++ ctx ++ msg
  let r := slice sig 0 n
  let forsBytesLen := k * (1 + a) * n     -- 2912
  let sigFors := slice sig n forsBytesLen
  let sigHt := slice sig (n + forsBytesLen) (sig_bytes - n - forsBytesLen)
  let digest := hmsg r pkSeed pkRoot wrapped
  let (md, treeIdx, leafIdx) := splitDigest digest
  let mut adrs := empty
  adrs := setLayer adrs 0
  adrs := setTree adrs treeIdx
  adrs := setType adrs AdrsType.fors_tree
  adrs := setKeypair adrs leafIdx
  let forsRoot := forsPkFromSig sigFors md pkSeed adrs
  let htRoot := htRootFromSig sigHt forsRoot treeIdx leafIdx pkSeed
  return htRoot = pkRoot

end Fips205.Verify
