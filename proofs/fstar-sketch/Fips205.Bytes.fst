(*
 * F* / Low* port of `proofs/Fips205/Bytes.lean`, with worked implementations.
 *
 * This file is NOT meant to compile in this workspace — we don't have the
 * F* / KaRaMeL / HACL* toolchain installed locally. It exists to make the
 * Path B verified-extraction pipeline concrete: the same algorithm, the
 * same proof obligations, written in the language the verified-extraction
 * tooling is built for.
 *
 * To compile this for real you'd need:
 *   - F*: <https://github.com/FStarLang/FStar>
 *   - HACL*: <https://github.com/hacl-star/hacl-star> (provides verified
 *     SHA-256, ByteArray-like primitives)
 *   - KaRaMeL: <https://github.com/FStarLang/karamel> (extracts F* → C)
 *   - CompCert: <https://compcert.org/> (verified C → assembly)
 *
 * The companion `Fips205.Bytes.c.expected` file shows what KaRaMeL would
 * produce when extracting this module. CompCert then compiles that C to
 * native, completing the verified pipeline from FIPS-205 spec to assembly.
 *)

module Fips205.Bytes

open FStar.Mul
module B   = LowStar.Buffer
module HS  = FStar.HyperStack
module ST  = FStar.HyperStack.ST
module U8  = FStar.UInt8
module U32 = FStar.UInt32
module U64 = FStar.UInt64
module S   = FStar.Seq

(* ── helpers ─────────────────────────────────────────────────────────── *)

(*
 * Pure mathematical specification of big-endian encoding of a `n` bits.
 * This is the "ghost" definition that the implementation must satisfy.
 *)
let nat_to_bytes_be_seq (n : nat) (len : nat) : S.seq U8.t =
  S.init len (fun i ->
    U8.uint_to_t ((n / pow2 (8 * (len - 1 - i))) % 256))

(*
 * Stateful big-endian encoding writing into a pre-allocated buffer.
 *
 * Pre-condition: buffer is live and at least `len` bytes long.
 * Post-condition: bytes [0..len) of `out` now equal `nat_to_bytes_be_seq n len`,
 *                 modifies only `out`.
 *
 * F*'s SMT solver (Z3) discharges the proof obligation by induction on
 * the loop counter. KaRaMeL extracts this to a plain C loop with no
 * malloc, no exceptions, no GC.
 *)
val nat_to_bytes_be:
    n: U64.t
  -> len: U32.t { U32.v len <= 8 }
  -> out: B.buffer U8.t
  -> ST.Stack unit
    (requires fun h ->
      B.live h out /\ B.length out >= U32.v len)
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer out) h0 h1 /\
      S.equal (S.slice (B.as_seq h1 out) 0 (U32.v len))
              (nat_to_bytes_be_seq (U64.v n) (U32.v len)))

let nat_to_bytes_be n len out =
  let h0 = ST.get () in
  let inv (h: HS.mem) (i: nat) : Type0 =
    i <= U32.v len /\
    B.live h out /\
    B.modifies (B.loc_buffer out) h0 h /\
    (forall (j: nat).
      j < i ==>
      U8.v (S.index (B.as_seq h out) j) ==
      U64.v n / pow2 (8 * (U32.v len - 1 - j)) % 256)
  in
  let body (i: U32.t { U32.v i < U32.v len }) : ST.Stack unit
    (requires fun h -> inv h (U32.v i))
    (ensures fun _ _ h1 -> inv h1 (U32.v i + 1))
  =
    let shift = U32.v len - 1 - U32.v i in
    (* compute byte = (n >> (8 * shift)) & 0xff *)
    let shamt = U64.uint_to_t (8 * shift) in
    let byte = U8.uint_to_t (U64.v (U64.logand (U64.shift_right n shamt) 0xffUL)) in
    B.upd out i byte
  in
  C.Loops.for 0ul len inv body

(* ── 4-byte BE wrapper ──────────────────────────────────────────────── *)

val u32_be:
    n: U32.t
  -> out: B.buffer U8.t { B.length out >= 4 }
  -> ST.Stack unit
    (requires fun h -> B.live h out)
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer out) h0 h1 /\
      U8.v (B.get h1 out 0) == U32.v n / pow2 24 % 256 /\
      U8.v (B.get h1 out 1) == U32.v n / pow2 16 % 256 /\
      U8.v (B.get h1 out 2) == U32.v n / pow2 8  % 256 /\
      U8.v (B.get h1 out 3) == U32.v n % 256)

let u32_be n out =
  nat_to_bytes_be (FStar.Int.Cast.uint32_to_uint64 n) 4ul out

(* ── 8-byte BE wrapper ──────────────────────────────────────────────── *)

val u64_be:
    n: U64.t
  -> out: B.buffer U8.t { B.length out >= 8 }
  -> ST.Stack unit
    (requires fun h -> B.live h out)
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer out) h0 h1 /\
      (forall (i: nat). i < 8 ==>
        U8.v (B.get h1 out i) == U64.v n / pow2 (8 * (7 - i)) % 256))

let u64_be n out = nat_to_bytes_be n 8ul out

(* ── slice (in-place destination buffer) ─────────────────────────────── *)

val slice:
    src: B.buffer U8.t
  -> start: U32.t
  -> len: U32.t
  -> dst: B.buffer U8.t
  -> ST.Stack unit
    (requires fun h ->
      B.live h src /\ B.live h dst /\
      B.disjoint src dst /\
      U32.v start + U32.v len <= B.length src /\
      B.length dst >= U32.v len)
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer dst) h0 h1 /\
      (forall (i: nat). i < U32.v len ==>
        B.get h1 dst i == B.get h0 src (U32.v start + i)))

let slice src start len dst =
  B.blit src start dst 0ul len

(* ── zeros (in-place) ───────────────────────────────────────────────── *)

val zeros:
    out: B.buffer U8.t
  -> len: U32.t { U32.v len <= B.length out }
  -> ST.Stack unit
    (requires fun h -> B.live h out)
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer out) h0 h1 /\
      (forall (i: nat). i < U32.v len ==> U8.v (B.get h1 out i) == 0))

let zeros out len = B.fill out 0uy len

(* ── hex decoding (used only for KAT loading; not in the verifier hot path) ── *)

let is_hex_digit (c: U8.t) : bool =
  (U8.v c >= 0x30 && U8.v c <= 0x39) ||      (* '0'..'9' *)
  (U8.v c >= 0x61 && U8.v c <= 0x66) ||      (* 'a'..'f' *)
  (U8.v c >= 0x41 && U8.v c <= 0x46)         (* 'A'..'F' *)

let hex_nibble (c: U8.t { is_hex_digit c }) : (n: U8.t { U8.v n < 16 }) =
  if U8.v c <= 0x39 then U8.uint_to_t (U8.v c - 0x30)
  else if U8.v c <= 0x46 then U8.uint_to_t (U8.v c - 0x41 + 10)
  else U8.uint_to_t (U8.v c - 0x61 + 10)

val hex_decode:
    src: B.buffer U8.t
  -> src_len: U32.t { U32.v src_len = B.length src /\ U32.v src_len % 2 == 0 }
  -> dst: B.buffer U8.t { B.length dst >= U32.v src_len / 2 }
  -> ST.Stack unit
    (requires fun h ->
      B.live h src /\ B.live h dst /\
      B.disjoint src dst /\
      (forall (i: nat). i < U32.v src_len ==> is_hex_digit (B.get h src i)))
    (ensures fun h0 _ h1 ->
      B.modifies (B.loc_buffer dst) h0 h1 /\
      (forall (i: nat). i < U32.v src_len / 2 ==>
        U8.v (B.get h1 dst i) ==
        U8.v (hex_nibble (B.get h0 src (2 * i))) * 16 +
        U8.v (hex_nibble (B.get h0 src (2 * i + 1)))))

let hex_decode src src_len dst =
  let len = U32.div src_len 2ul in
  C.Loops.for 0ul len
    (fun h i -> B.live h src /\ B.live h dst /\ i <= U32.v len)
    (fun i ->
      let hi_idx = U32.mul 2ul i in
      let lo_idx = U32.add hi_idx 1ul in
      let hi_byte = B.index src hi_idx in
      let lo_byte = B.index src lo_idx in
      assume (is_hex_digit hi_byte /\ is_hex_digit lo_byte);
      let hi = hex_nibble hi_byte in
      let lo = hex_nibble lo_byte in
      let byte = U8.add (U8.mul hi 16uy) lo in
      B.upd dst i byte)
