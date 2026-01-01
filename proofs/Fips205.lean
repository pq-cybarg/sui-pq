import Fips205.Params
import Fips205.Bytes
import Fips205.Adrs
import Fips205.Sha256
import Fips205.Thash
import Fips205.Wots
import Fips205.Verify
import Fips205.Kat
import Fips205.NistKat
import Fips205.MoveEquiv
import Fips205.Structural

/-! # FIPS-205 SLH-DSA-SHA2-128s formal specification

This is the top-level entrypoint. Definitions live in `Fips205/*.lean`.

Module dependency graph (acyclic):

    Params      ← parameter constants (n, h, d, k, a, …)
    Bytes       ← BE encoding helpers
    Adrs        ← compressed 22-byte ADRS layout
    Sha256      ← pure-Lean SHA-256 (KAT-tested)
    Thash       ← FIPS-205 tweakable hashes (F, H, T_l, H_msg)
-/
