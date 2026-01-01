/**
 * Cross-package integration tests. These don't mock anything — they exercise
 * the real `@sui-gen/pqc` surface end-to-end and pin the byte format
 * agreements with the Move-side counterparts.
 *
 * Why this matters: if the TS `buildUnlockMessageBytes` ever diverges from
 * the Move `pq_guard::unlock_message_bytes`, the Move verifier on-chain will
 * reject signatures the TS signer thought were valid. These tests catch
 * that as a unit-test regression instead of a chain-reject regression.
 */
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import {
  // schemes / signing
  keygen, sign, verify, SCHEME_META,
  // ML-KEM
  kemKeygen, kemEncrypt, kemDecrypt,
  // attestation
  buildAttestation, verifyAttestation, buildRegisterTx,
  // hybrid / zk-login
  packHybrid,
  createZkLoginPqBinding,
  // pq-guard
  buildUnlockMessageBytes, addPqGuardUnlock,
  // sponsor
  PqSponsoredClient, base64ToBytes,
  // SLH-DSA-LITE (Move-mirror) namespace
  slh,
} from './index.js';
import { Transaction } from '@mysten/sui/transactions';

// Same key material the Move pq_guard test vectors used (gen-pq-guard-vectors.ts):
// seed and skSeed are both 32 bytes filled with 0xcc and 0xdd respectively.
const SEED = new Uint8Array(32).fill(0xcc);
const SK_SEED = new Uint8Array(32).fill(0xdd);
const SENDER = '0x' + '0a'.repeat(32);

describe('cross-package integration', () => {
  it('every top-level export resolves at runtime', () => {
    // If any of these are undefined the module graph has a hole. Cheap
    // canary that the index.ts re-exports stay in sync with the source files.
    expect(typeof keygen).toBe('function');
    expect(typeof sign).toBe('function');
    expect(typeof verify).toBe('function');
    expect(typeof kemKeygen).toBe('function');
    expect(typeof kemEncrypt).toBe('function');
    expect(typeof kemDecrypt).toBe('function');
    expect(typeof buildAttestation).toBe('function');
    expect(typeof verifyAttestation).toBe('function');
    expect(typeof buildRegisterTx).toBe('function');
    expect(typeof packHybrid).toBe('function');
    expect(typeof createZkLoginPqBinding).toBe('function');
    expect(typeof buildUnlockMessageBytes).toBe('function');
    expect(typeof addPqGuardUnlock).toBe('function');
    expect(typeof PqSponsoredClient).toBe('function');
    expect(typeof base64ToBytes).toBe('function');
    // SLH-DSA-LITE namespace
    expect(typeof slh.keygen).toBe('function');
    expect(typeof slh.sign).toBe('function');
    expect(typeof slh.verify).toBe('function');
    expect(typeof slh.packSignature).toBe('function');
    expect(typeof slh.unpackSignature).toBe('function');
  });

  // ── ML-DSA: round-trip, every parameter set ─────────────────────────────
  it.each(['ML_DSA_44', 'ML_DSA_65', 'ML_DSA_87'] as const)(
    '%s sign/verify round-trips with workspace-canonical sizes',
    (scheme) => {
      const kp = keygen(scheme);
      const meta = SCHEME_META[scheme];
      expect(kp.publicKey.length).toBe(meta.publicKeyBytes);
      const msg = sha256(new TextEncoder().encode(`message for ${scheme}`));
      const sig = sign(kp, msg);
      expect(sig.length).toBe(meta.signatureBytes);
      expect(verify(scheme, kp.publicKey, msg, sig)).toBe(true);
      // Tamper detection: flipping the first byte fails verification
      const bad = new Uint8Array(sig);
      bad[0] = (bad[0] ?? 0) ^ 0xff;
      expect(verify(scheme, kp.publicKey, msg, bad)).toBe(false);
    },
  );

  // ── SLH-DSA: ditto, single small variant for speed ──────────────────────
  it.each(['SLH_DSA_SHA2_128S'] as const)(
    '%s sign/verify round-trips',
    (scheme) => {
      const kp = keygen(scheme);
      const meta = SCHEME_META[scheme];
      expect(kp.publicKey.length).toBe(meta.publicKeyBytes);
      const msg = new TextEncoder().encode('hash-based PQ');
      const sig = sign(kp, msg);
      expect(sig.length).toBe(meta.signatureBytes);
      expect(verify(scheme, kp.publicKey, msg, sig)).toBe(true);
    },
  );

  // ── ML-KEM ↔ AEAD: encrypt-decrypt across the public/secret boundary ───
  it('ML-KEM-768 + AES-GCM round-trips payload across separate keypairs', () => {
    const recipient = kemKeygen('ML_KEM_768');
    const plaintext = new TextEncoder().encode('the carrier is ready');
    const aad = new TextEncoder().encode('app=demo;v=1');
    const packet = kemEncrypt('ML_KEM_768', recipient.publicKey, plaintext, aad);
    const out = kemDecrypt('ML_KEM_768', recipient.secretKey, packet, aad);
    expect(new TextDecoder().decode(out)).toBe('the carrier is ready');
  });

  // ── Attestation: build_tx uses move-tx subpath; verify shape ────────────
  it('attestation round-trip + move-tx builder produces a valid Transaction', () => {
    const { attestation } = buildAttestation({
      scheme: 'ML_DSA_44',
      suiAddress: SENDER,
      appTag: 'cross-pkg-integration',
    });
    expect(verifyAttestation(attestation).ok).toBe(true);

    const tx = buildRegisterTx({
      packageId: '0x' + '11'.repeat(32),
      attestation,
    });
    // Transaction is a class from @mysten/sui — check the type rather than
    // try to serialize without a client.
    expect(tx).toBeInstanceOf(Transaction);
  });

  // ── zkLogin PQ binding ─────────────────────────────────────────────────
  it('zkLogin binding + verify works end-to-end with the same secret key', () => {
    const { binding, secretKey } = createZkLoginPqBinding({ zkLoginAddress: SENDER });
    // Sanity: the attestation embedded in the binding is itself verifiable
    expect(verifyAttestation(binding.attestation).ok).toBe(true);
    // And the secret key + the attestation's pubkey are a real pair
    const msg = sha256(new TextEncoder().encode('zkLogin-bound action'));
    const sig = sign({ scheme: binding.scheme, secretKey }, msg);
    expect(verify(binding.scheme, binding.pqPublicKey, msg, sig)).toBe(true);
  });

  // ── PQ-Guard byte format: TS ↔ Move agreement ───────────────────────────
  it('buildUnlockMessageBytes produces the 90-byte format Move pq_guard expects', () => {
    const actionDigest = sha256(new TextEncoder().encode('vault::withdraw(1000)'));
    const msg = buildUnlockMessageBytes({ sender: SENDER, nonce: 0n, actionDigest });

    // Layout assertions — this is the contract with move/pq_guard/sources/pq_guard.move
    expect(msg.length).toBe(18 + 32 + 8 + 32); // 90 bytes
    expect(new TextDecoder().decode(msg.slice(0, 18))).toBe('PQ_GUARD:UNLOCK:v1');
    // Sender: low byte of "0x0a..." is 0x0a
    for (let i = 0; i < 32; i++) expect(msg[18 + i]).toBe(0x0a);
    // Nonce 0 → all-zero u64 BE
    for (let i = 0; i < 8; i++) expect(msg[50 + i]).toBe(0x00);
    // Action digest tail
    for (let i = 0; i < 32; i++) expect(msg[58 + i]).toBe(actionDigest[i]);
  });

  // ── End-to-end PQ-Guard: TS builds the same bytes the Move tests verify ──
  it('TS sign → TS verify works on the EXACT same payload Move pq_guard tests use', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);

    const action0 = sha256(new TextEncoder().encode('vault::withdraw(1000)'));
    const msg0 = buildUnlockMessageBytes({ sender: SENDER, nonce: 0n, actionDigest: action0 });
    const sig0 = slh.packSignature(slh.sign(sk, msg0));
    expect(slh.verify(pk, msg0, slh.unpackSignature(sig0))).toBe(true);

    const action1 = sha256(new TextEncoder().encode('vault::withdraw(2500)'));
    const msg1 = buildUnlockMessageBytes({ sender: SENDER, nonce: 1n, actionDigest: action1 });
    const sig1 = slh.packSignature(slh.sign(sk, msg1));
    expect(slh.verify(pk, msg1, slh.unpackSignature(sig1))).toBe(true);

    // Same pk, but message digest changed → sig0 no longer valid for msg1
    expect(slh.verify(pk, msg1, slh.unpackSignature(sig0))).toBe(false);
  });

  // ── PTB shape: addPqGuardUnlock + sponsor builder produce well-formed tx ─
  it('addPqGuardUnlock inserts a moveCall and returns a usable argument', () => {
    const tx = new Transaction();
    const auth = addPqGuardUnlock(tx, {
      guardPackageId: '0x' + '22'.repeat(32),
      identityId: '0x' + '33'.repeat(32),
      actionDigest: new Uint8Array(32),
      signature: new Uint8Array(5056),
    });
    // The witness arg from a moveCall is itself a TransactionArgument
    expect(auth).toBeDefined();
    // The transaction should now contain at least one moveCall command
    const data = tx.getData();
    const calls = data.commands.filter((c) => '$kind' in c && c.$kind === 'MoveCall');
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });

  // ── Hybrid pack format: deterministic shape ─────────────────────────────
  it('packHybrid emits a well-formed byte string we can re-parse', () => {
    const txBytes = new Uint8Array([1, 2, 3, 4]);
    const packed = packHybrid({
      txBytes,
      classicalSignature: 'abc',
      scheme: 'ML_DSA_44',
      pqPublicKey: new Uint8Array(SCHEME_META.ML_DSA_44.publicKeyBytes),
      pqSignature: new Uint8Array(SCHEME_META.ML_DSA_44.signatureBytes),
    });
    // Header byte = scheme byte for ML_DSA_44
    expect(packed[0]).toBe(SCHEME_META.ML_DSA_44.byte);
    // Then 4-byte u32 LE of txBytes length
    expect([packed[1], packed[2], packed[3], packed[4]]).toEqual([4, 0, 0, 0]);
    // Then 4 bytes of tx body
    expect([packed[5], packed[6], packed[7], packed[8]]).toEqual([1, 2, 3, 4]);
  });

  // ── base64 codec round-trip (used by the sponsor wire format) ───────────
  it('base64ToBytes is the inverse of the sponsor encoder', async () => {
    // Use the same encoder that PqSponsoredClient uses internally
    const original = new Uint8Array([0, 1, 2, 0xff, 0xaa, 0x55]);
    const encoded = Buffer.from(original).toString('base64');
    const decoded = base64ToBytes(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });
});
