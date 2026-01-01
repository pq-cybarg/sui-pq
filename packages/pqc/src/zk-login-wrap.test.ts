import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { sign } from './signing.js';
import {
  type PqWrappedZkLoginTx,
  createZkLoginPqBinding,
  verifyPqWrappedZkLoginTx,
} from './zk-login-wrap.js';

const ADDR = `0x${'ab'.repeat(32)}`;

describe('zkLogin PQ-wrap', () => {
  it('creates a binding with the requested address + scheme', () => {
    const { binding } = createZkLoginPqBinding({ zkLoginAddress: ADDR, scheme: 'ML_DSA_44' });
    expect(binding.zkLoginAddress).toBe(ADDR);
    expect(binding.scheme).toBe('ML_DSA_44');
    expect(binding.attestation.suiAddress).toBe(ADDR);
  });

  it('wraps a tx with a PQ co-signature; verifyPqWrappedZkLoginTx accepts it', () => {
    const { binding, secretKey } = createZkLoginPqBinding({ zkLoginAddress: ADDR });
    const txBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const txDigest = sha256(txBytes);
    const pqSignature = sign({ scheme: binding.scheme, secretKey }, txDigest);

    const wrapped: PqWrappedZkLoginTx = {
      txBytes,
      txDigest,
      pqSignature,
      pqPublicKey: binding.pqPublicKey,
      scheme: binding.scheme,
      zkLoginAddress: ADDR,
    };
    const res = verifyPqWrappedZkLoginTx(wrapped, binding);
    expect(res.ok).toBe(true);
    expect(res.digestMatches).toBe(true);
    expect(res.pqSignatureOk).toBe(true);
  });

  it('rejects a wrapped tx whose claimed address differs from the binding', () => {
    const { binding, secretKey } = createZkLoginPqBinding({ zkLoginAddress: ADDR });
    const txBytes = new Uint8Array([9, 9, 9]);
    const pqSignature = sign({ scheme: binding.scheme, secretKey }, sha256(txBytes));
    const wrapped: PqWrappedZkLoginTx = {
      txBytes,
      txDigest: sha256(txBytes),
      pqSignature,
      pqPublicKey: binding.pqPublicKey,
      scheme: binding.scheme,
      zkLoginAddress: `0x${'cd'.repeat(32)}`,
    };
    expect(verifyPqWrappedZkLoginTx(wrapped, binding).ok).toBe(false);
  });

  it('rejects a wrapped tx signed under a different PQ keypair', () => {
    const { binding } = createZkLoginPqBinding({ zkLoginAddress: ADDR });
    const intruder = createZkLoginPqBinding({ zkLoginAddress: ADDR });
    const txBytes = new Uint8Array([1, 2]);
    const wrapped: PqWrappedZkLoginTx = {
      txBytes,
      txDigest: sha256(txBytes),
      pqSignature: sign(
        { scheme: intruder.binding.scheme, secretKey: intruder.secretKey },
        sha256(txBytes),
      ),
      pqPublicKey: intruder.binding.pqPublicKey,
      scheme: intruder.binding.scheme,
      zkLoginAddress: ADDR,
    };
    // pubkey mismatch should fail at the binding-pin step
    expect(verifyPqWrappedZkLoginTx(wrapped, binding).ok).toBe(false);
  });
});
