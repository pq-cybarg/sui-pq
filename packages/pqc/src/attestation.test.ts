import { describe, expect, it } from 'vitest';
import { buildAttestation, verifyAttestation } from './attestation.js';
import { SCHEME_META } from './schemes.js';

const ADDR = '0x' + '11'.repeat(32);

describe('PQ attestations', () => {
  it('ML_DSA_44 round-trips', () => {
    const { attestation } = buildAttestation({
      scheme: 'ML_DSA_44',
      suiAddress: ADDR,
      appTag: 'unit-test',
    });
    expect(attestation.publicKey.length).toBe(SCHEME_META.ML_DSA_44.publicKeyBytes);
    expect(attestation.signature.length).toBe(SCHEME_META.ML_DSA_44.signatureBytes);
    expect(verifyAttestation(attestation).ok).toBe(true);
  });

  it('tampering with appTag invalidates the attestation', () => {
    const { attestation } = buildAttestation({
      scheme: 'ML_DSA_44',
      suiAddress: ADDR,
      appTag: 'unit-test',
    });
    const tampered = { ...attestation, appTag: new TextEncoder().encode('different') };
    const res = verifyAttestation(tampered);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/digest mismatch/);
  });

  it('tampering with signature bytes fails verification', () => {
    const { attestation } = buildAttestation({
      scheme: 'ML_DSA_44',
      suiAddress: ADDR,
      appTag: 'unit-test',
    });
    const sig = new Uint8Array(attestation.signature);
    sig[0] = ((sig[0] ?? 0) ^ 0xff) & 0xff;
    expect(verifyAttestation({ ...attestation, signature: sig }).ok).toBe(false);
  });
});
