/**
 * Identifier bytes for the PQ scheme of a stored attestation.
 *
 * Wire format: 1 byte. Reserved range 0x00–0x7F for NIST/FIPS schemes,
 * 0x80–0xFE for future / experimental, 0xFF for "unspecified — pass-through".
 *
 * The byte is what gets stored as `scheme: u8` in the Move attestation object,
 * and what `fastcrypto`'s SLH-DSA verifier (when exposed) will key off when
 * an on-chain verifier is shipped. Don't reorder; treat as a wire enum.
 */
export const SCHEME = {
  ML_DSA_44: 0x10, // FIPS 204, security category 2
  ML_DSA_65: 0x11, // FIPS 204, security category 3
  ML_DSA_87: 0x12, // FIPS 204, security category 5
  SLH_DSA_SHA2_128S: 0x20,
  SLH_DSA_SHA2_128F: 0x21,
  SLH_DSA_SHA2_192S: 0x22,
  SLH_DSA_SHA2_192F: 0x23,
  SLH_DSA_SHA2_256S: 0x24,
  SLH_DSA_SHA2_256F: 0x25,
  SLH_DSA_SHAKE_128S: 0x28,
  SLH_DSA_SHAKE_128F: 0x29,
  SLH_DSA_SHAKE_192S: 0x2a,
  SLH_DSA_SHAKE_192F: 0x2b,
  SLH_DSA_SHAKE_256S: 0x2c,
  SLH_DSA_SHAKE_256F: 0x2d,
  FALCON_512: 0x30,
  FALCON_1024: 0x31,
} as const;

export type SchemeName = keyof typeof SCHEME;
export type SchemeByte = (typeof SCHEME)[SchemeName];

const NAME_BY_BYTE: Record<number, SchemeName> = Object.fromEntries(
  Object.entries(SCHEME).map(([k, v]) => [v as number, k as SchemeName]),
);

export function schemeName(byte: number): SchemeName | 'UNKNOWN' {
  return NAME_BY_BYTE[byte] ?? 'UNKNOWN';
}

export interface SchemeMeta {
  byte: SchemeByte;
  name: SchemeName;
  /** NIST security category (1, 2, 3, or 5). */
  category: 1 | 2 | 3 | 5;
  publicKeyBytes: number;
  signatureBytes: number;
  /** Bytes the secret key occupies in noble's serialization. */
  secretKeyBytes: number;
}

/** FIPS-defined sizes. Source: FIPS 204, FIPS 205. */
export const SCHEME_META: Record<SchemeName, SchemeMeta> = {
  ML_DSA_44: {
    byte: SCHEME.ML_DSA_44,
    name: 'ML_DSA_44',
    category: 2,
    publicKeyBytes: 1312,
    signatureBytes: 2420,
    secretKeyBytes: 2560,
  },
  ML_DSA_65: {
    byte: SCHEME.ML_DSA_65,
    name: 'ML_DSA_65',
    category: 3,
    publicKeyBytes: 1952,
    signatureBytes: 3309,
    secretKeyBytes: 4032,
  },
  ML_DSA_87: {
    byte: SCHEME.ML_DSA_87,
    name: 'ML_DSA_87',
    category: 5,
    publicKeyBytes: 2592,
    signatureBytes: 4627,
    secretKeyBytes: 4896,
  },
  SLH_DSA_SHA2_128S: {
    byte: SCHEME.SLH_DSA_SHA2_128S,
    name: 'SLH_DSA_SHA2_128S',
    category: 1,
    publicKeyBytes: 32,
    signatureBytes: 7856,
    secretKeyBytes: 64,
  },
  SLH_DSA_SHA2_128F: {
    byte: SCHEME.SLH_DSA_SHA2_128F,
    name: 'SLH_DSA_SHA2_128F',
    category: 1,
    publicKeyBytes: 32,
    signatureBytes: 17088,
    secretKeyBytes: 64,
  },
  SLH_DSA_SHA2_192S: {
    byte: SCHEME.SLH_DSA_SHA2_192S,
    name: 'SLH_DSA_SHA2_192S',
    category: 3,
    publicKeyBytes: 48,
    signatureBytes: 16224,
    secretKeyBytes: 96,
  },
  SLH_DSA_SHA2_192F: {
    byte: SCHEME.SLH_DSA_SHA2_192F,
    name: 'SLH_DSA_SHA2_192F',
    category: 3,
    publicKeyBytes: 48,
    signatureBytes: 35664,
    secretKeyBytes: 96,
  },
  SLH_DSA_SHA2_256S: {
    byte: SCHEME.SLH_DSA_SHA2_256S,
    name: 'SLH_DSA_SHA2_256S',
    category: 5,
    publicKeyBytes: 64,
    signatureBytes: 29792,
    secretKeyBytes: 128,
  },
  SLH_DSA_SHA2_256F: {
    byte: SCHEME.SLH_DSA_SHA2_256F,
    name: 'SLH_DSA_SHA2_256F',
    category: 5,
    publicKeyBytes: 64,
    signatureBytes: 49856,
    secretKeyBytes: 128,
  },
  SLH_DSA_SHAKE_128S: {
    byte: SCHEME.SLH_DSA_SHAKE_128S,
    name: 'SLH_DSA_SHAKE_128S',
    category: 1,
    publicKeyBytes: 32,
    signatureBytes: 7856,
    secretKeyBytes: 64,
  },
  SLH_DSA_SHAKE_128F: {
    byte: SCHEME.SLH_DSA_SHAKE_128F,
    name: 'SLH_DSA_SHAKE_128F',
    category: 1,
    publicKeyBytes: 32,
    signatureBytes: 17088,
    secretKeyBytes: 64,
  },
  SLH_DSA_SHAKE_192S: {
    byte: SCHEME.SLH_DSA_SHAKE_192S,
    name: 'SLH_DSA_SHAKE_192S',
    category: 3,
    publicKeyBytes: 48,
    signatureBytes: 16224,
    secretKeyBytes: 96,
  },
  SLH_DSA_SHAKE_192F: {
    byte: SCHEME.SLH_DSA_SHAKE_192F,
    name: 'SLH_DSA_SHAKE_192F',
    category: 3,
    publicKeyBytes: 48,
    signatureBytes: 35664,
    secretKeyBytes: 96,
  },
  SLH_DSA_SHAKE_256S: {
    byte: SCHEME.SLH_DSA_SHAKE_256S,
    name: 'SLH_DSA_SHAKE_256S',
    category: 5,
    publicKeyBytes: 64,
    signatureBytes: 29792,
    secretKeyBytes: 128,
  },
  SLH_DSA_SHAKE_256F: {
    byte: SCHEME.SLH_DSA_SHAKE_256F,
    name: 'SLH_DSA_SHAKE_256F',
    category: 5,
    publicKeyBytes: 64,
    signatureBytes: 49856,
    secretKeyBytes: 128,
  },
  FALCON_512: {
    byte: SCHEME.FALCON_512,
    name: 'FALCON_512',
    category: 1,
    publicKeyBytes: 897,
    signatureBytes: 666,
    secretKeyBytes: 1281,
  },
  FALCON_1024: {
    byte: SCHEME.FALCON_1024,
    name: 'FALCON_1024',
    category: 5,
    publicKeyBytes: 1793,
    signatureBytes: 1280,
    secretKeyBytes: 2305,
  },
};
