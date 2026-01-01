import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import type { Signer } from '@mysten/sui/cryptography';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import { Secp256r1Keypair } from '@mysten/sui/keypairs/secp256r1';

/**
 * Build a Signer from a Bech32 `suiprivkey1…` string. Detects the keypair scheme automatically.
 */
export function signerFromBech32(privKey: string): Signer {
  const { schema, secretKey } = decodeSuiPrivateKey(privKey);
  switch (schema) {
    case 'ED25519':
      return Ed25519Keypair.fromSecretKey(secretKey);
    case 'Secp256k1':
      return Secp256k1Keypair.fromSecretKey(secretKey);
    case 'Secp256r1':
      return Secp256r1Keypair.fromSecretKey(secretKey);
    default:
      throw new Error(`Unsupported key scheme: ${schema}`);
  }
}

/**
 * Build a signer from the SUI_PRIVATE_KEY env var. Throws if missing.
 * For CI/scripting use. Never call from browser code.
 */
export function signerFromEnv(envName = 'SUI_PRIVATE_KEY'): Signer {
  const v = process.env[envName];
  if (!v) throw new Error(`Missing env var ${envName}`);
  return signerFromBech32(v);
}

/** Ephemeral key for tests / dev. */
export function newEphemeralSigner(): Ed25519Keypair {
  return new Ed25519Keypair();
}
