import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
/**
 * zkLogin: sign in with Google/Apple/Facebook/Twitch and get a Sui address derived
 * from a ZK proof over your JWT. No private key custody required.
 *
 * Flow (client-side):
 *   1. Generate an ephemeral Ed25519 keypair + randomness + maxEpoch.
 *   2. Build a nonce = jwtToZkLoginNonce(pubKey, maxEpoch, randomness).
 *   3. Open the OAuth provider's authorize URL with that nonce.
 *   4. Provider returns a JWT bound to the nonce.
 *   5. Fetch a user-specific salt from your salt service (or generate yourself).
 *   6. Compute the user's Sui address: jwtToAddress(jwt, salt).
 *   7. POST { jwt, ephPubKey, maxEpoch, randomness, salt } to the prover URL.
 *   8. Sign txs with the ephemeral key + attach the ZK proof in a `ZkLoginSignature`.
 */
import {
  computeZkLoginAddress,
  generateNonce,
  generateRandomness,
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  jwtToAddress,
  parseZkLoginSignature,
} from '@mysten/sui/zklogin';
import { decodeJwt } from 'jose';

export {
  computeZkLoginAddress,
  generateNonce,
  generateRandomness,
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  jwtToAddress,
  parseZkLoginSignature,
};

export interface ZkLoginSetup {
  ephemeralKeyPair: Ed25519Keypair;
  randomness: string;
  maxEpoch: number;
  nonce: string;
}

/**
 * Bootstrap the client-side state needed before sending the user to the OAuth provider.
 * Persist `randomness` + the ephemeral secret key to sessionStorage and re-hydrate on
 * the OAuth callback to complete sign-in.
 */
export function beginZkLogin(currentEpoch: number, epochsAhead = 2): ZkLoginSetup {
  const ephemeralKeyPair = new Ed25519Keypair();
  const randomness = generateRandomness();
  const maxEpoch = currentEpoch + epochsAhead;
  const nonce = generateNonce(ephemeralKeyPair.getPublicKey(), maxEpoch, randomness);
  return { ephemeralKeyPair, randomness, maxEpoch, nonce };
}

export interface OAuthProvider {
  name: 'google' | 'facebook' | 'apple' | 'twitch' | 'kakao' | 'slack';
  authorizeUrl: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
}

/** Construct the authorize URL for an OAuth provider with a zkLogin-compatible nonce. */
export function buildAuthorizeUrl(provider: OAuthProvider, nonce: string): string {
  const url = new URL(provider.authorizeUrl);
  url.searchParams.set('client_id', provider.clientId);
  url.searchParams.set('redirect_uri', provider.redirectUri);
  url.searchParams.set('response_type', 'id_token');
  url.searchParams.set('scope', provider.scope ?? 'openid email');
  url.searchParams.set('nonce', nonce);
  return url.toString();
}

/** Extract the standard `sub` and `aud` claims from a JWT. */
export function parseJwtClaims(jwt: string): { sub: string; aud: string | string[]; iss: string } {
  const claims = decodeJwt(jwt);
  return {
    sub: String(claims.sub ?? ''),
    aud: (claims.aud as string | string[]) ?? '',
    iss: String(claims.iss ?? ''),
  };
}

export interface ProverRequest {
  jwt: string;
  extendedEphemeralPublicKey: string;
  maxEpoch: number;
  jwtRandomness: string;
  salt: string;
  keyClaimName: 'sub' | 'email';
}

export interface ProverResponse {
  proofPoints: { a: string[]; b: string[][]; c: string[] };
  issBase64Details: { value: string; indexMod4: number };
  headerBase64: string;
}

/** POST to a Mysten-style zkLogin prover service and return the ZK proof. */
export async function fetchZkProof(proverUrl: string, req: ProverRequest): Promise<ProverResponse> {
  const res = await fetch(proverUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(`Prover failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as ProverResponse;
}
