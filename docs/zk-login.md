# zkLogin

zkLogin lets users sign in with Google/Apple/Facebook/Twitch and produce Sui transactions without ever holding a private key. The protocol uses a zero-knowledge proof over the user's JWT to bind an ephemeral keypair to the OAuth identity.

## Flow

```
1. Generate (ephemeralKey, randomness, maxEpoch)
2. nonce = generateNonce(ephPubKey, maxEpoch, randomness)
3. Redirect user to OAuth provider with that nonce
4. Provider returns id_token (JWT) bound to the nonce
5. Compute address = jwtToAddress(jwt, salt)
6. POST jwt → prover → ZK proof
7. Sign tx with ephemeral key + attach proof as ZkLoginSignature
```

## Setup

```bash
# In .env (server) or .env.local (web):
ZK_LOGIN_PROVER_URL=https://prover-dev.mystenlabs.com/v1
GOOGLE_CLIENT_ID=…apps.googleusercontent.com
```

## Salt

Each (jwt iss, sub) pair must map to a stable user-controlled salt. Options:

- **Hosted salt service** (Mysten Labs runs one): `https://salt.api.mystenlabs.com/get_salt`.
- **Self-hosted**: derive `HMAC(serverSecret, sub || iss)` and serve it from your backend.
- **Client-stored**: store in localStorage / a wallet — loses cross-device portability.

## Production notes

- Use the **production prover** (`https://prover.mystenlabs.com/v1`) on mainnet — the dev prover has rate limits and is reset periodically.
- `maxEpoch` is in *Sui epochs*. Set it 2–10 epochs ahead. Users must re-prove after `maxEpoch` expires.
- ZK proofs are bulky (~6 KB). Cache the proof in sessionStorage and reuse across multiple txs until `maxEpoch` expires.
- Always verify the JWT signature against the provider's JWKs before computing the address — never trust a client-supplied JWT directly server-side.
