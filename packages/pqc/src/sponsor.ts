/**
 * PQ-sponsored gas flow.
 *
 * The "gas paid by PQ" pattern: the user holds NO classical key. They sign a
 * structured request with their SLH-DSA secret key and POST it to a sponsor
 * service. The sponsor — which holds a classical key only for operational
 * reasons (paying gas) — assembles a sponsored Sui transaction whose PTB:
 *
 *   1. calls `pq_guard::unlock(&mut identity, action_digest, pq_signature)`
 *      → aborts (and the whole tx rolls back) if SLH-DSA verify fails
 *   2. calls the user's intended gated operation, consuming the witness
 *
 * The sponsor sets itself as `gasOwner` (so it pays gas) and `sender`
 * (so the validator's classical sig check is satisfied by the sponsor's
 * signature). The user's authority is entirely in the SLH-DSA proof inside
 * the PTB — it never appears as a Sui-level signature.
 *
 * From the user's perspective: they have no classical key, sign nothing in
 * the Sui sense, and yet authorize on-chain operations that the chain treats
 * as atomic. From the chain's perspective: it sees a normal sponsored tx.
 */
import { Transaction, type TransactionArgument } from '@mysten/sui/transactions';
import type { SuiClient } from '@mysten/sui/client';
import type { Signer } from '@mysten/sui/cryptography';
import { addPqGuardUnlock } from './pq-guard.js';

export interface SponsoredOpRequest {
  /** Object id of the user's `PqIdentity`. */
  pqIdentityId: string;
  /** The 32-byte action_digest the user signed (must match the gated op's expected digest). */
  actionDigest: Uint8Array;
  /** SLH-DSA-LITE packed signature over `buildUnlockMessageBytes(sponsor_address, current_nonce, actionDigest)`. */
  pqSignature: Uint8Array;
  /**
   * The gated operation to call after `pq_guard::unlock`. The witness produced
   * by unlock is inserted as `witnessArgIndex` of `arguments`.
   *
   *   target              = "<pkg>::<module>::<function>"
   *   arguments           = transaction-argument descriptors EXCEPT the witness slot
   *   witnessArgIndex     = where in the final argument list the witness goes
   *   typeArguments       = generic type args, if any
   */
  gatedCall: {
    target: `${string}::${string}::${string}`;
    arguments: Array<{ kind: 'object'; id: string } | { kind: 'pure'; type: string; value: unknown }>;
    witnessArgIndex: number;
    typeArguments?: string[];
  };
}

export interface SponsorOptions {
  client: SuiClient;
  /** Sponsor's classical Sui signer (must hold SUI to pay gas). */
  sponsor: Signer;
  /** Deployed `pq_guard` package id. */
  guardPackageId: string;
  /** Maximum gas budget the sponsor is willing to pay per request. */
  maxGasBudget?: bigint;
}

export interface SponsorResult {
  digest: string;
  effectsStatus: 'success' | 'failure';
  effectsError?: string;
}

/**
 * Server-side: validate the request and submit a sponsored tx.
 *
 * Real production deployments should additionally:
 *   - rate-limit per `pqIdentityId`
 *   - allowlist `gatedCall.target` packages so the sponsor's gas can't be
 *     spent on arbitrary calls
 *   - verify the SLH-DSA signature off-chain too (cheap defense in depth;
 *     the on-chain verify is still authoritative)
 */
export async function sponsorPqOperation(
  req: SponsoredOpRequest,
  opts: SponsorOptions,
): Promise<SponsorResult> {
  if (req.actionDigest.length !== 32) {
    throw new Error('actionDigest must be 32 bytes');
  }

  const tx = new Transaction();
  tx.setSender(opts.sponsor.toSuiAddress());
  tx.setGasOwner(opts.sponsor.toSuiAddress());
  if (opts.maxGasBudget) tx.setGasBudget(opts.maxGasBudget);

  // PTB command 1: PQ-verify and produce the witness.
  const auth = addPqGuardUnlock(tx, {
    guardPackageId: opts.guardPackageId,
    identityId: req.pqIdentityId,
    actionDigest: req.actionDigest,
    signature: req.pqSignature,
  });

  // PTB command 2: the gated call, with the witness spliced in at the right index.
  const args: TransactionArgument[] = [];
  let argIdx = 0;
  for (let i = 0; i < req.gatedCall.arguments.length + 1; i++) {
    if (i === req.gatedCall.witnessArgIndex) {
      args.push(auth);
    } else {
      const a = req.gatedCall.arguments[argIdx++]!;
      if (a.kind === 'object') {
        args.push(tx.object(a.id));
      } else {
        // tx.pure.<type> dispatch; default to `tx.pure(value, type)` for arbitrary BCS types
        // Common shortcuts:
        if (a.type === 'address') args.push(tx.pure.address(a.value as string));
        else if (a.type === 'u8') args.push(tx.pure.u8(a.value as number));
        else if (a.type === 'u32') args.push(tx.pure.u32(a.value as number));
        else if (a.type === 'u64') args.push(tx.pure.u64(a.value as bigint));
        else if (a.type === 'u128') args.push(tx.pure.u128(a.value as bigint));
        else if (a.type === 'bool') args.push(tx.pure.bool(a.value as boolean));
        else if (a.type === 'vector<u8>') args.push(tx.pure.vector('u8', a.value as number[]));
        else throw new Error(`unsupported pure type ${a.type} in sponsored request`);
      }
    }
  }

  tx.moveCall({
    target: req.gatedCall.target,
    typeArguments: req.gatedCall.typeArguments ?? [],
    arguments: args,
  });

  const result = await opts.client.signAndExecuteTransaction({
    transaction: tx,
    signer: opts.sponsor,
    options: { showEffects: true },
  });

  const status = result.effects?.status?.status ?? 'failure';
  return {
    digest: result.digest,
    effectsStatus: status,
    effectsError: result.effects?.status?.error,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Client side
// ────────────────────────────────────────────────────────────────────────────

export interface PqSponsoredClientOptions {
  /** URL of a server that exposes the sponsorPqOperation logic over HTTP. */
  endpoint: string;
  /** Optional fetch override (testing, edge runtimes, etc.). */
  fetcher?: typeof fetch;
}

/**
 * Client: POST a `SponsoredOpRequest` to a sponsor service. The user signs
 * the SLH-DSA proof locally (`@sui-gen/pqc/slh.sign`) and never touches a
 * classical key.
 */
export class PqSponsoredClient {
  constructor(private readonly opts: PqSponsoredClientOptions) {}

  async submit(req: SponsoredOpRequest): Promise<SponsorResult> {
    const payload = {
      pqIdentityId: req.pqIdentityId,
      actionDigest: bytesToBase64(req.actionDigest),
      pqSignature: bytesToBase64(req.pqSignature),
      gatedCall: req.gatedCall,
    };
    const fetcher = this.opts.fetcher ?? fetch;
    const res = await fetcher(this.opts.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`sponsor ${res.status}: ${await res.text()}`);
    return (await res.json()) as SponsorResult;
  }
}

// JSON-friendly base64 codec (server decodes back to bytes before calling sponsorPqOperation).
function bytesToBase64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  // btoa is available in browser and modern Node
  return typeof btoa !== 'undefined' ? btoa(s) : Buffer.from(b).toString('base64');
}

export function base64ToBytes(s: string): Uint8Array {
  const bin = typeof atob !== 'undefined' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
