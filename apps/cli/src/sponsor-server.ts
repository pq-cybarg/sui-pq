/**
 * Minimal HTTP sponsor for PQ-sponsored gas flow.
 *
 *   PQ_SPONSOR_KEY=<bech32 sui priv>  PQ_GUARD_PKG=0x...  \
 *     pnpm --filter @sui-gen/cli run cli sponsor-serve --port 4000
 *
 * Exposes:
 *   GET  /healthz              → { ok, sponsor }
 *   POST /sponsor              → { digest, effectsStatus, effectsError? }
 *
 * The user POSTs a SponsoredOpRequest JSON; the server hands it to
 * `sponsorPqOperation` which builds + signs + submits the sponsored tx.
 *
 * Production hardening (left to the integrator):
 *   - allowlist `gatedCall.target` so sponsor gas can't be spent arbitrarily
 *   - rate-limit per `pqIdentityId`
 *   - HTTPS + auth header to prevent random parties from spending your gas
 */
import http from 'node:http';
import { type SponsoredOpRequest, base64ToBytes, sponsorPqOperation } from '@sui-gen/pqc';
import { getClient, resolveNetwork, signerFromBech32 } from '@sui-gen/sdk-core';

interface ServeOptions {
  port: number;
  allowedTargets?: Set<string>;
}

export async function startSponsorServer(opts: ServeOptions): Promise<http.Server> {
  const guardPackageId = process.env.PQ_GUARD_PKG;
  const sponsorKey = process.env.PQ_SPONSOR_KEY;
  if (!guardPackageId) throw new Error('PQ_GUARD_PKG env var is required');
  if (!sponsorKey) throw new Error('PQ_SPONSOR_KEY env var is required (suiprivkey1…)');

  const network = resolveNetwork();
  const client = getClient({ network });
  const sponsor = signerFromBech32(sponsorKey);

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/healthz') {
        return json(res, 200, { ok: true, sponsor: sponsor.toSuiAddress(), network });
      }
      if (req.method !== 'POST' || req.url !== '/sponsor') {
        return json(res, 404, { error: 'not found' });
      }

      const body = await readJson(req);
      const requested: SponsoredOpRequest = {
        pqIdentityId: String(body.pqIdentityId),
        actionDigest: base64ToBytes(String(body.actionDigest)),
        pqSignature: base64ToBytes(String(body.pqSignature)),
        gatedCall: body.gatedCall as SponsoredOpRequest['gatedCall'],
      };

      if (opts.allowedTargets && !opts.allowedTargets.has(requested.gatedCall.target)) {
        return json(res, 403, { error: `target ${requested.gatedCall.target} not on allowlist` });
      }

      const out = await sponsorPqOperation(requested, {
        client,
        sponsor,
        guardPackageId,
        maxGasBudget: 200_000_000n,
      });
      return json(res, 200, out);
    } catch (e) {
      return json(res, 400, { error: String(e).slice(0, 600) });
    }
  });

  await new Promise<void>((resolve) => server.listen(opts.port, () => resolve()));
  console.log(`[pq-sponsor] listening on http://localhost:${opts.port}`);
  console.log(`[pq-sponsor]   sponsor address  : ${sponsor.toSuiAddress()}`);
  console.log(`[pq-sponsor]   pq_guard package : ${guardPackageId}`);
  console.log(`[pq-sponsor]   network          : ${network}`);
  if (opts.allowedTargets) {
    console.log(`[pq-sponsor]   target allowlist : ${[...opts.allowedTargets].join(', ')}`);
  } else {
    console.log(
      '[pq-sponsor]   target allowlist : (none — accepting any target; production should set one)',
    );
  }
  return server;
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}
