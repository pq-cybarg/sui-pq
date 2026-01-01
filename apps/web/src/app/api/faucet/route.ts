/**
 * Same-origin faucet proxy. Lets the browser POST to /api/faucet instead of
 * cross-origin to the public testnet faucet or to localhost:9123 — the
 * browser blocks the local POST because the Sui faucet doesn't set CORS
 * headers, and the public faucet doesn't always either.
 *
 * The proxy runs in the Next.js dev/runtime process (Node), which can
 * reach both localhost and remote endpoints without CORS concerns.
 *
 * Request:  POST /api/faucet
 * Body:     { recipient: '0x…', faucetUrl: 'http://127.0.0.1:9123/gas' }
 * Response: faucet's body, status, and the same Content-Type — OR a
 *           structured 502 with a `hint` field when the upstream is
 *           unreachable (most commonly: no local validator running).
 */
export async function POST(req: Request) {
  let recipient = '';
  let faucetUrl = '';
  try {
    const body = (await req.json()) as { recipient?: string; faucetUrl?: string };
    recipient = String(body.recipient ?? '');
    faucetUrl = String(body.faucetUrl ?? '');
  } catch {
    return Response.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  if (!recipient.startsWith('0x')) {
    return Response.json({ error: 'recipient must be a 0x-prefixed Sui address' }, { status: 400 });
  }
  if (!/^https?:\/\//.test(faucetUrl)) {
    return Response.json({ error: 'faucetUrl must be http(s)://' }, { status: 400 });
  }

  const isLocal = /^https?:\/\/(127\.0\.0\.1|localhost)/.test(faucetUrl);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const upstream = await fetch(faucetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ FixedAmountRequest: { recipient } }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: { 'Content-Type': upstream.headers.get('content-type') ?? 'application/json' },
    });
  } catch (e) {
    clearTimeout(timeout);
    const msg = String((e as Error)?.message ?? e);
    const hint = isLocal
      ? `local faucet at ${faucetUrl} isn't reachable. Start your local Sui validator:\n  $ sui start --with-faucet`
      : 'upstream faucet did not respond (rate-limit / network / CORS / DNS). Try the CLI instead:\n  $ sui client faucet';
    return Response.json({ error: msg, hint }, { status: 502 });
  }
}
