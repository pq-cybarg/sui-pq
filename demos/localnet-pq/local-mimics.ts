/**
 * Local mimics of the off-Sui live networks the ecosystem packages talk to, so
 * each package's REAL client code can run end-to-end against 127.0.0.1 with no
 * public endpoint — and, where the package also touches Sui, against the
 * post-quantum localnet.
 *
 * These speak each network's actual wire protocol (REST shapes / response
 * schemas) faithfully enough that the unmodified `@sui-gen/*` client drives
 * them. Crypto-bearing services (Seal key servers, zkLogin prover, a Wormhole
 * guardian for Pyth/bridge) need real key material — those are stood up
 * separately (see pq-pyth.ts etc.); this module covers the REST services.
 */
import { type Server, createServer } from 'node:http';

export interface Mimic {
  url: string;
  close: () => void;
}

function listen(
  handler: (
    req: import('node:http').IncomingMessage,
    body: Buffer,
    res: import('node:http').ServerResponse,
  ) => void,
): Promise<Mimic> {
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => handler(req, Buffer.concat(chunks), res));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

const json = (res: import('node:http').ServerResponse, code: number, body: unknown) => {
  res.statusCode = code;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
};

/**
 * Walrus publisher + aggregator. `PUT /v1/blobs` stores bytes and returns the
 * `newlyCreated.blobObject` shape the client parses; `GET /v1/blobs/:id`
 * streams them back. Faithful to the public Walrus HTTP API.
 */
export function startWalrus(): Promise<Mimic> {
  const store = new Map<string, Buffer>();
  return listen((req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (req.method === 'PUT' && url.pathname === '/v1/blobs') {
      const id = `blob-${body.toString('hex').slice(0, 24) || 'empty'}`;
      store.set(id, body);
      return json(res, 200, {
        newlyCreated: {
          blobObject: {
            blobId: id,
            id: `0x${'a'.repeat(64)}`,
            storage: { id: `0x${'b'.repeat(64)}`, endEpoch: 5 },
          },
        },
      });
    }
    if (req.method === 'GET' && url.pathname.startsWith('/v1/blobs/')) {
      const blob = store.get(decodeURIComponent(url.pathname.split('/').pop() ?? ''));
      if (!blob) {
        res.statusCode = 404;
        return res.end('not found');
      }
      return res.end(blob);
    }
    res.statusCode = 404;
    res.end('nope');
  });
}

/**
 * Lumiwave REST service. Mimics the partner API surface the client uses:
 * `GET /v1/users/:handle` → `{ address }` (handle resolution), plus a generic
 * echo for other GET/POST paths so `LumiwaveService.get/post` round-trip.
 */
export function startLumiwave(handles: Record<string, string>): Promise<Mimic> {
  return listen((req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const userMatch = url.pathname.match(/^\/v1\/users\/(.+)$/);
    if (req.method === 'GET' && userMatch) {
      const handle = decodeURIComponent(userMatch[1]);
      const address = handles[handle];
      if (!address) {
        res.statusCode = 404;
        return res.end('unknown handle');
      }
      return json(res, 200, { address, handle });
    }
    if (req.method === 'POST') {
      return json(res, 200, { ok: true, echo: body.length ? JSON.parse(body.toString()) : null });
    }
    return json(res, 200, { ok: true, path: url.pathname });
  });
}

/**
 * Pyth Hermes price-feed mimic: `GET /v2/updates/price/latest?ids[]=…` returns
 * a base64 price-update payload. (For an on-chain price *update*, the payload
 * must be a Wormhole VAA signed by a guardian the on-chain Wormhole trusts —
 * see pq-pyth.ts, which runs a local guardian. This serves whatever VAA it's
 * given so the client's fetch path is exercised against a local endpoint.)
 */
export function startHermes(vaaBase64: string): Promise<Mimic> {
  return listen((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (
      url.pathname.startsWith('/v2/updates/price/latest') ||
      url.pathname.startsWith('/api/latest_vaas')
    ) {
      return json(res, 200, { binary: { encoding: 'base64', data: [vaaBase64] }, parsed: [] });
    }
    return json(res, 200, [vaaBase64]);
  });
}
