/**
 * Lumiwave service client. The Lumiwave platform exposes a REST/JSON-RPC service that
 * partner game studios use to mint reward NFTs, look up user profiles, and trigger
 * IP-licensed events. The exact schema is partner-specific; this client is intentionally
 * thin so callers can layer their own typed surface on top.
 */
import { DEFAULT_LUMIWAVE_CONFIG, type LumiwaveConfig } from './config.js';

export interface LumiwaveServiceOptions extends Partial<LumiwaveConfig> {
  fetch?: typeof fetch;
}

export class LumiwaveService {
  private readonly config: LumiwaveConfig;
  private readonly fetcher: typeof fetch;

  constructor(opts: LumiwaveServiceOptions = {}) {
    this.config = { ...DEFAULT_LUMIWAVE_CONFIG, ...opts };
    this.fetcher = opts.fetch ?? fetch;
  }

  /** GET against the Lumiwave REST API. */
  async get<T = unknown>(path: string, query?: Record<string, string | number>): Promise<T> {
    const url = new URL(path, this.config.rpcUrl);
    if (query) {
      for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v));
    }
    const res = await this.fetcher(url, { headers: this.#headers() });
    if (!res.ok) throw new Error(`Lumiwave GET ${path} failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as T;
  }

  /** POST against the Lumiwave REST API. */
  async post<T = unknown>(path: string, body: unknown): Promise<T> {
    const res = await this.fetcher(new URL(path, this.config.rpcUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.#headers() },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Lumiwave POST ${path} failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as T;
  }

  /** Resolve a Lumiwave user handle → Sui address. */
  async resolveHandle(handle: string): Promise<{ address: string } | null> {
    try {
      return await this.get<{ address: string }>(`/v1/users/${encodeURIComponent(handle)}`);
    } catch {
      return null;
    }
  }

  #headers(): Record<string, string> {
    return this.config.apiKey ? { Authorization: `Bearer ${this.config.apiKey}` } : {};
  }
}
