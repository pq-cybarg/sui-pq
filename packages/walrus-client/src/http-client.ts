/**
 * HTTP-only Walrus client. Uses public Walrus publishers/aggregators —
 * no Sui wallet required, but the publisher pays the storage fee in WAL/SUI.
 *
 * For client-side control (paying with your own WAL), see `./sui-client.ts`.
 */
import { type WalrusEndpoints, endpointsFromEnv } from './config.js';

export interface PutBlobOptions {
  /** Number of storage epochs (default 5, max ~53 on testnet). */
  epochs?: number;
  /** Send blob ownership to this Sui address; default keeps it with publisher. */
  sendTo?: string;
  /** Optional content-type hint, set as the request body header. */
  contentType?: string;
}

export interface PutBlobResult {
  blobId: string;
  /** Sui object id of the Blob (only present when sendTo provided). */
  blobObjectId?: string;
  /** Sui object id of the Storage resource. */
  storageObjectId?: string;
  /** Epoch number at which the blob will expire. */
  endEpoch?: number;
  /** Whether the blob was already certified before this request. */
  alreadyCertified: boolean;
  raw: unknown;
}

export class WalrusHttpClient {
  readonly endpoints: WalrusEndpoints;

  constructor(endpoints?: Partial<WalrusEndpoints>) {
    const base = endpointsFromEnv();
    this.endpoints = { ...base, ...endpoints };
  }

  /** Upload a blob via the publisher REST API. */
  async put(data: Uint8Array | Blob | string, opts: PutBlobOptions = {}): Promise<PutBlobResult> {
    const epochs = opts.epochs ?? Number(process.env.WALRUS_EPOCHS ?? 5);
    const url = new URL('/v1/blobs', this.endpoints.publisher);
    url.searchParams.set('epochs', String(epochs));
    if (opts.sendTo) url.searchParams.set('send_object_to', opts.sendTo);

    const body: BodyInit =
      typeof data === 'string' ? new TextEncoder().encode(data) : (data as BodyInit);

    const res = await fetch(url, {
      method: 'PUT',
      headers: opts.contentType ? { 'Content-Type': opts.contentType } : undefined,
      body,
    });
    if (!res.ok) {
      throw new Error(`Walrus PUT failed: ${res.status} ${await res.text()}`);
    }
    const json = (await res.json()) as Record<string, unknown>;

    const newlyCreated = (json as { newlyCreated?: unknown }).newlyCreated;
    const alreadyCert = (json as { alreadyCertified?: unknown }).alreadyCertified;
    const node = newlyCreated ?? alreadyCert;

    const blobId =
      this.#pluck<string>(node, ['blobObject', 'blobId']) ?? this.#pluck<string>(node, ['blobId']);
    if (!blobId) {
      throw new Error(`Walrus PUT returned no blobId: ${JSON.stringify(json)}`);
    }
    return {
      blobId,
      blobObjectId: this.#pluck<string>(node, ['blobObject', 'id']),
      storageObjectId: this.#pluck<string>(node, ['blobObject', 'storage', 'id']),
      endEpoch: this.#pluck<number>(node, ['blobObject', 'storage', 'endEpoch']),
      alreadyCertified: Boolean(alreadyCert),
      raw: json,
    };
  }

  /** Stream a blob from the aggregator. */
  async get(blobId: string): Promise<Uint8Array> {
    const res = await fetch(`${this.endpoints.aggregator}/v1/blobs/${encodeURIComponent(blobId)}`);
    if (!res.ok) {
      throw new Error(`Walrus GET failed: ${res.status} ${await res.text()}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }

  /** Get blob as text. */
  async getText(blobId: string): Promise<string> {
    return new TextDecoder().decode(await this.get(blobId));
  }

  /** Aggregator URL where this blob can be fetched directly (eg. for <img src=…>). */
  url(blobId: string): string {
    return `${this.endpoints.aggregator}/v1/blobs/${encodeURIComponent(blobId)}`;
  }

  #pluck<T = string>(obj: unknown, path: string[]): T | undefined {
    let cur: unknown = obj;
    for (const k of path) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[k];
    }
    return cur as T | undefined;
  }
}
