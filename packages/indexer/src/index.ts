/**
 * Lightweight event indexer.
 * Polls `client.queryEvents` with cursor persistence and dispatches to a handler.
 * For higher-throughput indexing, switch to Sui's GraphQL streaming subscriptions
 * or run your own checkpoint reader (sui-indexer crate).
 */
import type { SuiClient, SuiEvent, SuiEventFilter } from '@mysten/sui/client';
import { type Network, getClient } from '@sui-gen/sdk-core';

export interface CursorStore {
  load(key: string): Promise<{ txDigest: string; eventSeq: string } | null>;
  save(key: string, cursor: { txDigest: string; eventSeq: string }): Promise<void>;
}

export class InMemoryCursorStore implements CursorStore {
  private data = new Map<string, { txDigest: string; eventSeq: string }>();
  async load(key: string) {
    return this.data.get(key) ?? null;
  }
  async save(key: string, cursor: { txDigest: string; eventSeq: string }) {
    this.data.set(key, cursor);
  }
}

export interface PollOptions {
  client?: SuiClient;
  network?: Network;
  filter: SuiEventFilter;
  /** Key used to namespace the cursor. */
  cursorKey: string;
  store?: CursorStore;
  /** Page size per RPC call. */
  limit?: number;
  /** Poll interval ms. */
  intervalMs?: number;
}

export type EventHandler = (event: SuiEvent) => Promise<void> | void;

/** Begin polling. Returns a `stop()` function. */
export function startPolling(opts: PollOptions, handle: EventHandler): () => void {
  const client = opts.client ?? getClient({ network: opts.network });
  const store = opts.store ?? new InMemoryCursorStore();
  const intervalMs = opts.intervalMs ?? 2000;
  const limit = opts.limit ?? 50;
  let cancelled = false;

  async function tick() {
    while (!cancelled) {
      const cursor = await store.load(opts.cursorKey);
      const page = await client.queryEvents({
        query: opts.filter,
        cursor: cursor ?? undefined,
        limit,
        order: 'ascending',
      });
      for (const ev of page.data) await handle(ev);
      if (page.nextCursor) await store.save(opts.cursorKey, page.nextCursor);
      if (!page.hasNextPage) await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  void tick();
  return () => {
    cancelled = true;
  };
}

/** One-shot fetch of recent events matching a filter. */
export async function fetchRecent(opts: Omit<PollOptions, 'cursorKey' | 'store'>, count = 25) {
  const client = opts.client ?? getClient({ network: opts.network });
  const page = await client.queryEvents({
    query: opts.filter,
    limit: count,
    order: 'descending',
  });
  return page.data;
}

/** Run a GraphQL query against the Sui GraphQL endpoint. */
export async function gqlQuery<T = unknown>(
  query: string,
  variables: Record<string, unknown> = {},
  url = process.env.INDEXER_GRAPHQL_URL ?? 'https://sui-mainnet.mystenlabs.com/graphql',
): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  if (!res.ok) throw new Error(`GraphQL failed: ${res.status}`);
  const json = (await res.json()) as { data: T; errors?: unknown };
  if (json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}
