import type { SuiTransactionBlockResponse } from '@mysten/sui/client';
import type { SuiClient } from '@mysten/sui/client';
import type { Signer } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';

export { Transaction };

export interface ExecuteOptions {
  showEffects?: boolean;
  showEvents?: boolean;
  showObjectChanges?: boolean;
  showBalanceChanges?: boolean;
  /** Wait until the transaction is confirmed. Default: true. */
  waitForCheckpoint?: boolean;
}

const DEFAULT_OPTIONS: Required<ExecuteOptions> = {
  showEffects: true,
  showEvents: true,
  showObjectChanges: true,
  showBalanceChanges: true,
  waitForCheckpoint: true,
};

/** Sign + execute a Transaction and return the full effects/events response. */
export async function executeTx(
  client: SuiClient,
  signer: Signer,
  tx: Transaction,
  opts: ExecuteOptions = {},
): Promise<SuiTransactionBlockResponse> {
  const options = { ...DEFAULT_OPTIONS, ...opts };
  const result = await client.signAndExecuteTransaction({
    transaction: tx,
    signer,
    options: {
      showEffects: options.showEffects,
      showEvents: options.showEvents,
      showObjectChanges: options.showObjectChanges,
      showBalanceChanges: options.showBalanceChanges,
    },
  });

  if (options.waitForCheckpoint) {
    await client.waitForTransaction({ digest: result.digest });
  }
  return result;
}

/** Extract the first created object id of a given Move type from a tx response. */
export function findCreatedObjectId(
  res: SuiTransactionBlockResponse,
  matcher: string | RegExp,
): string | undefined {
  const changes = res.objectChanges ?? [];
  for (const c of changes) {
    if (c.type !== 'created') continue;
    const ok =
      typeof matcher === 'string' ? c.objectType.includes(matcher) : matcher.test(c.objectType);
    if (ok) return c.objectId;
  }
  return undefined;
}
