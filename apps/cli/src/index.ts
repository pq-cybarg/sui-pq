#!/usr/bin/env node
import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { getLwaBalance } from '@sui-gen/lumiwave';
import { getClient, requestFaucet, resolveNetwork, signerFromEnv } from '@sui-gen/sdk-core';
import { WalrusHttpClient } from '@sui-gen/walrus-client';
import { cac } from 'cac';

const cli = cac('sui-gen');

cli
  .command('balance <address>', 'Show SUI balance for an address')
  .action(async (address: string) => {
    const client = getClient();
    const { totalBalance } = await client.getBalance({ owner: address });
    console.log(`SUI: ${totalBalance} (network=${resolveNetwork()})`);
  });

cli
  .command('faucet [address]', 'Drip SUI to an address from the active network faucet')
  .action(async (address?: string) => {
    const addr = address ?? process.env.SUI_SENDER_ADDRESS;
    if (!addr) throw new Error('Pass an address or set SUI_SENDER_ADDRESS');
    await requestFaucet(addr, resolveNetwork());
    console.log(`Requested faucet for ${addr}`);
  });

cli.command('publish <path>', 'Publish a Move package via sui CLI').action((path: string) => {
  const abs = resolve(path);
  if (!existsSync(join(abs, 'Move.toml'))) throw new Error(`No Move.toml at ${abs}`);
  execSync(`sui client publish --gas-budget 200000000 ${abs}`, { stdio: 'inherit' });
});

cli
  .command('lwa-balance <address>', 'Show LWA (Lumiwave) balance')
  .action(async (address: string) => {
    console.log((await getLwaBalance(address)).toString());
  });

cli
  .command('walrus-upload <file>', 'Upload a file to Walrus')
  .option('--epochs <n>', 'Number of storage epochs', { default: 5 })
  .action(async (file: string, opts: { epochs: number }) => {
    const buf = new Uint8Array(readFileSync(resolve(file)));
    const client = new WalrusHttpClient();
    const res = await client.put(buf, { epochs: Number(opts.epochs) });
    console.log(JSON.stringify(res, null, 2));
  });

cli
  .command('walrus-download <blobId>', 'Download a blob from Walrus and print to stdout')
  .action(async (blobId: string) => {
    const client = new WalrusHttpClient();
    process.stdout.write(await client.get(blobId));
  });

cli.command('whoami', 'Show active env-derived signer address').action(() => {
  const signer = signerFromEnv();
  console.log(signer.toSuiAddress());
});

cli
  .command('sponsor-serve', 'Run the PQ-sponsored gas HTTP service')
  .option('--port <port>', 'TCP port to listen on', { default: 4000 })
  .option('--allow <target>', 'Restrict gatedCall.target to this value (repeat to add more)')
  .action(async (opts: { port: number; allow?: string | string[] }) => {
    const { startSponsorServer } = await import('./sponsor-server.js');
    const allow = opts.allow
      ? new Set(Array.isArray(opts.allow) ? opts.allow : [opts.allow])
      : undefined;
    await startSponsorServer({ port: Number(opts.port), allowedTargets: allow });
  });

cli
  .command(
    'pq-address',
    'Derive an SLH-DSA-LITE Sui address from a seed (no classical key anywhere)',
  )
  .option('--seed <hex>', 'PK.seed 32-byte hex (default: 0xcc repeated)', {
    default: 'cc'.repeat(32),
  })
  .option('--sk-seed <hex>', 'SK seed 32-byte hex (default: 0xdd repeated)', {
    default: 'dd'.repeat(32),
  })
  .action(async (opts: { seed: string; skSeed: string }) => {
    const { slh, slhDsaAddress } = await import('@sui-gen/pqc');
    const seed = Buffer.from(opts.seed, 'hex');
    const skSeed = Buffer.from(opts.skSeed, 'hex');
    if (seed.length !== 32 || skSeed.length !== 32) {
      throw new Error('--seed and --sk-seed must each be 32 bytes (64 hex chars)');
    }
    const { pk } = slh.keygen(new Uint8Array(seed), new Uint8Array(skSeed));
    console.log(slhDsaAddress(pk));
  });

cli
  .command(
    'pq-send <recipient> <amount>',
    'Send SUI via a PQ-only signature (requires patched local validator on port 9000)',
  )
  .option('--seed <hex>', 'PK.seed 32-byte hex', { default: 'cc'.repeat(32) })
  .option('--sk-seed <hex>', 'SK seed 32-byte hex', { default: 'dd'.repeat(32) })
  .action(async (recipient: string, amount: string, opts: { seed: string; skSeed: string }) => {
    const { Transaction } = await import('@mysten/sui/transactions');
    const { SuiClient } = await import('@mysten/sui/client');
    const { slh, slhDsaAddress, signAndExecuteSlhDsa } = await import('@sui-gen/pqc');
    const seed = new Uint8Array(Buffer.from(opts.seed, 'hex'));
    const skSeed = new Uint8Array(Buffer.from(opts.skSeed, 'hex'));
    const { pk, sk } = slh.keygen(seed, skSeed);
    const sender = slhDsaAddress(pk);
    const client = new SuiClient({ url: process.env.SUI_RPC_URL ?? 'http://127.0.0.1:9000' });
    console.log(`sender (PQ-derived): ${sender}`);
    console.log(`recipient:           ${recipient}`);
    console.log(`amount:              ${amount} MIST`);
    const tx = new Transaction();
    const [coin] = tx.splitCoins(tx.gas, [BigInt(amount)]);
    tx.transferObjects([coin], recipient);
    const res = await signAndExecuteSlhDsa({ client, transaction: tx, pk, sk });
    console.log(`digest: ${res.digest}`);
    console.log(`status: ${res.effects?.status?.status ?? '?'}`);
  });

cli.help();
cli.version('0.1.0');

try {
  cli.parse(process.argv, { run: false });
  await cli.runMatchedCommand();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
