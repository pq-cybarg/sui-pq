/**
 * Mnemonic-derived, post-quantum-only end-to-end demo on the patched validator.
 *
 * Uses the patched `sui` CLI (built from ~/.local/share/pq-sui/sui) to:
 *   1. derive an SLH-DSA-SHA2-128s account from a BIP-39 mnemonic
 *      (`sui client new-address slhdsa`),
 *   2. prove the derivation is deterministic by re-importing the same mnemonic
 *      into two independent, isolated keystores and checking the address,
 *   3. fund the post-quantum address from the localnet faucet, and
 *   4. execute a real on-chain transfer signed by ONLY the SLH-DSA key — the
 *      CLI keystore holds no elliptic-curve key for this account at all.
 *
 * Runs entirely in a throwaway `SUI_CONFIG_DIR`, so it never touches the
 * operator's real `~/.sui` keystore (which the stock `sui`, unaware of the
 * 0x07 scheme, also reads). Everything is local: the patched validator on
 * 127.0.0.1:9000 and its faucet on :9123. No public endpoint is contacted.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Transaction } from '@mysten/sui/transactions';
import { LOCALNET_FAUCET, LOCALNET_RPC, client, sleep } from './lib.js';
import { type PqAccount, pqExec } from './pq-sign.js';

const SUI = `${process.env.HOME}/.local/share/pq-sui/sui/target/release/sui`;
const RUN = process.env.PQ_RUN ?? `${process.pid}`;

// An isolated config dir keeps the operator's real ~/.sui untouched.
const CFG = mkdtempSync(join(tmpdir(), 'pq-cfg-'));

function sui(args: string[]): string {
  try {
    return execFileSync(SUI, args, {
      env: { ...process.env, SUI_CONFIG_DIR: CFG },
      maxBuffer: 64 * 1024 * 1024,
    }).toString();
  } catch (e) {
    // Surface the CLI's own stdout/stderr (the node's rejection reason).
    const err = e as { stdout?: Buffer; stderr?: Buffer };
    const detail = `${err.stdout?.toString() ?? ''}${err.stderr?.toString() ?? ''}`.trim();
    throw new Error(`sui ${args.join(' ')}\n${detail}`);
  }
}

// biome-ignore lint/suspicious/noExplicitAny: CLI JSON is dynamically shaped.
function suiJson(args: string[]): any {
  const out = sui([...args, '--json']);
  const starts = ['{', '['].map((c) => out.indexOf(c)).filter((i) => i >= 0);
  return JSON.parse(out.slice(Math.min(...starts)));
}

// CLI JSON may be snake_case or camelCase depending on the field; accept both.
// biome-ignore lint/suspicious/noExplicitAny: dynamic CLI JSON.
const pick = (o: any, ...keys: string[]) => keys.map((k) => o[k]).find((v) => v !== undefined);

function ok(label: string, cond: boolean, detail = '') {
  console.log(`  ${cond ? '✓' : '✗'} ${label}${detail ? `  ${detail}` : ''}`);
  if (!cond) throw new Error(`FAILED: ${label} ${detail}`);
}

/** Write a full client.yaml + empty keystore/aliases pointing at the localnet
 *  into `dir`, so every keystore-mutating command stays fully isolated and the
 *  operator's real ~/.sui is never read or written. */
function writeConfig(dir: string) {
  writeFileSync(join(dir, 'sui.keystore'), '[]');
  writeFileSync(join(dir, 'sui.aliases'), '[]');
  writeFileSync(
    join(dir, 'client.yaml'),
    [
      '---',
      'keystore:',
      `  File: ${join(dir, 'sui.keystore')}`,
      'envs:',
      '  - alias: localnet',
      `    rpc: "${LOCALNET_RPC}"`,
      '    ws: ~',
      '    basic_auth: ~',
      'active_env: localnet',
      'active_address: ~',
      '',
    ].join('\n'),
  );
}

/** Re-import a mnemonic into a throwaway isolated config; return the address.
 *  Runs against its own `SUI_CONFIG_DIR` so it neither reads nor writes the
 *  operator's real ~/.sui (`keytool` writes aliases into the active config). */
function deriveInIsolatedKeystore(mnemonic: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'pq-ks-'));
  writeConfig(dir);
  try {
    const out = execFileSync(SUI, ['keytool', 'import', mnemonic, 'slhdsa', '--json'], {
      env: { ...process.env, SUI_CONFIG_DIR: dir },
      maxBuffer: 64 * 1024 * 1024,
    }).toString();
    const r = JSON.parse(out.slice(out.indexOf('{')));
    return pick(r, 'suiAddress', 'address') as string;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function fund(address: string): Promise<void> {
  const c = client();
  const r = await fetch(`${LOCALNET_FAUCET}/v2/gas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
  });
  if (!r.ok) throw new Error(`faucet ${r.status}`);
  for (let i = 0; i < 40; i++) {
    if (BigInt((await c.getBalance({ owner: address })).totalBalance) > 0n) return;
    await sleep(300);
  }
  throw new Error(`faucet did not fund ${address}`);
}

async function main() {
  const c = client();
  console.log(`patched sui: ${SUI}`);
  console.log(`config dir:  ${CFG}`);
  console.log(`chain:       ${await c.getChainIdentifier()}\n`);

  writeConfig(CFG);

  // A throwaway recipient (its scheme is irrelevant — only the *sender* is the
  // post-quantum account under test).
  const recipient = pick(
    suiJson(['client', 'new-address', 'ed25519', 'recipient']),
    'address',
  ) as string;

  // 1. Derive a post-quantum account from a fresh BIP-39 mnemonic.
  console.log('1. Derive an SLH-DSA account from a BIP-39 mnemonic');
  const gen = suiJson(['client', 'new-address', 'slhdsa', `pq-mnem-${RUN}`, 'word15']);
  const address = pick(gen, 'address') as string;
  const scheme = String(pick(gen, 'keyScheme', 'key_scheme'));
  const mnemonic = pick(gen, 'recoveryPhrase', 'recovery_phrase') as string;
  ok('scheme is SLH-DSA', /slhdsa/i.test(scheme), `(${scheme})`);
  ok(
    'mnemonic returned',
    mnemonic.trim().split(/\s+/).length === 15,
    `(${mnemonic.split(/\s+/).length} words)`,
  );
  console.log(`     address:  ${address}`);
  console.log(`     mnemonic: ${mnemonic}\n`);

  // 2. Determinism: the same mnemonic re-derives the same address in two
  //    independent keystores that never saw the original key.
  console.log('2. Re-derive the same mnemonic in two isolated keystores');
  const b = deriveInIsolatedKeystore(mnemonic);
  const cc = deriveInIsolatedKeystore(mnemonic);
  ok('keystore #1 matches', b === address, b);
  ok('keystore #2 matches', cc === address, cc);
  console.log();

  // 3. Fund the post-quantum address.
  console.log('3. Fund the post-quantum address from the faucet');
  await fund(address);
  const coins = (await c.getCoins({ owner: address })).data;
  ok('funded', coins.length > 0, `${coins.length} coin(s)`);
  console.log();

  // 4. Execute a real on-chain transfer signed by ONLY the CLI-derived SLH-DSA
  //    key. We read the key the CLI just wrote to its keystore (the
  //    mnemonic-derived `0x07 || 64-byte signing key`) and submit over JSON-RPC,
  //    which the patched node verifies natively. (The CLI's own gRPC submission
  //    path can't carry scheme 0x07 — the external `sui-sdk-types` crate's
  //    SignatureScheme enum stops at Passkey; see docs/local-pq-validator.md.)
  console.log('4. Transfer on-chain, authenticated by the SLH-DSA key alone (no EC key)');
  const entries = JSON.parse(readFileSync(join(CFG, 'sui.keystore'), 'utf8')) as string[];
  const skFull = entries.map((b) => Buffer.from(b, 'base64')).find((bytes) => bytes[0] === 0x07);
  if (!skFull) throw new Error('no SLH-DSA key found in the CLI keystore');
  const sk = new Uint8Array(skFull.subarray(1)); // 64-byte FIPS-205 signing key
  const pk = sk.slice(32, 64); // PK.seed ‖ PK.root
  const acct: PqAccount = { pk, sk, address };
  ok(
    'key read from CLI keystore',
    sk.length === 64 && pk.length === 32,
    `flag=0x07 sk=${sk.length}B`,
  );

  const tx = new Transaction();
  const [coin] = tx.splitCoins(tx.gas, [1_000_000]);
  tx.transferObjects([coin], recipient);
  const res = await pqExec(c, acct, tx);
  ok('transaction executed', !!res.digest, res.digest);

  // Independently confirm the sender is the post-quantum (0x07) account.
  const onchain = await c.getTransactionBlock({ digest: res.digest, options: { showInput: true } });
  ok(
    'sender is the PQ account',
    onchain.transaction?.data.sender === address,
    onchain.transaction?.data.sender ?? '',
  );

  console.log('\n✅ A BIP-39 mnemonic derived a post-quantum SLH-DSA account that');
  console.log('   transacted on-chain with no elliptic-curve key anywhere.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => rmSync(CFG, { recursive: true, force: true }));
