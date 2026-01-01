/**
 * Localnet lifecycle from the dApp.
 *
 *   GET    /api/localnet  → { running, rpcOk, faucetOk, pid?, logPath?, suiBin? }
 *   POST   /api/localnet  → spawn `sui start --with-faucet` (idempotent: no-op if already up)
 *   DELETE /api/localnet  → kill the previously-spawned process
 *
 * Dev-only. The handler refuses to spawn anything unless `NODE_ENV !== 'production'`
 * — you don't want a publicly-deployed dApp launching a Sui node on the server.
 *
 * Persistence: the PID + log path live in `/tmp/sui-gen-localnet.json`. That way
 * the Next.js dev server can restart without orphaning the child node, and a
 * subsequent GET correctly reports "still running" from the previous session.
 */
import { spawn } from 'node:child_process';
import { existsSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const STATE_FILE = '/tmp/sui-gen-localnet.json';
const LOG_FILE = '/tmp/sui-gen-localnet.log';

type State = { pid: number; logPath: string; suiBin: string; startedAt: number };

function readState(): State | null {
  try {
    return JSON.parse(readFileSync(STATE_FILE, 'utf8')) as State;
  } catch {
    return null;
  }
}
function writeState(s: State): void {
  writeFileSync(STATE_FILE, JSON.stringify(s));
}
function clearState(): void {
  try {
    unlinkSync(STATE_FILE);
  } catch {}
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function portOpen(port: number): Promise<boolean> {
  // We can't open a raw socket from this runtime without 'net'; instead, hit
  // the RPC/faucet path and treat any HTTP response (or connection refused
  // with status) as "answered". A successful TCP handshake yields some body
  // back; a closed port throws.
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 800);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/`, { signal: ctl.signal });
    void res;
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

function findSuiBin(): string | null {
  const candidates = [
    process.env.SUI_BIN,
    join(homedir(), '.local/bin/sui'),
    join(homedir(), '.cargo/bin/sui'),
    '/opt/homebrew/bin/sui',
    '/usr/local/bin/sui',
  ].filter((p): p is string => Boolean(p));
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

function ensureDev(): Response | null {
  if (process.env.NODE_ENV === 'production') {
    return Response.json(
      { error: 'localnet spawn endpoint disabled in production builds' },
      { status: 403 },
    );
  }
  return null;
}

export async function GET() {
  const s = readState();
  const [rpcOk, faucetOk] = await Promise.all([portOpen(9000), portOpen(9123)]);
  const running = (s !== null && pidAlive(s.pid)) || rpcOk;
  return Response.json({
    running,
    rpcOk,
    faucetOk,
    pid: s?.pid,
    logPath: s?.logPath,
    startedAt: s?.startedAt,
    suiBin: s?.suiBin ?? findSuiBin(),
  });
}

export async function POST() {
  const denied = ensureDev();
  if (denied) return denied;

  // Idempotent: if we (or anyone) already have it up on 9000, return current state.
  if (await portOpen(9000)) {
    const s = readState();
    return Response.json({
      already_running: true,
      pid: s?.pid,
      message: 'localnet already responding on 127.0.0.1:9000',
    });
  }

  const suiBin = findSuiBin();
  if (!suiBin) {
    return Response.json(
      {
        error: 'sui binary not found',
        hint:
          'Install sui first. From the project root:\n  $ pnpm setup:sui\n' +
          'Or set $SUI_BIN to the absolute path of your sui binary.',
      },
      { status: 404 },
    );
  }

  // Spawn detached so a Next.js dev-server restart doesn't kill the node.
  const out = openSync(LOG_FILE, 'a');
  const err = openSync(LOG_FILE, 'a');
  const child = spawn(suiBin, ['start', '--with-faucet'], {
    stdio: ['ignore', out, err],
    detached: true,
  });
  child.unref();
  if (!child.pid) {
    return Response.json({ error: 'failed to spawn sui' }, { status: 500 });
  }
  writeState({ pid: child.pid, logPath: LOG_FILE, suiBin, startedAt: Date.now() });

  // Wait up to 30s for the RPC port to come up.
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    if (await portOpen(9000)) {
      return Response.json({
        spawned: true,
        pid: child.pid,
        logPath: LOG_FILE,
        message: 'localnet up on 127.0.0.1:9000 (faucet on :9123)',
      });
    }
  }
  return Response.json(
    {
      error: 'localnet did not come up within 30s',
      pid: child.pid,
      logPath: LOG_FILE,
      hint: 'check the log for errors',
    },
    { status: 504 },
  );
}

export async function DELETE() {
  const denied = ensureDev();
  if (denied) return denied;
  const s = readState();
  if (!s) return Response.json({ message: 'no managed localnet process' });
  if (!pidAlive(s.pid)) {
    clearState();
    return Response.json({ message: 'process already exited' });
  }
  try {
    // SIGTERM the whole process group to also kill child sui-node/faucet processes.
    process.kill(-s.pid, 'SIGTERM');
  } catch {
    try {
      process.kill(s.pid, 'SIGTERM');
    } catch {}
  }
  // Wait up to 5s for clean exit
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 250));
    if (!pidAlive(s.pid)) break;
  }
  clearState();
  return Response.json({ stopped: true, pid: s.pid });
}
