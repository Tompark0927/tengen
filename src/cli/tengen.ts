#!/usr/bin/env -S npx tsx
/**
 * Tengen CLI — library harness, not a product.
 *
 *   Research-grade. Pre-audit. Do not feed real secrets into this.
 *
 * Subcommands:
 *   deploy <source-file> <out-dir> [--nodes N] [--decoys M] [--difficulty D]
 *   run    <pkg-dir>                 -> reassembled source to stdout
 *   verify <pkg-dir>                 -> recompute + print deployment Merkle root
 *   audit                            -> run the adversarial audit
 *   version
 */

import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { argv, exit, stderr, stdout } from 'node:process';
import { deploy, run } from '../lib/tengen/deploy';
import { deploymentRoot } from '../lib/tengen/integrity';
import { formatReport, scanDir } from '../lib/tengen/scanner';

const USAGE = `tengen <command> [args]

Commands:
  scan    <project-dir>                  — static vuln scan (SQLi, eval, XSS, secrets, …)
  deploy  <source-file> <out-dir> [--nodes N] [--decoys M] [--difficulty D] [--ttl-ms T]
  run     <pkg-dir>
  verify  <pkg-dir>
  audit                                   — run the adversarial self-audit
  version

Notes:
  - This is a research harness. The code has not been audited. Do not
    use with data whose compromise would cause real-world harm.
  - Handle deploy.key with care: possession of that 32-byte file unlocks
    the package. The CLI writes it with 0600 permissions, but storage
    medium and transport are your responsibility.
`;

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const parseFlags = (args: string[]): Record<string, string> => {
  const out: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = args[i + 1];
      if (!val || val.startsWith('--')) {
        stderr.write(`error: --${key} requires a value\n`);
        exit(2);
      }
      out[key] = val;
      i++;
    }
  }
  return out;
};

function fail(msg: string, code = 1): never {
  stderr.write(`tengen: ${msg}\n`);
  exit(code);
  throw new Error(msg); // unreachable; satisfies narrowing
}

// -------- deploy ----------------------------------------------------------

const cmdDeploy = async (args: string[]): Promise<void> => {
  const [srcArg, outArg, ...rest] = args;
  if (!srcArg || !outArg) fail('usage: tengen deploy <source-file> <out-dir>', 2);
  const flags = parseFlags(rest);

  const src = resolve(srcArg);
  const out = resolve(outArg);
  if (!existsSync(src)) fail(`source not found: ${src}`);
  if (existsSync(out)) fail(`out-dir already exists: ${out} (refusing to overwrite)`);

  const source = await readFile(src);
  const pkg = await deploy(new Uint8Array(source), {
    nodes: flags['nodes'] ? Number(flags['nodes']) : 64,
    decoys: flags['decoys'] ? Number(flags['decoys']) : 128,
    difficulty: flags['difficulty'] ? Number(flags['difficulty']) : 12,
    ttlMs: flags['ttl-ms'] ? Number(flags['ttl-ms']) : 500,
  });

  await mkdir(join(out, 'blobs'), { recursive: true });
  // Write entry envelope + deploy key with restrictive perms.
  await writeFile(join(out, 'entry.body'), pkg.entry.body, { mode: 0o600 });
  await writeFile(join(out, 'entry.iv'), pkg.entry.iv, { mode: 0o600 });
  await writeFile(join(out, 'deploy.key'), pkg.deployKey, { mode: 0o600 });

  const manifest = {
    version: 1,
    realCount: pkg.realCount,
    decoyCount: pkg.decoyCount,
    blobs: [...pkg.blobs.keys()].sort(),
    note: 'blobs are content-addressed by url-safe-b64 of a 32-byte handle',
  };
  await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2));

  // Safe filenames: b64url chars include '-' and '_', no slashes. Direct use OK.
  for (const [addr, body] of pkg.blobs) {
    await writeFile(join(out, 'blobs', `${addr}.bin`), body);
  }

  stdout.write(
    `deployed ${pkg.realCount} real + ${pkg.decoyCount} decoy blobs to ${out}\n` +
      `  deploy.key  (KEEP THIS)  ${out}/deploy.key\n` +
      `  entry.body                ${out}/entry.body\n` +
      `  manifest.json             ${out}/manifest.json\n`,
  );
};

// -------- pkg loader (shared by run/verify) -------------------------------

const loadPackage = async (pkgDir: string) => {
  const req = (name: string) => {
    const p = join(pkgDir, name);
    if (!existsSync(p)) fail(`missing ${name} in ${pkgDir}`);
    return p;
  };
  const entryBody = new Uint8Array(await readFile(req('entry.body')));
  const entryIv = new Uint8Array(await readFile(req('entry.iv')));
  const manifestRaw = await readFile(req('manifest.json'), 'utf8');
  const manifest = JSON.parse(manifestRaw) as {
    version: number;
    realCount: number;
    decoyCount: number;
    blobs: string[];
  };
  if (manifest.version !== 1) fail(`unknown manifest version: ${manifest.version}`);

  const blobsDir = join(pkgDir, 'blobs');
  const expectedFiles = new Set(manifest.blobs.map((a) => `${a}.bin`));
  const actualFiles = new Set(await readdir(blobsDir));
  for (const want of expectedFiles) {
    if (!actualFiles.has(want)) fail(`missing blob file: ${want}`);
  }

  const blobs = new Map<string, Uint8Array>();
  for (const addr of manifest.blobs) {
    blobs.set(addr, new Uint8Array(await readFile(join(blobsDir, `${addr}.bin`))));
  }

  return {
    entry: { body: entryBody, iv: entryIv },
    manifest,
    blobs,
    deployKeyPath: join(pkgDir, 'deploy.key'),
  };
};

// -------- verify ----------------------------------------------------------

const cmdVerify = async (args: string[]): Promise<void> => {
  const [pkgDir] = args;
  if (!pkgDir) fail('usage: tengen verify <pkg-dir>', 2);

  const p = await loadPackage(resolve(pkgDir));
  const root = await deploymentRoot(p.blobs, p.entry.iv);
  stdout.write(
    `root: ${hex(root)}\n` +
      `  blobs:     ${p.blobs.size}\n` +
      `  real/dec:  ${p.manifest.realCount} / ${p.manifest.decoyCount}\n` +
      '  note: this root only equals the one embedded in entry if nothing\n' +
      '        has been tampered. To check embedded equality, run "tengen run"\n' +
      '        (which decrypts entry, compares roots, and refuses on mismatch).\n',
  );
};

// -------- run -------------------------------------------------------------

const cmdRun = async (args: string[]): Promise<void> => {
  const [pkgDir] = args;
  if (!pkgDir) fail('usage: tengen run <pkg-dir>', 2);

  const p = await loadPackage(resolve(pkgDir));
  if (!existsSync(p.deployKeyPath)) fail(`missing deploy.key in ${pkgDir}`);
  const deployKey = new Uint8Array(await readFile(p.deployKeyPath));

  const parts: Uint8Array[] = [];
  await run(
    {
      entry: p.entry,
      blobs: p.blobs,
      deployKey,
      realCount: p.manifest.realCount,
      decoyCount: p.manifest.decoyCount,
    },
    async (chunk) => {
      // Runtime zero-fills chunk after callback — must copy to retain.
      parts.push(new Uint8Array(chunk));
    },
  );

  const total = parts.reduce((s, c) => s + c.length, 0);
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of parts) {
    joined.set(c, off);
    off += c.length;
  }
  stdout.write(joined);
};

// -------- audit -----------------------------------------------------------

const cmdAudit = async (): Promise<void> => {
  await import('../lib/tengen/audit');
};

// -------- scan ------------------------------------------------------------

const cmdScan = async (args: string[]): Promise<void> => {
  const [dir] = args;
  if (!dir) fail('usage: tengen scan <project-dir>', 2);
  const findings = await scanDir(resolve(dir));
  stdout.write(formatReport(findings));
  // Non-zero exit if any critical/high so CI can gate on it.
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
    exit(2);
  }
};

// -------- dispatch --------------------------------------------------------

const main = async (): Promise<void> => {
  const [, , cmd, ...rest] = argv;
  switch (cmd) {
    case 'deploy':
      await cmdDeploy(rest);
      return;
    case 'run':
      await cmdRun(rest);
      return;
    case 'verify':
      await cmdVerify(rest);
      return;
    case 'audit':
      await cmdAudit();
      return;
    case 'scan':
      await cmdScan(rest);
      return;
    case 'version':
      stdout.write('tengen 0.0.1-research (pre-audit)\n');
      return;
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      stdout.write(USAGE);
      return;
    default:
      stderr.write(`unknown command: ${cmd}\n\n${USAGE}`);
      exit(2);
  }
};

main().catch((e) => {
  stderr.write(`tengen: ${e instanceof Error ? e.message : String(e)}\n`);
  exit(1);
});
