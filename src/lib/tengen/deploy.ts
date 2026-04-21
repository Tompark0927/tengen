import { b64u } from './primitives';
import {
  buildNetwork,
  runNetwork,
  type BuildResult,
  type EntryEnvelope,
  type FragmentOptions,
  type NodeBlob,
  type RunChunk,
} from './fragment';

/**
 * Deployment package — the public artifact of a build.
 *
 * It is self-contained: given this object and a `run(chunk, i)` executor,
 * the network runs end-to-end. Nothing else is needed; nothing else survives.
 */
export interface DeploymentPackage {
  readonly blobs: ReadonlyMap<string, Uint8Array>;
  readonly entry: EntryEnvelope;
  readonly deployKey: Uint8Array;
  readonly decoyCount: number;
  readonly realCount: number;
}

/**
 * The network deployment script.
 *
 *   1. Fragment source into (opts.nodes) executable nodes.
 *   2. Intermix decoys; shuffle.
 *   3. Build the entry envelope.
 *   4. Destroy every piece of transformation state.
 *   5. Return the deployment package.
 *
 * After this returns, the builder's in-memory keys and mapping tables are
 * zero-filled. The returned package is the only surviving artifact.
 */
export const deploy = async (
  source: Uint8Array,
  opts: FragmentOptions = {},
): Promise<DeploymentPackage> => {
  const built: BuildResult = await buildNetwork(source, opts);
  const blobs = new Map<string, Uint8Array>();
  for (const b of built.blobs) blobs.set(b.addr, b.body);
  const realCount = opts.nodes ?? 64;
  const decoyCount = built.blobs.length - realCount;
  const pkg: DeploymentPackage = {
    blobs,
    entry: built.entry,
    deployKey: built.deployKey,
    decoyCount,
    realCount,
  };
  // Self-destruct: wipe the network secret, per-edge secrets, per-node keys,
  // intermediate chunk buffers, and the original source reference. After
  // this call, there is no build-time state left to pwn.
  built.destroy();
  return pkg;
};

export interface RunGuard {
  /** Probe called before every hop. Return true to abort + wipe. */
  readonly isObserved?: () => boolean | Promise<boolean>;
  /** Set false to skip the Merkle check (default true). Only useful for tests. */
  readonly verifyIntegrity?: boolean;
}

/** Execute a deployed package. `deployKey` is consumed (zeroized) on use. */
export const run = async (
  pkg: DeploymentPackage,
  runChunk: RunChunk,
  guard: RunGuard = {},
): Promise<void> => {
  const verify = guard.verifyIntegrity !== false;
  await runNetwork(
    pkg.entry,
    pkg.deployKey,
    async (addr) => pkg.blobs.get(addr) ?? null,
    runChunk,
    verify
      ? { blobs: pkg.blobs, ...(guard.isObserved ? { isObserved: guard.isObserved } : {}) }
      : guard.isObserved
        ? { blobs: new Map(), isObserved: guard.isObserved }
        : undefined,
  );
};

/**
 * Serialize the PUBLIC portion of a package — everything that can safely
 * travel over an untrusted channel (CDN, DHT, etc.). Crucially this does
 * NOT include `deployKey`, which is the 32-byte secret that unlocks the
 * entry envelope. Publishing deployKey alongside blobs defeats the
 * entire scheme (audit finding J).
 *
 * If you also need to ship `deployKey`, use `serializeDeployKey()`
 * separately and transport it on a different, confidential channel.
 */
export const serializePublic = (pkg: DeploymentPackage): {
  entry: { body: string; iv: string };
  blobs: Array<{ addr: string; body: string }>;
  realCount: number;
  decoyCount: number;
} => ({
  entry: { body: b64u.encode(pkg.entry.body), iv: b64u.encode(pkg.entry.iv) },
  blobs: [...pkg.blobs.entries()].map(([addr, body]) => ({ addr, body: b64u.encode(body) })),
  realCount: pkg.realCount,
  decoyCount: pkg.decoyCount,
});

/**
 * Serialize ONLY the deployKey as b64u. Explicit, standalone call to make
 * it obvious in code review when a key is crossing a boundary. Treat the
 * returned string as a password: never log, never commit, never store
 * alongside the public portion.
 */
export const serializeDeployKey = (pkg: DeploymentPackage): string =>
  b64u.encode(pkg.deployKey);

export type { NodeBlob, EntryEnvelope, FragmentOptions, RunChunk };
