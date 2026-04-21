import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64u,
  concat,
  hkdf,
  randomBytes,
  zeroize,
} from './primitives';
import {
  digestExecution,
  mintEdgeSecret,
  solve,
  openChannel,
  type EdgePuzzle,
} from './channel';
import { bus } from './events';

/**
 * Source → executable network.
 *
 *   • Source splits into N chunks; each chunk becomes one node.
 *   • Each node's body = AES-GCM( { chunk, nextAddr, outgoingEdgeSecret } )
 *     under a per-node key. The IV is HKDF-derived from the node key + addr,
 *     so no header/IV byte is stored on the wire. A shard = pure ciphertext.
 *   • Each node knows only its OWN outgoing edge secret. Its successor's
 *     address is inside its encrypted body, so reading it requires having
 *     first unlocked this node.
 *   • Successor's key = HKDF( edgeSecret_i ∥ puzzleNonce, info="edge" ).
 *   • After build, `destroy()` zero-fills build-time state (network
 *     secret, per-edge secrets, per-node keys, chunks, source buffer).
 *
 * Security Boundary:
 *   ✓ A single blob without its predecessor's execution output is
 *     unlinkable to its siblings (successor address lives inside the
 *     encrypted body).
 *   ✓ Tampering with any byte of a used blob is caught by AES-GCM's tag.
 *   ✗ An attacker who possesses a node key AND has run the corresponding
 *     chunk can solve the PoW and advance one hop. The puzzle's cost
 *     is anti-casual, not anti-skilled — it does NOT prevent chain
 *     traversal under key compromise.
 *   ✗ zeroize() in JS is best-effort. V8 may have copied buffers into
 *     coroutine state, generational heaps, or registers; destroy() does
 *     what the language allows, not what the name implies.
 *   ⚠ Use in combination with obliviousFetchAll() (integrity.ts) to
 *     prevent runtime access patterns from enumerating real vs decoy.
 */

const enc = new TextEncoder();

export interface NodeBlob {
  readonly addr: string;
  readonly body: Uint8Array;
}

export interface EntryEnvelope {
  readonly body: Uint8Array;
  readonly iv: Uint8Array;
}

export interface BuildResult {
  readonly blobs: readonly NodeBlob[];
  readonly entry: EntryEnvelope;
  readonly deployKey: Uint8Array;
  destroy(): void;
}

export interface FragmentOptions {
  nodes?: number;
  decoys?: number;
  difficulty?: number;
  ttlMs?: number;
}

// Per-node IV: deterministic from (nodeKey, addr). Both sides can reproduce.
const ivFor = (nodeKey: Uint8Array, addr: Uint8Array): Promise<Uint8Array> =>
  hkdf(nodeKey, enc.encode('tengen:frag:iv:v1'), addr, 12);

const deriveEdgeKey = (
  edgeSecret: Uint8Array,
  nonce: Uint8Array,
  execDigest: Uint8Array,
): Promise<Uint8Array> =>
  hkdf(concat(edgeSecret, nonce), execDigest, enc.encode('tengen:edge:v1'), 32);

export const buildNetwork = async (
  source: Uint8Array,
  opts: FragmentOptions = {},
): Promise<BuildResult> => {
  if (source.length === 0) throw new Error('fragment: empty source');
  const n = Math.max(2, opts.nodes ?? 64);
  const decoyCount = opts.decoys ?? n * 2;
  const difficulty = opts.difficulty ?? 12;
  const ttlMs = opts.ttlMs ?? 1;
  const puzzle: EdgePuzzle = { difficulty, ttlMs };

  // Split source into n chunks.
  const chunkSize = Math.ceil(source.length / n);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    chunks.push(source.slice(i * chunkSize, Math.min((i + 1) * chunkSize, source.length)));
  }

  // Fresh random addresses — uniformly random; no secret input needed.
  const addrs: Uint8Array[] = Array.from({ length: n }, () => randomBytes(32));

  // Per-edge secrets (one edge OUT of each non-terminal node).
  const edgeSecrets: Uint8Array[] = Array.from({ length: n - 1 }, () => mintEdgeSecret());

  // Node keys. node 0's key is random (embedded in the entry envelope).
  // node i>0's key is derived from edgeSecrets[i-1] + a puzzle nonce + exec digest.
  const nodeKeys: Uint8Array[] = [randomBytes(32)];
  const solutionNonces: Uint8Array[] = [];
  for (let i = 0; i < n - 1; i++) {
    const d = await digestExecution(chunks[i]!);
    const sol = await solve(edgeSecrets[i]!, d, puzzle);
    const k = await deriveEdgeKey(edgeSecrets[i]!, sol.nonce, d);
    nodeKeys.push(k);
    solutionNonces.push(sol.nonce);
    zeroize(d, sol.digest);
  }

  // Encrypt each node's body.
  const realBlobs: NodeBlob[] = [];
  for (let i = 0; i < n; i++) {
    const isLast = i === n - 1;
    const nextAddr = isLast ? new Uint8Array(32) : addrs[i + 1]!;
    const outgoingEdgeSecret = isLast ? new Uint8Array(32) : edgeSecrets[i]!;
    // Layout: [isLast:1][chunkLen:u32BE][chunk][nextAddr:32][outgoingEdgeSecret:32]
    const header = new Uint8Array(5);
    header[0] = isLast ? 1 : 0;
    new DataView(header.buffer).setUint32(1, chunks[i]!.length);
    const payload = concat(header, chunks[i]!, nextAddr, outgoingEdgeSecret);
    const iv = await ivFor(nodeKeys[i]!, addrs[i]!);
    const body = await aesGcmEncrypt(nodeKeys[i]!, iv, payload, addrs[i]!);
    realBlobs.push({ addr: b64u.encode(addrs[i]!), body });
    zeroize(payload);
  }

  // Intermix decoys of identical size.
  const realSize = realBlobs[0]!.body.length;
  const allBlobs: NodeBlob[] = [...realBlobs];
  for (let i = 0; i < decoyCount; i++) {
    const fakeAddr = randomBytes(32);
    const fakeBody = randomBytes(realSize);
    allBlobs.push({ addr: b64u.encode(fakeAddr), body: fakeBody });
  }
  for (let i = allBlobs.length - 1; i > 0; i--) {
    const r = randomBytes(4);
    const j = ((r[0]! << 24) | (r[1]! << 16) | (r[2]! << 8) | r[3]!) >>> 0;
    const idx = j % (i + 1);
    [allBlobs[i], allBlobs[idx]] = [allBlobs[idx]!, allBlobs[i]!];
  }

  // Entry envelope — the only persistent link into the network.
  // Plaintext layout (102 bytes):
  //   addr0(32) ∥ nodeKey0(32) ∥ difficulty(1) ∥ ttlMs(1) ∥ chainLen(4 BE) ∥ merkleRoot(32)
  const deployKey = randomBytes(32);
  const chainLen = new Uint8Array(4);
  new DataView(chainLen.buffer).setUint32(0, n);
  const entryIv = randomBytes(12);

  // Compute Merkle root over the full shuffled blob set + entryIv.
  const { deploymentRoot } = await import('./integrity');
  const blobMap = new Map<string, Uint8Array>();
  for (const b of allBlobs) blobMap.set(b.addr, b.body);
  const merkleRootBytes = await deploymentRoot(blobMap, entryIv);

  const entryPlain = concat(
    addrs[0]!,
    nodeKeys[0]!,
    new Uint8Array([difficulty & 0xff, ttlMs & 0xff]),
    chainLen,
    merkleRootBytes,
  );
  const entryBody = await aesGcmEncrypt(
    deployKey,
    entryIv,
    entryPlain,
    enc.encode('tengen:entry:v1'),
  );
  zeroize(entryPlain);

  const destroy = () => {
    for (const c of chunks) zeroize(c);
    for (const a of addrs) zeroize(a);
    for (const e of edgeSecrets) zeroize(e);
    for (const k of nodeKeys) zeroize(k);
    for (const nonce of solutionNonces) zeroize(nonce);
    zeroize(source);
    // Drop references so GC can reclaim.
    chunks.length = 0;
    addrs.length = 0;
    edgeSecrets.length = 0;
    nodeKeys.length = 0;
    solutionNonces.length = 0;
  };

  return {
    blobs: allBlobs,
    entry: { body: entryBody, iv: entryIv },
    deployKey,
    destroy,
  };
};

/* -------------------------------------------------------------------------- *
 *  Runtime
 * -------------------------------------------------------------------------- */

export type BlobLookup = (addr: string) => Promise<Uint8Array | null>;
export type RunChunk = (chunk: Uint8Array, index: number) => Promise<void>;

export interface RunOptions {
  /** Map of all blob bodies — used for Merkle verification before run. */
  readonly blobs: ReadonlyMap<string, Uint8Array>;
  /** Optional observer probe — called before each hop. Return true to abort. */
  readonly isObserved?: () => boolean | Promise<boolean>;
}

export const runNetwork = async (
  entry: EntryEnvelope,
  deployKey: Uint8Array,
  lookup: BlobLookup,
  run: RunChunk,
  options?: RunOptions,
): Promise<void> => {
  const plain = await aesGcmDecrypt(
    deployKey,
    entry.iv,
    entry.body,
    enc.encode('tengen:entry:v1'),
  );

  let currAddr = plain.slice(0, 32);
  let currKey = plain.slice(32, 64);
  const difficulty = plain[64]!;
  const ttlMs = plain[65]!;
  const chainLen = new DataView(plain.buffer, plain.byteOffset + 66, 4).getUint32(0);
  const expectedRoot = plain.slice(70, 102);
  zeroize(plain);
  zeroize(deployKey);

  // Tamper check — must match BEFORE any key is used on blob data.
  if (options?.blobs) {
    const { deploymentRoot, rootsEqual } = await import('./integrity');
    const actual = await deploymentRoot(options.blobs, entry.iv);
    if (!rootsEqual(actual, expectedRoot)) {
      bus.emit('merkle-mismatch', { note: 'deployment root differs from runtime blobs' });
      zeroize(currAddr, currKey, expectedRoot);
      throw new Error('runtime: integrity check failed');
    }
  }
  zeroize(expectedRoot);

  const puzzle: EdgePuzzle = { difficulty, ttlMs: Math.max(ttlMs, 50) };
  // Runtime ttl floor 50ms — the 1 ms "channel" is about the post-solve key
  // lifetime, not the outer loop budget. Bumping the floor keeps the chain
  // traversable on slow hardware while still wiping keys aggressively.

  for (let i = 0; i < chainLen; i++) {
    if (options?.isObserved && (await options.isObserved())) {
      bus.emit('observer-detected', { note: `hop ${i}` });
      zeroize(currAddr, currKey);
      throw new Error('runtime: observation detected');
    }
    const addrStr = b64u.encode(currAddr);
    const body = await lookup(addrStr);
    if (!body) {
      bus.emit('fetch-blob-missing', { note: `node ${i}` });
      throw new Error(`runtime: missing node ${i}`);
    }

    // Hold the node key inside a TTL-gated channel. If downstream work
    // exceeds ttl, the key evaporates and the chain snaps.
    const ch = openChannel(currKey.slice(), ttlMs);
    const live = ch.use();
    if (!live) {
      bus.emit('channel-expired-mid-run', { note: `hop ${i}` });
      throw new Error('runtime: channel closed before use');
    }

    const iv = await ivFor(live, currAddr);
    let payload: Uint8Array;
    try {
      payload = await aesGcmDecrypt(live, iv, body, currAddr);
    } catch (e) {
      bus.emit('aes-gcm-tag-failure', { note: `hop ${i}` });
      ch.close();
      throw e;
    } finally {
      ch.close();
    }

    const isLast = payload[0] === 1;
    const chunkLen = new DataView(payload.buffer, payload.byteOffset + 1, 4).getUint32(0);
    const chunk = payload.slice(5, 5 + chunkLen);
    const nextAddr = payload.slice(5 + chunkLen, 5 + chunkLen + 32);
    const outgoingEdgeSecret = payload.slice(5 + chunkLen + 32, 5 + chunkLen + 64);
    zeroize(payload);

    await run(chunk, i);

    if (isLast) {
      zeroize(chunk, currAddr, currKey, nextAddr, outgoingEdgeSecret);
      return;
    }

    // Solve puzzle over the executed chunk's digest → derive next node's key.
    const d = await digestExecution(chunk);
    const sol = await solve(outgoingEdgeSecret, d, puzzle);
    const nextKey = await deriveEdgeKey(outgoingEdgeSecret, sol.nonce, d);
    zeroize(sol.nonce, sol.digest, d, outgoingEdgeSecret, chunk, currAddr, currKey);

    currAddr = nextAddr;
    currKey = nextKey;
  }
};
