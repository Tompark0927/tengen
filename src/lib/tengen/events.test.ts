import { test } from 'node:test';
import assert from 'node:assert/strict';

import { bus, newEventBus } from './events';
import { deploy, run } from './deploy';
import { commit, dealGroupKey, sign } from './frost';

const enc = new TextEncoder();

test('events: emit + subscribe round trip', () => {
  const b = newEventBus(16);
  const seen: string[] = [];
  const unsub = b.subscribe((e) => seen.push(e.kind));
  b.emit('merkle-mismatch', { actor: 'alice' });
  b.emit('observer-detected');
  assert.deepEqual(seen, ['merkle-mismatch', 'observer-detected']);
  unsub();
  b.emit('fetch-blob-missing');
  assert.equal(seen.length, 2, 'unsubscribe stopped delivery');
});

test('events: recent() returns most-recent-last, bounded by capacity', () => {
  const b = newEventBus(3);
  for (const kind of ['merkle-mismatch', 'observer-detected', 'fetch-blob-missing', 'nonce-reuse-attempt'] as const) {
    b.emit(kind);
  }
  const tail = b.recent();
  assert.equal(tail.length, 3);
  assert.equal(tail[0]!.kind, 'observer-detected');
  assert.equal(tail[tail.length - 1]!.kind, 'nonce-reuse-attempt');
});

test('events: riskScore is higher for active attacks than passive noise', () => {
  const b = newEventBus();
  b.emit('fetch-blob-missing');
  const low = b.riskScore();
  b.emit('merkle-mismatch');
  b.emit('nonce-reuse-attempt');
  const high = b.riskScore();
  assert.ok(high > low * 5, `expected spike; got low=${low} high=${high}`);
  assert.ok(high <= 100);
});

test('events: riskScore decays over time', () => {
  const b = newEventBus();
  const t0 = Date.now();
  b.emit('merkle-mismatch');
  const now = b.riskScore(undefined, t0);
  const muchLater = b.riskScore(undefined, t0 + 10 * 60_000); // 10 min later
  assert.ok(muchLater < now / 10, `expected strong decay; now=${now} later=${muchLater}`);
});

test('events: actor scoping isolates contributions', () => {
  const b = newEventBus();
  b.emit('merkle-mismatch', { actor: 'alice' });
  b.emit('merkle-mismatch', { actor: 'bob' });
  b.emit('merkle-mismatch', { actor: 'bob' });
  const a = b.riskScore('alice');
  const bScore = b.riskScore('bob');
  assert.ok(bScore > a, 'bob triggered twice as many events');
});

test('events: clear() empties the ring + drops actor/note refs', () => {
  const b = newEventBus();
  b.emit('merkle-mismatch', { actor: 'subject', note: 'detail' });
  assert.equal(b.recent().length, 1);
  const ev = b.recent()[0]!;
  b.clear();
  assert.equal(b.recent().length, 0);
  assert.equal(b.riskScore(), 0);
  // ev was the same object held by the ring; clear() blanks its fields.
  assert.equal(ev.actor, undefined);
  assert.equal(ev.note, undefined);
});

test('events: subscriber errors do not crash emitter', () => {
  const b = newEventBus();
  b.subscribe(() => {
    throw new Error('i am a bad subscriber');
  });
  b.subscribe((e) => {
    // second subscriber must still receive
    (e as { saw?: true }).saw = true;
  });
  // Should NOT throw.
  b.emit('observer-detected');
  assert.equal(b.recent().length, 1);
});

test('events: integration — merkle mismatch during run() emits + throws', async () => {
  // Use a dedicated listener on the process-wide bus because that's where
  // runNetwork emits to.
  const seen: string[] = [];
  const unsub = bus.subscribe((e) => seen.push(e.kind));
  bus.clear();

  const pkg = await deploy(enc.encode('payload to shred. '.repeat(10)), {
    nodes: 3, decoys: 5, difficulty: 6, ttlMs: 500,
  });
  const addrs = [...pkg.blobs.keys()];
  const body = pkg.blobs.get(addrs[0]!)!;
  body[0] = (body[0] ?? 0) ^ 0x01; // tamper

  await assert.rejects(() => run(pkg, async () => {}), /integrity check failed/);
  unsub();
  assert.ok(seen.includes('merkle-mismatch'), `expected merkle-mismatch, got ${seen.join(',')}`);
  assert.ok(bus.riskScore() >= 40, 'merkle-mismatch carries weight 40');
  bus.clear();
});

test('events: integration — FROST nonce reuse emits nonce-reuse-attempt', () => {
  const seen: string[] = [];
  const unsub = bus.subscribe((e) => seen.push(e.kind));
  bus.clear();

  const { groupPk, signerKeys } = dealGroupKey(2, [1, 2, 3]);
  const me = signerKeys[0]!;
  const { publicCommitment, privateNonce } = commit(me);
  const peerCommit = commit(signerKeys[1]!).publicCommitment;
  const commitments = [publicCommitment, peerCommit];

  sign(me, privateNonce, enc.encode('first'), commitments, groupPk);
  assert.throws(
    () => sign(me, privateNonce, enc.encode('second'), commitments, groupPk),
    /already used/,
  );
  unsub();
  assert.ok(seen.includes('nonce-reuse-attempt'));
  bus.clear();
});
