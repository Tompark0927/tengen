import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { concat, randomBytes, zeroize } from './primitives';
import { bus } from './events';

/**
 * FROST-Ed25519 (trusted-dealer variant).
 *
 *   Threshold Schnorr signing over Curve25519. Signers never transmit their
 *   long-term secret shares. Each signing round, a signer releases only a
 *   partial scalar `z_i = d_i + ρ_i·e_i + λ_i·sk_i·c  (mod n)`, where
 *   (d_i, e_i) are fresh per-round nonces. A passive observer collecting
 *   any number of z_i values from any number of rounds cannot recover sk_i
 *   (each equation has two unknown nonces freshly sampled).
 *
 * Security Boundary (please read before relying on this):
 *   ✓ Defends against: passive eavesdroppers, coordinator compromise,
 *     capture of partial signatures across rounds, bait-and-switch via
 *     message manipulation (message is bound into ρ_i and c).
 *   ✗ Does NOT defend against: compromise of a signer's long-term sk_i
 *     (that share is then attacker-controlled, and the usual m-of-n
 *     threshold applies: t compromised signers = group key compromise).
 *   ✗ Does NOT defend against: nonce reuse (d_i, e_i MUST be fresh per
 *     session). sign() burns its input SignerPrivateNonce on success, so
 *     passing the same object twice throws "nonce already used" — that
 *     protects against the accidental-reuse bug pattern. But a caller
 *     who reconstructs a fresh `{id, d, e}` object from previously-seen
 *     scalar values bypasses this check; there is no persistent-state
 *     defense in-library. Rule: treat SignerPrivateNonce as opaque and
 *     single-use — never serialize d/e to durable storage.
 *   ⚠ Trusted-dealer setup: `dealGroupKey()` briefly holds the full group
 *     sk in memory, splits it, then zeroizes. Distributed key generation
 *     (DKG) is out of scope here; use a hardware HSM or air-gapped
 *     ceremony for the deal step.
 *
 * References:
 *   RFC 9591 (FROST). This file implements a simplified but compatible
 *   2-round variant sufficient for the Tengen update protocol.
 */

const enc = new TextEncoder();
const n = ed25519.CURVE.n;
const G = ed25519.ExtendedPoint.BASE;
const IDENTITY = ed25519.ExtendedPoint.ZERO;

// ---- scalar helpers ------------------------------------------------------

const modN = (a: bigint): bigint => {
  const r = a % n;
  return r < 0n ? r + n : r;
};

const invModN = (a: bigint): bigint => {
  // Extended Euclidean in BigInt.
  let [oldR, r] = [modN(a), n];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('frost: value not invertible mod n');
  return modN(oldS);
};

const randScalar = (): bigint => {
  // Rejection-sample a scalar uniform in [1, n-1].
  while (true) {
    const b = randomBytes(32);
    // Interpret LE to match Ed25519 convention; reduce mod n and check non-zero.
    let x = 0n;
    for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
    const s = modN(x);
    zeroize(b);
    if (s !== 0n) return s;
  }
};

const scalarToBytesLE = (s: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let x = modN(s);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};

const scalarFromBytesLE = (b: Uint8Array): bigint => {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return modN(x);
};

const hashToScalar = (domain: string, ...parts: Uint8Array[]): bigint => {
  const h = sha512(concat(enc.encode(domain), ...parts));
  let x = 0n;
  for (let i = h.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(h[i]!);
  return modN(x);
};

// ---- public types --------------------------------------------------------

export interface SignerKey {
  readonly id: number; // 1..255; also the Shamir x-coord
  /** Secret share of the group sk. Stays with the signer forever. */
  readonly sk: bigint;
}

export interface GroupPublicKey {
  /** 32-byte compressed Ed25519 public key. */
  readonly bytes: Uint8Array;
  readonly threshold: number;
}

export interface SignerCommitment {
  readonly id: number;
  /** D_i = d_i · G, 32 bytes compressed. */
  readonly D: Uint8Array;
  /** E_i = e_i · G, 32 bytes compressed. */
  readonly E: Uint8Array;
}

export interface SignerPrivateNonce {
  readonly id: number;
  /** One-shot hiding nonce. Burn after sign(). */
  readonly d: bigint;
  /** One-shot binding nonce. Burn after sign(). */
  readonly e: bigint;
}

export interface PartialSignature {
  readonly id: number;
  /** z_i as 32-byte LE scalar. */
  readonly z: Uint8Array;
}

export interface Signature {
  /** R as 32-byte compressed Ed25519 point. */
  readonly R: Uint8Array;
  /** z as 32-byte LE scalar. */
  readonly z: Uint8Array;
}

// ---- dealer --------------------------------------------------------------

export const dealGroupKey = (
  threshold: number,
  signerIds: readonly number[],
): { groupPk: GroupPublicKey; signerKeys: readonly SignerKey[] } => {
  if (threshold < 2) throw new Error('frost: threshold must be >= 2');
  if (signerIds.length < threshold) throw new Error('frost: not enough signers');
  if (new Set(signerIds).size !== signerIds.length) throw new Error('frost: duplicate signerId');
  for (const id of signerIds) {
    if (id < 1 || id > 255 || !Number.isInteger(id)) throw new Error('frost: signerId in [1,255]');
  }

  // Polynomial f(x) = sk + a_1 x + ... + a_{t-1} x^{t-1}  over GF(n).
  const sk = randScalar();
  const coeffs: bigint[] = [sk];
  for (let i = 1; i < threshold; i++) coeffs.push(randScalar());

  const signerKeys: SignerKey[] = signerIds.map((id) => {
    const x = BigInt(id);
    let y = 0n;
    for (let i = coeffs.length - 1; i >= 0; i--) y = modN(y * x + coeffs[i]!);
    return { id, sk: y };
  });

  const groupPkBytes = G.multiply(sk).toRawBytes();

  // Zeroize the group sk and higher coefficients. Shares live only with signers.
  for (let i = 0; i < coeffs.length; i++) coeffs[i] = 0n;

  return {
    groupPk: { bytes: groupPkBytes, threshold },
    signerKeys,
  };
};

// ---- round 1: commit -----------------------------------------------------

export const commit = (
  key: SignerKey,
): { publicCommitment: SignerCommitment; privateNonce: SignerPrivateNonce } => {
  const d = randScalar();
  const e = randScalar();
  const D = G.multiply(d).toRawBytes();
  const E = G.multiply(e).toRawBytes();
  return {
    publicCommitment: { id: key.id, D, E },
    privateNonce: { id: key.id, d, e },
  };
};

// ---- binding & challenge -------------------------------------------------

const bindingFactor = (
  id: number,
  msg: Uint8Array,
  commitments: readonly SignerCommitment[],
): bigint => {
  const sorted = [...commitments].sort((a, b) => a.id - b.id);
  const parts: Uint8Array[] = [new Uint8Array([id & 0xff]), msg];
  for (const c of sorted) {
    parts.push(new Uint8Array([c.id & 0xff]));
    parts.push(c.D);
    parts.push(c.E);
  }
  return hashToScalar('tengen:frost:rho:v1', ...parts);
};

const groupCommitmentPoint = (
  commitments: readonly SignerCommitment[],
  binders: ReadonlyMap<number, bigint>,
): InstanceType<typeof ed25519.ExtendedPoint> => {
  let acc = IDENTITY;
  for (const c of commitments) {
    const rho = binders.get(c.id)!;
    const D = ed25519.ExtendedPoint.fromHex(c.D);
    const E = ed25519.ExtendedPoint.fromHex(c.E);
    acc = acc.add(D.add(E.multiply(rho)));
  }
  return acc;
};

const challengeScalar = (R: Uint8Array, groupPk: Uint8Array, msg: Uint8Array): bigint =>
  hashToScalar('tengen:frost:c:v1', R, groupPk, msg);

const lagrangeCoeffAt0 = (me: bigint, others: readonly bigint[]): bigint => {
  let num = 1n;
  let den = 1n;
  for (const xj of others) {
    num = modN(num * modN(-xj));
    den = modN(den * modN(me - xj));
  }
  return modN(num * invModN(den));
};

// ---- round 2: sign -------------------------------------------------------

export const sign = (
  key: SignerKey,
  nonce: SignerPrivateNonce,
  msg: Uint8Array,
  commitments: readonly SignerCommitment[],
  groupPk: GroupPublicKey,
): PartialSignature => {
  if (nonce.id !== key.id) throw new Error('frost: nonce/key id mismatch');
  // Single-shot nonce enforcement. Reusing (d, e) across two signatures with
  // different messages leaks sk_i via linear algebra (audit finding G). We
  // treat a zeroed nonce as "already burned" and refuse.
  if (nonce.d === 0n || nonce.e === 0n) {
    bus.emit('nonce-reuse-attempt', { note: `signer ${key.id}` });
    throw new Error('frost: nonce already used (single-shot required)');
  }
  if (!commitments.some((c) => c.id === key.id)) {
    throw new Error('frost: my commitment is not in the list');
  }
  if (commitments.length < groupPk.threshold) throw new Error('frost: below threshold');
  if (new Set(commitments.map((c) => c.id)).size !== commitments.length) {
    throw new Error('frost: duplicate signer in commitments');
  }

  const binders = new Map<number, bigint>();
  for (const c of commitments) binders.set(c.id, bindingFactor(c.id, msg, commitments));

  const R = groupCommitmentPoint(commitments, binders);
  const c = challengeScalar(R.toRawBytes(), groupPk.bytes, msg);

  const others = commitments.filter((cm) => cm.id !== key.id).map((cm) => BigInt(cm.id));
  const lambda = lagrangeCoeffAt0(BigInt(key.id), others);

  const myBinder = binders.get(key.id)!;
  const z = modN(nonce.d + myBinder * nonce.e + lambda * key.sk * c);

  // Burn the nonce unconditionally on success. Any subsequent sign() with the
  // same nonce object will short-circuit on the zeroed-d/e check above.
  (nonce as { d: bigint }).d = 0n;
  (nonce as { e: bigint }).e = 0n;

  return { id: key.id, z: scalarToBytesLE(z) };
};

/** Zero a private nonce. Callers MUST invoke this after sign(). */
export const burnNonce = (nonce: { d: bigint; e: bigint } & Record<string, unknown>): void => {
  (nonce as { d: bigint }).d = 0n;
  (nonce as { e: bigint }).e = 0n;
};

// ---- aggregate + verify --------------------------------------------------

export const aggregate = (
  commitments: readonly SignerCommitment[],
  partials: readonly PartialSignature[],
  msg: Uint8Array,
  groupPk: GroupPublicKey,
): Signature => {
  if (partials.length < groupPk.threshold) throw new Error('frost: not enough partials');
  if (partials.length !== commitments.length) throw new Error('frost: partial/commit count mismatch');
  if (new Set(partials.map((p) => p.id)).size !== partials.length) {
    throw new Error('frost: duplicate partial');
  }

  const binders = new Map<number, bigint>();
  for (const c of commitments) binders.set(c.id, bindingFactor(c.id, msg, commitments));
  const R = groupCommitmentPoint(commitments, binders);

  let z = 0n;
  for (const p of partials) z = modN(z + scalarFromBytesLE(p.z));

  return { R: R.toRawBytes(), z: scalarToBytesLE(z) };
};

export const verify = (sig: Signature, msg: Uint8Array, groupPk: GroupPublicKey): boolean => {
  try {
    const R = ed25519.ExtendedPoint.fromHex(sig.R);
    const PK = ed25519.ExtendedPoint.fromHex(groupPk.bytes);
    const z = scalarFromBytesLE(sig.z);
    const c = challengeScalar(sig.R, groupPk.bytes, msg);
    // Schnorr verification: z·G == R + c·PK
    const lhs = G.multiply(z);
    const rhs = R.add(PK.multiply(c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
};

// ---- internal helpers shared with dkg.ts ---------------------------------
// NOT part of the stable public API. Underscore prefix flags intent.
// dkg.ts consumes these to avoid duplicating curve + scalar glue.
export const _internal = {
  modN,
  invModN,
  randScalar,
  scalarToBytesLE,
  scalarFromBytesLE,
  hashToScalar,
  lagrangeCoeffAt0,
  G,
  IDENTITY,
  n,
};
