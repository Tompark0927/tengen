import { x25519 } from '@noble/curves/ed25519';
import {
  verifyApproval,
  type Challenge,
  type GroupPublicKey,
  type QuorumPolicy,
  type Signature,
} from './quorum';
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  concat,
  hkdf,
  randomBytes,
  sha256,
  zeroize,
} from './primitives';
import { deploymentRoot } from './integrity';
import { bus } from './events';
import type { DeploymentPackage } from './deploy';

/**
 * Quorum-signed updates.
 *
 *   Two independent mechanisms, composed:
 *
 *     1. Authorization (FROST): a Schnorr signature over the update's
 *        boundTo value, produced by t-of-n signers without ever
 *        reconstructing the group secret. See quorum.ts.
 *
 *     2. Confidentiality (X25519-ECIES): the NEW package's deployKey is
 *        wrapped to a specific installer's long-term public key. Only the
 *        holder of the matching private key can unwrap. Capturing the
 *        wrapped key on the wire reveals nothing.
 *
 *   The signature covers BOTH the new deployment root AND the installer's
 *   public key, so a relay attacker cannot redirect the bundle to a
 *   different installer.
 *
 * Security Boundary:
 *   ✓ Passive eavesdrop of any number of bundles does not reveal deployKeys
 *     or signer shares.
 *   ✓ Signature forgery requires t colluding signers.
 *   ✓ Substituting the package body changes deploymentRoot → boundTo
 *     mismatch → signature verification fails.
 *   ✗ An installer who already decrypted a past bundle can hand the
 *     deployKey to anyone else. ECIES protects transit, not post-decrypt
 *     behavior.
 *   ⚠ installUpdate()'s old-package zeroize is best-effort under the JS
 *     memory model; see primitives.ts:zeroize. Copies in coroutine state
 *     or GC-moved buffers may survive.
 */

const enc = new TextEncoder();
const UPDATE_AAD = enc.encode('tengen:update:v2');

export interface InstallerKeypair {
  /** X25519 private key (32 bytes). */
  readonly sk: Uint8Array;
  /** X25519 public key (32 bytes). */
  readonly pk: Uint8Array;
}

export const generateInstallerKeypair = (): InstallerKeypair => {
  const sk = x25519.utils.randomPrivateKey();
  const pk = x25519.getPublicKey(sk);
  return { sk, pk };
};

export interface UpdateBundle {
  readonly newPackage: Omit<DeploymentPackage, 'deployKey'>;
  readonly challenge: Challenge;
  /** FROST-Ed25519 Schnorr signature over (deploymentRoot ∥ installerPk). */
  readonly signature: Signature;
  /** 32-byte X25519 ephemeral public key. */
  readonly ephemeralPk: Uint8Array;
  /** AES-GCM IV for the wrapped deployKey. */
  readonly iv: Uint8Array;
  /** AES-GCM ciphertext of newPackage.deployKey. */
  readonly wrappedDeployKey: Uint8Array;
  /** Recipient's long-term public key. Makes bundle recipient-specific. */
  readonly installerPk: Uint8Array;
}

/**
 * Compute the boundTo value that signers must attest to. Combines the new
 * package's Merkle root with the installer's long-term public key, so the
 * signature certifies BOTH "this package" AND "for this recipient".
 */
export const updateBinding = async (
  newPackageBlobs: ReadonlyMap<string, Uint8Array>,
  newEntryIv: Uint8Array,
  installerPk: Uint8Array,
): Promise<Uint8Array> => {
  const root = await deploymentRoot(newPackageBlobs, newEntryIv);
  return sha256(concat(enc.encode('tengen:update:binding:v2'), root, installerPk));
};

/**
 * Publisher-side: wrap the new deployKey to the installer, package up the
 * already-produced FROST signature, return the bundle. This function does
 * NOT run quorum — it assumes the signature was produced out-of-band via
 * quorum.ts (commit → approve → aggregateApprovals).
 */
export const sealUpdate = async (
  newPkg: DeploymentPackage,
  challenge: Challenge,
  signature: Signature,
  installerPk: Uint8Array,
): Promise<UpdateBundle> => {
  const ephemeralSk = x25519.utils.randomPrivateKey();
  const ephemeralPk = x25519.getPublicKey(ephemeralSk);
  const shared = x25519.getSharedSecret(ephemeralSk, installerPk);
  zeroize(ephemeralSk);

  const aesKey = await hkdf(shared, enc.encode('tengen:update:wrap:v2'), ephemeralPk, 32);
  zeroize(shared);

  const iv = randomBytes(12);
  const wrappedDeployKey = await aesGcmEncrypt(aesKey, iv, newPkg.deployKey, UPDATE_AAD);
  zeroize(aesKey);
  zeroize(newPkg.deployKey);

  const { deployKey: _dk, ...rest } = newPkg;
  void _dk;
  return {
    newPackage: rest,
    challenge,
    signature,
    ephemeralPk,
    iv,
    wrappedDeployKey,
    installerPk,
  };
};

/**
 * Installer-side: verify signature, unwrap deployKey, atomically hand off.
 * The old package is left untouched if verification fails.
 */
export const installUpdate = async (
  oldPkg: DeploymentPackage,
  bundle: UpdateBundle,
  groupPk: GroupPublicKey,
  installer: InstallerKeypair,
  policy: QuorumPolicy,
  now = Date.now(),
): Promise<DeploymentPackage> => {
  // (1) Bundle must be addressed to THIS installer. Catches misrouted bundles.
  if (!bytesEqual(bundle.installerPk, installer.pk)) {
    bus.emit('bundle-misaddressed');
    throw new Error('updater: bundle not addressed to this installer');
  }

  // (2) The challenge's boundTo must match the binding we compute locally
  //     from the bundle's package + installer pk. Substitution fails here.
  const expectedBinding = await updateBinding(
    bundle.newPackage.blobs,
    bundle.newPackage.entry.iv,
    installer.pk,
  );
  if (!bytesEqual(bundle.challenge.boundTo, expectedBinding)) {
    bus.emit('bundle-binding-mismatch');
    throw new Error('updater: challenge not bound to this (package, installer) pair');
  }

  // (3) Verify the FROST signature over the challenge-derived message.
  if (!verifyApproval(bundle.signature, bundle.challenge, groupPk, policy, now)) {
    bus.emit('signature-verify-failed');
    throw new Error('updater: signature did not verify');
  }

  // (4) Unwrap the new deployKey with the installer's long-term sk.
  const shared = x25519.getSharedSecret(installer.sk, bundle.ephemeralPk);
  const aesKey = await hkdf(shared, enc.encode('tengen:update:wrap:v2'), bundle.ephemeralPk, 32);
  zeroize(shared);

  let newDeployKey: Uint8Array;
  try {
    newDeployKey = await aesGcmDecrypt(aesKey, bundle.iv, bundle.wrappedDeployKey, UPDATE_AAD);
  } finally {
    zeroize(aesKey);
  }

  // (5) Atomic handoff: wipe old pkg's secrets and return the new pkg.
  handoff(oldPkg);
  return { ...bundle.newPackage, deployKey: newDeployKey };
};

export const handoff = (pkg: DeploymentPackage): void => {
  for (const body of pkg.blobs.values()) zeroize(body);
  (pkg.blobs as Map<string, Uint8Array>).clear();
  zeroize(pkg.deployKey);
  zeroize(pkg.entry.body);
  zeroize(pkg.entry.iv);
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
};
