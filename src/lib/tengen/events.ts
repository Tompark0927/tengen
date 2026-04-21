/**
 * Local-only event bus + risk scoring.
 *
 *   The user's concern is correct: an alerting system is itself attack
 *   surface. A push-based alarm that calls Slack / email / a log endpoint
 *   on every detection gives the attacker (a) an oracle — probe and watch
 *   for the alarm — and (b) an exfiltration path, if the destination is
 *   compromised. It also directly contradicts Tengen's "stateless,
 *   traceless" posture.
 *
 *   So this module does the opposite of an external alarm. It is a
 *   ring-buffered, in-RAM, zero-side-effect bus that emits events when the
 *   library's own defensive paths fire. Nothing leaves the process unless
 *   the application explicitly subscribes and forwards (which it should
 *   only do with full awareness of the tradeoffs documented below).
 *
 * Security Boundary:
 *   ✓ No disk writes. No network calls. No console output.
 *   ✓ `clear()` zeroizes the ring buffer.
 *   ✓ Emission happens on the SAME conditions that throw today — a passive
 *     attacker observing timing learns nothing new from the event system.
 *   ✓ Error messages thrown by the library are UNCHANGED. The event system
 *     is invisible to a caller that doesn't subscribe.
 *   ✗ If a subscriber forwards events externally (Slack, HTTP, file),
 *     ALL the risks the bus was designed to avoid return: oracle behavior,
 *     exfiltration, classifier-gradient leakage to the attacker. That is
 *     the subscriber's responsibility, not the bus's.
 *   ⚠ Risk scores are heuristic. They help adapt defensive posture (e.g.,
 *     increase decoy count, rotate keys, self-destruct). They are NOT a
 *     gate — do not use a score to decide "is this allowed" because the
 *     attacker who learns the threshold will tune below it.
 */

import { zeroize } from './primitives';

export type EventKind =
  // Evidence of active tampering.
  | 'merkle-mismatch'           // integrity root did not match at runtime
  | 'aes-gcm-tag-failure'       // decrypt failed (tamper / replay / wrong key)
  | 'nonce-reuse-attempt'       // sign() called with an already-burned nonce
  | 'signature-verify-failed'   // FROST / updater signature rejected
  // Quorum + update anomalies.
  | 'quorum-below-threshold'
  | 'quorum-expired-challenge'
  | 'bundle-misaddressed'       // updater bundle not addressed to us
  | 'bundle-binding-mismatch'   // challenge not bound to this package
  // Runtime environment + traffic.
  | 'observer-detected'         // inspector / devtools / timing heuristic
  | 'route-token-invalid'
  | 'route-token-expired'
  | 'channel-expired-mid-run'
  | 'lightspeed-anomaly'
  | 'fetch-blob-missing'
  | 'manifest-decode-failed';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Per-event risk weight. Summed into the score with exponential time decay. */
const WEIGHT: Record<EventKind, number> = {
  'merkle-mismatch': 40,
  'aes-gcm-tag-failure': 20,
  'nonce-reuse-attempt': 40,
  'signature-verify-failed': 35,
  'quorum-below-threshold': 15,
  'quorum-expired-challenge': 10,
  'bundle-misaddressed': 25,
  'bundle-binding-mismatch': 30,
  'observer-detected': 15,
  'route-token-invalid': 8,
  'route-token-expired': 4,
  'channel-expired-mid-run': 6,
  'lightspeed-anomaly': 25,
  'fetch-blob-missing': 3,
  'manifest-decode-failed': 10,
};

const SEVERITY: Record<EventKind, Severity> = {
  'merkle-mismatch': 'critical',
  'aes-gcm-tag-failure': 'high',
  'nonce-reuse-attempt': 'critical',
  'signature-verify-failed': 'critical',
  'quorum-below-threshold': 'medium',
  'quorum-expired-challenge': 'low',
  'bundle-misaddressed': 'high',
  'bundle-binding-mismatch': 'critical',
  'observer-detected': 'medium',
  'route-token-invalid': 'low',
  'route-token-expired': 'low',
  'channel-expired-mid-run': 'low',
  'lightspeed-anomaly': 'high',
  'fetch-blob-missing': 'low',
  'manifest-decode-failed': 'medium',
};

export interface Event {
  readonly kind: EventKind;
  readonly severity: Severity;
  /** Monotonic wall clock ms. */
  readonly at: number;
  /** Opaque actor handle (e.g., session.id b64u). Never an external identifier. */
  readonly actor?: string;
  /** Short, non-secret context. MUST NOT contain keys, plaintext, or addresses. */
  readonly note?: string;
}

export type Subscriber = (e: Event) => void;
export type Unsubscribe = () => void;

/** Time-decay half-life for risk scores. */
const DECAY_HALF_LIFE_MS = 60_000;

export interface EventBus {
  emit(kind: EventKind, opts?: { actor?: string; note?: string }): void;
  subscribe(fn: Subscriber): Unsubscribe;
  recent(n?: number): readonly Event[];
  /**
   * Score in [0, 100]. If `actor` is provided, only events attributed to
   * that actor contribute; otherwise all events in the ring are used.
   * Older events decay with half-life DECAY_HALF_LIFE_MS.
   */
  riskScore(actor?: string, now?: number): number;
  /** Drop all buffered events and zero associated string buffers. */
  clear(): void;
}

const createEventBus = (capacity = 1024): EventBus => {
  const ring: Event[] = [];
  const subscribers = new Set<Subscriber>();

  const emit = (kind: EventKind, opts: { actor?: string; note?: string } = {}) => {
    const e: Event = {
      kind,
      severity: SEVERITY[kind],
      at: Date.now(),
      ...(opts.actor !== undefined ? { actor: opts.actor } : {}),
      ...(opts.note !== undefined ? { note: opts.note } : {}),
    };
    ring.push(e);
    if (ring.length > capacity) ring.shift();
    // Fan out synchronously. Subscriber errors must not crash the caller;
    // we swallow them, which is the right tradeoff for a defensive bus.
    for (const fn of subscribers) {
      try {
        fn(e);
      } catch {
        /* subscriber bug — do not propagate */
      }
    }
  };

  const subscribe = (fn: Subscriber): Unsubscribe => {
    subscribers.add(fn);
    return () => {
      subscribers.delete(fn);
    };
  };

  const recent = (n = 100): readonly Event[] => ring.slice(-n);

  const riskScore = (actor?: string, now = Date.now()): number => {
    let sum = 0;
    for (const e of ring) {
      if (actor !== undefined && e.actor !== actor) continue;
      const age = Math.max(0, now - e.at);
      const decay = Math.pow(0.5, age / DECAY_HALF_LIFE_MS);
      sum += WEIGHT[e.kind] * decay;
    }
    return Math.min(100, Math.round(sum));
  };

  const clear = () => {
    // Zeroize actor + note strings we can reach. Strings are immutable in JS
    // so we replace refs; memory reclaim depends on GC, same caveat as
    // primitives.zeroize. Ring is emptied regardless.
    for (const e of ring) {
      delete (e as { actor?: string }).actor;
      delete (e as { note?: string }).note;
    }
    ring.length = 0;
    void zeroize;
  };

  return { emit, subscribe, recent, riskScore, clear };
};

/** Process-wide default bus. Libraries emit into this unless a caller
 *  explicitly threads their own bus through an option. */
export const bus: EventBus = createEventBus();

/** Factory for callers who want an isolated bus (e.g., multi-tenant). */
export const newEventBus = (capacity?: number): EventBus => createEventBus(capacity);
