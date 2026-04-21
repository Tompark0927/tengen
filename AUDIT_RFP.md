# Tengen — External Cryptographic Audit RFP

**Status:** Pre-audit research codebase. No external review performed to date.

**Scope contact:** contact via GitHub issues on the repository
(anonymized during pre-audit phase; will be updated to a dedicated
security mailbox before engagement).
**Repository:** https://github.com/tengen-dev/tengen  (private — access granted per engagement)

**Proposed engagement length:** 2–4 weeks of reviewer time, plus 1 week
for response + re-review after fixes.

**Budget band:** USD $30k–$60k, depending on firm and depth requested.

---

## 1. What is Tengen

A TypeScript library + CLI + Go loader implementing a stealth-oriented
security architecture for user data. The core properties it attempts to
provide:

- **Metadata-less storage**: user data is split by Shamir, each shard is
  AES-GCM encrypted under a session-derived key, and shard addresses are
  HKDF-derived so a shard at rest carries no identifying information.
- **Oblivious retrieval**: the runtime fetches the full blob set (real +
  decoys) in uniform order so an external observer of the blob store
  cannot distinguish real from decoy by access pattern.
- **FROST-Ed25519 threshold approvals**: m-of-n quorum via Schnorr
  threshold signing. Signers release only partial signatures; no share
  material is ever transmitted.
- **X25519-ECIES update wrapping**: new deploy keys are encrypted to a
  specific installer's long-term public key.
- **Fragment-chain execution**: source code is fragmented into micro-nodes
  connected by output-chained PoW puzzles; each hop has a short key TTL.
- **Tamper-evident canary**: Merkle root over the blob set, verified
  before runtime begins.

## 2. What we want reviewed, in priority order

### Priority A — cryptographic protocol correctness

1. **`src/lib/tengen/frost.ts`** — FROST-Ed25519 (trusted-dealer variant).
   Specifically the Lagrange coefficient computation, binding-factor
   derivation, group commitment aggregation, and challenge hashing.
   Reference: RFC 9591. We implemented a simplified 2-round variant.
2. **`src/lib/tengen/dkg.ts`** — Pedersen DKG with Feldman verification.
   Does NOT implement complaint / blame phase.
3. **`src/lib/tengen/shamir.ts`** — Shamir secret sharing over GF(256)
   with the Rijndael polynomial 0x11b, generator 3.
4. **`src/lib/tengen/updater.ts`** — FROST signature + X25519 ECIES
   composition. Binding of the signature to (deploymentRoot ∥ installerPk)
   is the novel part; verify there is no substitution or relay vector.

### Priority B — protocol construction around audited primitives

5. **`src/lib/tengen/fragment.ts`** — fragment chain: correctness of
   edge-secret derivation, puzzle construction, AAD binding per hop.
6. **`src/lib/tengen/shatter.ts`** — data shattering + manifest envelope.
   Specifically that the manifest cannot be forged and that the
   information-theoretic Shamir property is preserved across the
   AES-GCM outer layer.
7. **`src/lib/tengen/integrity.ts`** — Merkle tree domain separation,
   canonical sort, and the `obliviousFetchAll` contract.

### Priority C — implementation-level concerns

8. Constant-time behavior in scalar arithmetic (BigInt operations are
   NOT constant-time; assess the impact for FROST).
9. JavaScript memory model limits: `zeroize()` claims vs reality
   (coroutine state, V8 heap moves). We do not claim to defeat a
   memory-capable adversary; confirm this is adequately scoped.
10. Randomness source: all entropy routes through `crypto.getRandomValues`.
    Verify no `Math.random` leakage or test-only mocks survive in the
    production build surface.

### Out of scope

- Side-channel analysis of the host machine (EM, power, cache).
- Network-level traffic analysis beyond what `obliviousFetchAll` addresses.
- The Go loader (`loader/`) past the Ed25519 signature-verification path;
  its execution callback is a stub.
- Any UI. There is none.

## 3. Known findings (internal audit already recorded)

`npm run audit` executes `src/lib/tengen/audit.ts`, which itself attacks
the codebase. Current report summary:

| Finding | Severity | Verdict |
|---------|----------|---------|
| A — Quorum share leakage | CRITICAL | NOT REPRODUCED under FROST |
| B — Traffic enumeration | HIGH | NOT REPRODUCED under oblivious fetch |
| C — Merkle scope | INFORMATIONAL | Documented as decoy canary, not shield |
| D — Observer bypass | INFORMATIONAL | Documented as advisory layer |
| E — PoW ≤ MAC under secret leak | INFORMATIONAL | Accepted design limit |
| F — FROST bait-and-switch | CRITICAL | NOT REPRODUCED (message-bound) |

Auditors should treat these as starting hypotheses, not conclusions.

## 4. Deliverables we expect

- Written report covering every Priority A/B item with findings classified
  Critical / High / Medium / Low / Informational, each with reproduction
  steps and suggested remediation.
- A machine-readable summary (JSON or similar) that can be cross-referenced
  with `audit.ts`.
- Post-remediation re-review of any Critical / High findings.
- Permission to publish the report (redactable at auditor's discretion)
  after remediation.

## 5. What we provide

- Read access to the repository at a pinned commit SHA.
- A dedicated engineering contact during business hours for clarifications.
- Pre-audit fuzz + benchmark output (`npm run fuzz`, `npm run bench`) to
  avoid auditors re-discovering known-expected behaviors.
- SBOM of the dependency tree: `@noble/curves`, `@noble/hashes`, `zod`,
  plus devDependencies (typescript, tsx, @types/node).
- An NDA (mutual, non-exclusive).

## 6. What we do NOT provide

- Production keys or production data. The audit covers code; operational
  key handling is a separate engagement.
- Commitment to accept every finding. Recommendations that conflict with
  explicit non-goals (see Threat Model in README.md) may be marked
  "acknowledged, out of scope".

---

*Before sending: pin a commit SHA and attach README.md + current
`npm run audit` + `npm run fuzz` output.*
