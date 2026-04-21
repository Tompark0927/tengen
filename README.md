# Tengen

> You shipped an app. You wrote most of it with AI help. You're not sure
> it's secure. You don't want to become a security engineer. You just
> want to stop worrying.

That's the person Tengen is for.

Tengen does three things, in order of how quickly they help you:

1. **`tengen scan`** — static-analyzes your JS/TS codebase and reports
   the vulnerability classes AI coders commonly ship: SQL injection,
   `eval()`, `dangerouslySetInnerHTML`, hardcoded API keys, `Math.random`
   used for tokens, unvalidated `JSON.parse(req.body)`, open redirects,
   CORS wildcard with credentials, server env vars leaked into client
   components. Each finding explains what's wrong and how to fix it.

2. **`securityHeaders()` + `ward`** — drop-in helpers for hardening a
   live app without a rewrite: a CSP / HSTS / framing header factory,
   a `gate()` that Zod-validates request bodies without throwing, a
   tagged-template `paramOnly` that forces parameterized SQL, and
   output encoders for HTML / attributes / URLs.

3. **Encrypted data-at-rest primitives** — if you want stronger
   defense-in-depth, Tengen ships a full FROST-Ed25519 threshold
   signing stack, Shamir-sharded data scatter, an oblivious-fetch
   pattern, and a fragmented-execution runtime. These are for people
   who want the full protocol; most people should start with (1) and (2).

---

## ⚠️ STATUS: PRE-AUDIT RESEARCH CODE

**Do not use Tengen with data whose compromise would cause real-world harm.**

No independent cryptographic auditor has reviewed this repository.
Primitives come from audited libraries (Web Crypto, `@noble/curves`,
`@noble/hashes`), but the composition — FROST wrapper, shatter/scatter
encoding, update binding, Merkle canonicalization, scanner patterns —
is original and has not been externally reviewed. Before any
production use, commission an audit (`AUDIT_RFP.md` is ready to send).

---

## Install

Requires **Node 22+**.

```bash
git clone https://github.com/tengen-dev/tengen
cd tengen
npm install
```

## Why use this

**For individuals:** you shipped an AI-generated app and you're worried.
Run `tengen scan` in 5 seconds. If it's clean, breathe. If it's not,
the tool tells you exactly which line, why it's dangerous, and how to
fix it. See [`docs/AI_ANTIPATTERNS.md`](docs/AI_ANTIPATTERNS.md) for the
catalogue of 20 common vulnerabilities AI tools ship by default.

**For teams / startups preparing for SOC 2 / ISO 27001:**
`tengen scan --compliance` annotates every finding with OWASP Top 10,
CWE, SOC 2 CC, and ISO 27001 Annex A control mappings. Export with
`--format html` for an auditor-ready report.
See [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) for the full mapping +
an evidence checklist auditors actually ask for. Drop-in GitHub Action
at [`docs/github-action-tengen-scan.yml`](docs/github-action-tengen-scan.yml).

**What tengen scan catches that `npm audit` doesn't:**
`npm audit` finds known-vulnerable dependencies. `tengen scan` finds
vulnerabilities in YOUR CODE — the SQL injection on line 42 of your
own router, the `Math.random()` session token, the hardcoded Stripe
key. The two tools are complements, not substitutes.

## 60-second demo

```bash
# 1. Scan a project for AI-coder vulnerabilities
npm run tengen -- scan ./your-app/src
# → "7 findings (4 critical, 1 high, 2 medium)" with file:line, reason, fix

# 2. Add security headers to a Next.js app (middleware.ts)
#    import { securityHeaders } from 'tengen';
#    const h = securityHeaders({ csp: 'next-app' });
#    for (const [k, v] of Object.entries(h)) res.headers.set(k, v);

# 3. Harden a SQL query
#    import { paramOnly } from 'tengen';
#    const q = paramOnly`SELECT * FROM users WHERE id=${id}`;
#    db.query(q.text, q.values);  // attacker cannot inject

# 4. Stop logging deploy keys by accident (if you use Tengen's shatter)
#    const pub = serializePublic(pkg);       // safe to publish
#    const key = serializeDeployKey(pkg);    // treat as password
```

## What the scanner catches

| Class | Example line the scanner flags |
|-------|-------------------------------|
| SQLI-TEMPLATE | `` `SELECT * FROM t WHERE id = ${userId}` `` |
| EVAL | `eval(req.body.code)` / `new Function(input)` |
| INNERHTML | `el.innerHTML = someVar` |
| DANGEROUSLY-SET-INNERHTML | `dangerouslySetInnerHTML={{ __html: bio }}` |
| HARDCODED-SECRET | `const key = 'sk_live_...'` (Stripe, GitHub, Slack, AWS, OpenAI, Google) |
| JWT-HARDCODED-SECRET | `jwt.sign(payload, 'supersecret')` |
| MATH-RANDOM-SECURITY | `const token = Math.random().toString(36)` |
| JSON-PARSE-REQUEST | `JSON.parse(req.body)` with no schema |
| OPEN-REDIRECT | `res.redirect(req.query.next)` |
| CORS-WILDCARD-CREDENTIALS | `cors({ origin: '*', credentials: true })` |
| EXPOSED-ENV-CLIENT | `process.env.DATABASE_URL` in a `'use client'` file |

The scanner is intentionally **noisy over missing things**: it prefers
false positives (review quickly) to false negatives (silent breach).
It is NOT a sound static analyzer — pair with CodeQL or Semgrep before
shipping anything non-trivial.

## CLI

```bash
tengen scan <project-dir>
  [--format text|json|markdown|html]      default: text
  [--fail-on critical|high|medium|low]    default: high  (exits 2 on match)
  [--ignore <path>]                       default: <project-dir>/.tengenignore
  [--compliance]                          annotate with OWASP/CWE/SOC2/ISO

tengen deploy <source-file> <out-dir>     # encrypt + fragment a file
tengen verify <pkg-dir>                   # recompute Merkle root
tengen run    <pkg-dir>                   # execute chain, recover source to stdout
tengen audit                              # run the adversarial self-audit
tengen version
```

## Library surface

Everything re-exported from the root:

```ts
import {
  // Scanner + hardening helpers (start here)
  scanDir, formatReport, securityHeaders, gate, paramOnly, escHtml, canonicalize,

  // Encrypted data at rest
  shatter, reassemble, sealManifest, openManifest,

  // Deployment protocol
  deploy, run, serializePublic, serializeDeployKey,

  // FROST threshold signing (DKG or trusted-dealer)
  dealShares, commit, approve, aggregateApprovals, verifyApproval,
  dkgSimulate, dkgStart, dkgShareFor, dkgAcceptShare, dkgFinalize,

  // Signed updates
  sealUpdate, installUpdate, generateInstallerKeypair,

  // Local-only event bus + risk scoring
  bus, newEventBus,
} from 'tengen';
```

Each module carries a **Security Boundary** comment block enumerating
what it does and does NOT defend against.

## Scripts

```bash
npm run typecheck
npm test            # 95 unit + integration tests
npm run audit       # adversarial self-audit (12 attack scenarios)
npm run fuzz        # randomized input harness (2000+ runs)
npm run bench       # performance + oblivious-fetch multipliers
npm run sbom        # generate CycloneDX software bill of materials
npm run tengen      # CLI entry point
```

## Layout

```
tengen/
├── src/
│   ├── lib/tengen/    # library modules (scanner, headers, crypto, runtime)
│   └── cli/tengen.ts  # CLI harness
├── loader/             # Go RAM-only loader (mlock + Ed25519 + scrub)
├── .github/workflows/ci.yml
├── AUDIT_RFP.md        # ready-to-send external-audit specification
├── NOTICE.md           # license rationale + dep licenses
└── LICENSE             # PolyForm Noncommercial 1.0.0
```

## Threat model

**Defends against**: passive network observers, reconnaissance scans,
per-byte blob tampering, update bait-and-switch, quorum share leakage
via wire observation, static vulnerability patterns common in AI-written
code, missing HTTP security headers, unparameterized SQL, XSS via
`innerHTML`/`dangerouslySetInnerHTML`, weak randomness for security
tokens.

**Does NOT defend against**: side-channel attacks (cache/power/EM),
compromise of a signer's long-term key, a determined reverse engineer
on the runtime host, denial of service, sovereign / legal compulsion,
application-logic bugs in code the scanner didn't flag, runtime
compromise of the machine running Tengen itself.

## License

PolyForm Noncommercial 1.0.0. See `LICENSE` and `NOTICE.md`.
Commercial licensing: contact the repository owner.
