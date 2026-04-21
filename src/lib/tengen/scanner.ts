/**
 * Scanner — static-analysis heuristics for AI/vibe-coded JS/TS projects.
 *
 *   Regex-based, no AST. Fast, opinionated, and noisy on purpose: we want
 *   false positives more than false negatives, because the user we serve
 *   here is someone who didn't write the code themselves and can't tell
 *   which findings matter. Every finding includes a one-sentence
 *   explanation and a suggested fix.
 *
 * Security Boundary:
 *   ✓ Catches the common vulnerability classes AI coders generate without
 *     realizing: SQL injection via template literals, XSS via
 *     dangerouslySetInnerHTML / innerHTML, eval(), hardcoded API keys,
 *     Math.random() used for security-sensitive values, unvalidated
 *     JSON.parse of request bodies, open redirects.
 *   ✗ This is NOT a sound static analyzer. A real AST-based tool with
 *     dataflow (semgrep, CodeQL) catches far more. Use the scanner as a
 *     first-pass filter; pair with a real analyzer before shipping.
 *   ✗ Regex cannot understand semantics. If the flagged pattern is
 *     actually safe in your case, review and move on. If the scanner
 *     doesn't find anything, it does NOT mean your code is secure.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  readonly id: string;
  readonly file: string;
  readonly line: number;
  readonly severity: Severity;
  readonly title: string;
  readonly snippet: string;
  readonly why: string;
  readonly fix: string;
}

export interface ScanOptions {
  /** Only scan files with these extensions. */
  readonly extensions?: readonly string[];
  /** Skip directory names (recursive). */
  readonly skipDirs?: readonly string[];
  /** Max file size in bytes; larger files are skipped. */
  readonly maxBytes?: number;
}

const DEFAULTS: Required<ScanOptions> = {
  extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  skipDirs: ['node_modules', 'dist', 'build', '.next', '.git', 'coverage', '.turbo', 'out'],
  maxBytes: 1_000_000,
};

// ---- detectors ----------------------------------------------------------

interface Detector {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly why: string;
  readonly fix: string;
  readonly test: (line: string, fullSource: string) => boolean;
}

const DETECTORS: readonly Detector[] = [
  {
    id: 'SQLI-TEMPLATE',
    severity: 'critical',
    title: 'SQL query built with template literal + variable interpolation',
    why: 'Concatenating user-controlled values into a SQL string is the textbook SQL-injection bug. Any attacker who controls the variable controls your database.',
    fix: "Use your driver's parameterized API. With tengen's ward: `import { paramOnly } from 'tengen'; const q = paramOnly`SELECT * FROM t WHERE id=${id}`; driver.query(q.text, q.values);`",
    test: (line) =>
      /`[^`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES|SET)\b[^`]*\$\{[^}]+\}[^`]*`/i.test(line),
  },
  {
    id: 'EVAL',
    severity: 'critical',
    title: 'eval() or new Function() on a string',
    why: 'eval and Function constructors execute arbitrary strings as code. If any piece of that string ever comes from user input, it is remote code execution.',
    fix: 'Replace with explicit branching / JSON.parse / switch. If you need dynamic code, look for a schema-driven interpreter, not eval.',
    test: (line) =>
      /(^|[^A-Za-z0-9_$])eval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line),
  },
  {
    id: 'INNERHTML',
    severity: 'high',
    title: '.innerHTML assigned a non-literal value',
    why: 'Assigning untrusted strings to innerHTML is the classic DOM XSS path. Any <script>, onerror, onclick embedded in the value runs in your origin.',
    fix: 'Use .textContent for plain text, or sanitize with DOMPurify before assigning innerHTML. For React, never bypass JSX escaping.',
    test: (line) => /\.innerHTML\s*=\s*(?!["'`][^"'`]*["'`]\s*;?\s*$)[^=]/.test(line),
  },
  {
    id: 'DANGEROUSLY-SET-INNERHTML',
    severity: 'high',
    title: 'React dangerouslySetInnerHTML',
    why: 'The name is a warning: any value passed here is injected as raw HTML. Without DOMPurify (or equivalent), an attacker-controlled string becomes XSS.',
    fix: 'Prefer plain children so JSX escapes for you. If you truly need HTML, sanitize with DOMPurify first.',
    test: (line) => /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html/.test(line),
  },
  {
    id: 'HARDCODED-SECRET',
    severity: 'critical',
    title: 'Hardcoded API key or token in source',
    why: 'Secrets in source are leaked the moment the repo goes anywhere — GitHub, a colleague, a CI log, an AI assistant. Once committed, they must be rotated.',
    fix: 'Move the value to an environment variable. Add .env to .gitignore. Rotate the secret because it is already effectively public.',
    test: (line) => {
      // Stripe / GitHub / Slack / AWS / OpenAI / generic
      if (/['"`]sk_(live|test)_[A-Za-z0-9]{16,}['"`]/.test(line)) return true;
      if (/['"`]ghp_[A-Za-z0-9]{30,}['"`]/.test(line)) return true;
      if (/['"`]xox[baprs]-[A-Za-z0-9-]{20,}['"`]/.test(line)) return true;
      if (/['"`]AKIA[A-Z0-9]{16}['"`]/.test(line)) return true;
      if (/['"`]sk-[A-Za-z0-9]{32,}['"`]/.test(line)) return true; // OpenAI
      if (/['"`]AIza[A-Za-z0-9_-]{35}['"`]/.test(line)) return true; // Google
      return false;
    },
  },
  {
    id: 'JWT-HARDCODED-SECRET',
    severity: 'critical',
    title: 'JWT signing secret hardcoded',
    why: 'If your JWT signing key is a short literal in code, anyone who reads the repo can forge tokens. Also defeats rotation.',
    fix: 'Load the secret from process.env at startup; rotate if this ever shipped. Consider an asymmetric key (RS256/EdDSA) so you can publish the verifier publicly.',
    test: (line) => {
      // Must reference jwt/jsonwebtoken somewhere on the line AND call .sign
      // with a literal string as the 2nd argument.
      if (!/\b(jwt|jsonwebtoken)\b/i.test(line)) return false;
      return /\.sign\s*\(\s*[^,()]+,\s*['"`][^'"`]{4,}['"`]/.test(line);
    },
  },
  {
    id: 'MATH-RANDOM-SECURITY',
    severity: 'high',
    title: 'Math.random() used for a security-sensitive value',
    why: 'Math.random is predictable to anyone who observes its output for a while. Tokens, session ids, password reset codes, OTPs, nonces all need cryptographic randomness.',
    fix: 'Use crypto.getRandomValues(new Uint8Array(n)) in browsers/Node; crypto.randomBytes(n) in Node only. Tengen ships randomBytes() as a convenience.',
    test: (line) => {
      if (!/Math\.random\s*\(\s*\)/.test(line)) return false;
      // Match "token", "sessionId", "csrfToken", "passwordHash", etc.
      // Not using \b because AI-written code prefers camelCase compounds.
      return /(token|secret|session|password|reset|otp|nonce|salt|csrf|apikey|api_key)/i.test(line);
    },
  },
  {
    id: 'JSON-PARSE-REQUEST',
    severity: 'medium',
    title: 'JSON.parse() directly on request input without schema',
    why: 'Parsing untrusted JSON without shape validation exposes your handler to deeply-nested objects (DoS), prototype pollution, and unexpected types that crash downstream code.',
    fix: "Validate with zod or similar BEFORE trusting the shape. Tengen's ward provides `gate(schema, raw)` that returns `{ ok, value }` without throwing.",
    test: (line) =>
      /JSON\.parse\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body|event\.body|params\.\w+|searchParams\.\w+)/.test(line),
  },
  {
    id: 'OPEN-REDIRECT',
    severity: 'medium',
    title: 'Redirect target derived from user input',
    why: 'If the redirect URL comes from a query parameter or request body, an attacker can craft a phishing link that looks like it came from your domain but bounces to theirs.',
    fix: 'Allowlist redirect targets. Accept only a short code the client sends; map the code to a server-side URL constant.',
    test: (line) =>
      /(res|response)\s*\.\s*redirect\s*\(\s*(req\.|request\.|searchParams|params)/.test(line) ||
      /Response\s*\.\s*redirect\s*\(\s*(req\.|request\.|searchParams|params)/.test(line),
  },
  {
    id: 'CORS-WILDCARD-CREDENTIALS',
    severity: 'high',
    title: 'CORS * with credentials',
    why: 'Access-Control-Allow-Origin: * combined with credentials: true lets any site read authenticated responses from your API. Browsers usually block this combination, but if you set the header manually it is still a misconfiguration.',
    fix: 'List concrete origins or reflect the origin after checking it against an allowlist. Never mix wildcard with credentials.',
    test: (line) =>
      /['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/.test(line) ||
      /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true/.test(line),
  },
  {
    id: 'EXPOSED-ENV-CLIENT',
    severity: 'medium',
    title: 'process.env leaked to client bundle',
    why: 'Anything in a React/Next client component that references a non-NEXT_PUBLIC_ env var ships in the JS bundle. Server-only secrets become public on first page load.',
    fix: "Rename client-exposed variables to NEXT_PUBLIC_* so the leak is explicit. Keep server-only secrets behind API routes.",
    test: (line, src) => {
      if (!/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/.test(line)) return false;
      const isClient = /^\s*['"]use client['"]/m.test(src);
      if (!isClient) return false;
      const m = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
      return !!(m && !m[1]!.startsWith('NEXT_PUBLIC_'));
    },
  },
];

// ---- scanner core -------------------------------------------------------

const isInComment = (line: string): boolean => /^\s*(\/\/|\*|\/\*)/.test(line);

export const scanSource = (file: string, src: string): Finding[] => {
  const findings: Finding[] = [];
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (isInComment(line)) continue;
    for (const d of DETECTORS) {
      if (d.test(line, src)) {
        findings.push({
          id: d.id,
          file,
          line: i + 1,
          severity: d.severity,
          title: d.title,
          snippet: line.trim().slice(0, 160),
          why: d.why,
          fix: d.fix,
        });
      }
    }
  }
  return findings;
};

const walk = async (
  dir: string,
  root: string,
  opts: Required<ScanOptions>,
  out: string[],
): Promise<void> => {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (opts.skipDirs.includes(entry.name)) continue;
      await walk(full, root, opts, out);
    } else if (entry.isFile()) {
      if (!opts.extensions.some((ext) => entry.name.endsWith(ext))) continue;
      const s = await stat(full);
      if (s.size > opts.maxBytes) continue;
      out.push(full);
    }
  }
};

export const scanDir = async (rootDir: string, opts: ScanOptions = {}): Promise<Finding[]> => {
  const merged: Required<ScanOptions> = {
    extensions: opts.extensions ?? DEFAULTS.extensions,
    skipDirs: opts.skipDirs ?? DEFAULTS.skipDirs,
    maxBytes: opts.maxBytes ?? DEFAULTS.maxBytes,
  };
  const root = resolve(rootDir);
  const files: string[] = [];
  await walk(root, root, merged, files);
  const findings: Finding[] = [];
  for (const f of files) {
    const src = await readFile(f, 'utf8');
    for (const finding of scanSource(relative(root, f), src)) findings.push(finding);
  }
  return findings;
};

// ---- formatter ----------------------------------------------------------

const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export const formatReport = (findings: readonly Finding[]): string => {
  if (findings.length === 0) {
    return 'tengen scan: 0 findings. Note: a clean report does not mean the code is secure.\n';
  }
  const sorted = [...findings].sort((a, b) => {
    if (SEV_ORDER[b.severity] !== SEV_ORDER[a.severity]) return SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of sorted) counts[f.severity]++;
  const header =
    `tengen scan — ${findings.length} finding(s) ` +
    `(critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low})\n` +
    '─'.repeat(72) + '\n';
  const body = sorted
    .map(
      (f, i) =>
        `\n[${i + 1}] ${f.severity.toUpperCase()} · ${f.id}  ${f.file}:${f.line}\n` +
        `    ${f.title}\n` +
        `    > ${f.snippet}\n` +
        `    why: ${f.why}\n` +
        `    fix: ${f.fix}`,
    )
    .join('\n');
  return header + body + '\n';
};
