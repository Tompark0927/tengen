import { test } from 'node:test';
import assert from 'node:assert/strict';

import { formatReport, scanSource } from './scanner';
import { securityHeaders } from './headers';

test('scanner: flags SQL injection via template literal', () => {
  const src = "const q = `SELECT * FROM users WHERE id = ${userId}`;";
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'SQLI-TEMPLATE'));
});

test('scanner: does NOT flag parameterized sql-looking literal', () => {
  const src = 'const q = "SELECT * FROM users WHERE id = $1";';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'SQLI-TEMPLATE').length, 0);
});

test('scanner: flags eval + new Function', () => {
  const src =
    'function a(x) { return eval(x); }\n' +
    'const f = new Function("return 1");';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'EVAL').length, 2);
});

test('scanner: flags dangerouslySetInnerHTML', () => {
  const src = 'return <div dangerouslySetInnerHTML={{ __html: bio }} />;';
  const findings = scanSource('x.tsx', src);
  assert.ok(findings.some((f) => f.id === 'DANGEROUSLY-SET-INNERHTML'));
});

test('scanner: flags innerHTML = <variable>', () => {
  const src = 'element.innerHTML = userInput;';
  const findings = scanSource('x.js', src);
  assert.ok(findings.some((f) => f.id === 'INNERHTML'));
});

test('scanner: flags hardcoded API key patterns', () => {
  // NOTE: these strings ARE dummy/syntactic-only test fixtures; no real keys.
  const src =
    'const stripe = "sk_live_" + "abcdef0123456789abcdef01";\n' + // split to avoid secret-scan alert on real scanners
    'const token = "sk_live_abcdef0123456789abcdef01abcdef01";\n' +
    'const openai = "sk-' + 'a'.repeat(48) + '";';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'HARDCODED-SECRET'));
});

test('scanner: flags Math.random() for token/session/password contexts', () => {
  const src =
    'const token = Math.random().toString(36);\n' +
    'const sessionId = Math.random() * 1e9;';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'MATH-RANDOM-SECURITY').length, 2);
});

test('scanner: ignores Math.random() in non-security contexts', () => {
  const src = 'const jitter = Math.random() * 100; // animation';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.filter((f) => f.id === 'MATH-RANDOM-SECURITY').length, 0);
});

test('scanner: flags JSON.parse(req.body)', () => {
  const src = 'const data = JSON.parse(req.body);';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'JSON-PARSE-REQUEST'));
});

test('scanner: flags open redirect from query param', () => {
  const src = 'res.redirect(req.query.next);';
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'OPEN-REDIRECT'));
});

test('scanner: flags CORS wildcard with credentials', () => {
  const src = `cors({ origin: "*", credentials: true })`;
  const findings = scanSource('x.ts', src);
  assert.ok(findings.some((f) => f.id === 'CORS-WILDCARD-CREDENTIALS'));
});

test('scanner: flags server env leaked to client component', () => {
  const src = `'use client';\nconst key = process.env.DATABASE_URL;`;
  const findings = scanSource('x.tsx', src);
  assert.ok(findings.some((f) => f.id === 'EXPOSED-ENV-CLIENT'));
});

test('scanner: ignores NEXT_PUBLIC_ envs in client components', () => {
  const src = `'use client';\nconst key = process.env.NEXT_PUBLIC_API_URL;`;
  const findings = scanSource('x.tsx', src);
  assert.equal(findings.filter((f) => f.id === 'EXPOSED-ENV-CLIENT').length, 0);
});

test('scanner: comments are not flagged', () => {
  const src = '// eval(x)\n/* const q = `SELECT ${id}` */\n// innerHTML = x';
  const findings = scanSource('x.ts', src);
  assert.equal(findings.length, 0);
});

test('scanner: formatReport produces readable output', () => {
  const src = 'const q = `SELECT * FROM t WHERE id = ${id}`;';
  const findings = scanSource('x.ts', src);
  const report = formatReport(findings);
  assert.ok(report.includes('CRITICAL'));
  assert.ok(report.includes('SQLI-TEMPLATE'));
  assert.ok(report.includes('x.ts:1'));
});

test('scanner: empty findings produces a "clean but beware" note', () => {
  const report = formatReport([]);
  assert.ok(/does not mean the code is secure/i.test(report));
});

test('headers: default set includes CSP, HSTS, framing, and sane misc', () => {
  const h = securityHeaders();
  assert.ok(h['Content-Security-Policy']?.includes("default-src 'none'"));
  assert.ok(h['Strict-Transport-Security']?.includes('max-age='));
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['Referrer-Policy'], 'no-referrer');
});

test('headers: csp=off omits CSP', () => {
  const h = securityHeaders({ csp: 'off' });
  assert.equal(h['Content-Security-Policy'], undefined);
});

test('headers: next-app preset allows inline styles', () => {
  const h = securityHeaders({ csp: 'next-app' });
  assert.ok(h['Content-Security-Policy']?.includes("style-src 'self' 'unsafe-inline'"));
});

test('headers: explicit frame-ancestors replaces default DENY', () => {
  const h = securityHeaders({ frameAncestors: ["'self'", 'https://example.com'] });
  assert.equal(h['X-Frame-Options'], undefined);
  assert.ok(h['Content-Security-Policy']?.includes("frame-ancestors 'self' https://example.com"));
});
