/**
 * Security-headers factory (framework neutral).
 *
 *   Returns a plain record of HTTP response headers. Works with any
 *   framework that lets you set headers — Next.js, Express, Hono,
 *   Fastify, Cloudflare Workers, plain Node http.
 *
 *   Defaults are conservative (strict CSP, no inline scripts, no inline
 *   styles, no framing). If any default breaks your app, override the
 *   relevant preset rather than loosening globally.
 *
 * Security Boundary:
 *   ✓ Sets every HTTP header that a reasonable defender would enable.
 *   ✓ Defaults are strict. If your app breaks, the headers found a real
 *     issue (usually an inline script or a third-party iframe).
 *   ✗ Headers alone do not secure your code. They are the outermost
 *     layer; SQL injection in your backend ignores every one of them.
 *   ✗ Does NOT set Set-Cookie attributes — cookie flags are per-cookie
 *     and need to go on the cookie itself (HttpOnly, Secure, SameSite).
 *
 * Example (Next.js middleware):
 *
 *   import { NextResponse } from 'next/server';
 *   import { securityHeaders } from 'tengen';
 *
 *   export function middleware() {
 *     const res = NextResponse.next();
 *     for (const [k, v] of Object.entries(securityHeaders())) res.headers.set(k, v);
 *     return res;
 *   }
 */

export interface HeaderOptions {
  /**
   * Override the Content-Security-Policy preset.
   *   'strict'       — default; no inline scripts or styles, no third-party origins.
   *   'next-app'     — relaxes style-src to 'unsafe-inline' (Next needs it).
   *   'off'          — omit the CSP header entirely (NOT RECOMMENDED).
   *   string          — use this verbatim as the CSP value.
   */
  readonly csp?: 'strict' | 'next-app' | 'off' | string;
  /** Disable HSTS (default: enabled with 2-year max-age). */
  readonly hsts?: 'off' | { maxAgeSeconds?: number; includeSubDomains?: boolean; preload?: boolean };
  /** Allow framing (default: DENY). Only set if you intentionally serve in an iframe. */
  readonly frameAncestors?: readonly string[];
}

const cspStrict =
  "default-src 'none'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "connect-src 'self'; " +
  "font-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'none'; " +
  "form-action 'none'; " +
  "require-trusted-types-for 'script'";

const cspNextApp =
  "default-src 'none'; " +
  "script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: blob:; " +
  "connect-src 'self'; " +
  "font-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'none'; " +
  "form-action 'self'";

export const securityHeaders = (opts: HeaderOptions = {}): Record<string, string> => {
  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };

  // CSP
  const csp =
    opts.csp === 'off' ? null :
    opts.csp === 'next-app' ? cspNextApp :
    typeof opts.csp === 'string' && opts.csp.length > 0 ? opts.csp :
    cspStrict;
  if (csp) headers['Content-Security-Policy'] = csp;

  // Framing
  if (opts.frameAncestors && opts.frameAncestors.length > 0) {
    // Frame-ancestors wins in modern browsers; X-Frame-Options is legacy.
    // Skip X-Frame-Options when caller opts in to specific ancestors.
    headers['Content-Security-Policy'] = (csp ?? '').replace(
      /frame-ancestors\s+[^;]+;?\s*/,
      `frame-ancestors ${opts.frameAncestors.join(' ')}; `,
    );
  } else {
    headers['X-Frame-Options'] = 'DENY';
  }

  // HSTS
  if (opts.hsts !== 'off') {
    const h = typeof opts.hsts === 'object' ? opts.hsts : {};
    const parts = [`max-age=${h.maxAgeSeconds ?? 63072000}`];
    if (h.includeSubDomains !== false) parts.push('includeSubDomains');
    if (h.preload) parts.push('preload');
    headers['Strict-Transport-Security'] = parts.join('; ');
  }

  return headers;
};
