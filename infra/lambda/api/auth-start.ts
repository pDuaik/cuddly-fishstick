// lambda/api/auth-start.ts
// CommonJS-compatible Lambda export: handler: "auth_start.handler"

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';

function b64url(buf: Buffer): string {
  // Node 22 supports base64url, but we keep it explicit and portable.
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function pkceVerifier(): string {
  // RFC 7636: 43..128 chars
  // 32 bytes -> 43 chars base64url
  return b64url(randomBytes(32));
}

function pkceChallenge(verifier: string): string {
  const digest = createHash('sha256').update(verifier, 'utf8').digest();
  return b64url(digest);
}

function getQueryString(event: APIGatewayProxyEventV2): Record<string, string> {
  // HTTP API v2 provides `queryStringParameters`
  // which can be undefined.
  return (event.queryStringParameters ?? {}) as Record<string, string>;
}

function safeNextPath(raw: string | undefined, fallback: string): string {
  /**
   * Allow only relative paths like "/app/page1.html".
   * Reject anything that could become an absolute URL (//, http:, https:, etc).
   */
  if (!raw) return fallback;

  const v = raw.trim();
  if (!v.startsWith('/')) return fallback;
  if (v.startsWith('//')) return fallback;

  const lowered = v.toLowerCase();
  if (lowered.includes('://')) return fallback;

  return v;
}

function getHeader(event: APIGatewayProxyEventV2, name: string): string {
  const headers = event.headers ?? {};
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return (v ?? '').toString();
  }
  return '';
}

function enforceOriginVerify(event: APIGatewayProxyEventV2): APIGatewayProxyResultV2 | null {
  const headerName = (process.env.ORIGIN_VERIFY_HEADER_NAME ?? '').trim();
  const expected = (process.env.ORIGIN_VERIFY_HEADER_VALUE ?? '').trim();

  // Template stance: must be configured and must match (fail closed)
  if (!headerName || !expected) {
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Server misconfigured (origin verify not set)' }),
    };
  }

  const actual = getHeader(event, headerName);
  if (!actual) {
    return {
      statusCode: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Forbidden (missing origin verify header)' }),
    };
  }

  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  const ok = a.length === b.length && timingSafeEqual(a, b);

  if (!ok) {
    return {
      statusCode: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Forbidden (bad origin verify header)' }),
    };
  }

  return null;
}

function requireEnv(name: string): string {
  const v = (process.env[name] ?? '').trim();
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const deny = enforceOriginVerify(event);
  if (deny) return deny;

  const clientId = requireEnv('COGNITO_CLIENT_ID');
  const cognitoDomain = requireEnv('COGNITO_DOMAIN'); // e.g. auth.example.com
  const redirectUri = requireEnv('REDIRECT_URI'); // https://example.com/auth/callback

  const defaultPostLogin = (process.env.POST_LOGIN_REDIRECT ?? '/app/page1.html').trim() || '/app/page1.html';

  const qs = getQueryString(event);
  const nextPath = safeNextPath(qs.next, defaultPostLogin);

  // cookie names (keep template-consistent)
  const stateCookieName = (process.env.OAUTH_STATE_COOKIE_NAME ?? 'oauth_state').trim() || 'oauth_state';
  const verifierCookieName = (process.env.PKCE_VERIFIER_COOKIE_NAME ?? 'pkce_verifier').trim() || 'pkce_verifier';
  const postLoginCookieName = (process.env.POST_LOGIN_COOKIE_NAME ?? 'post_login').trim() || 'post_login';

  // mint state + pkce
  const state = b64url(randomBytes(24));
  const verifier = pkceVerifier();
  const challenge = pkceChallenge(verifier);

  // Auth cookies are short-lived
  const maxAgeSeconds = 300;

  // NOTE: These are NOT __Host- cookies because they are scoped to Path=/auth
  // (and __Host- requires Path=/)
  const common = `Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;

  const cookies = [
    `${stateCookieName}=${state}; ${common}`,
    `${verifierCookieName}=${verifier}; ${common}`,
    `${postLoginCookieName}=${encodeURIComponent(nextPath)}; ${common}`,
  ];

  const authorizeUrl =
    `https://${cognitoDomain}/oauth2/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&response_type=code` +
    `&scope=openid+email+profile` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge_method=S256` +
    `&code_challenge=${encodeURIComponent(challenge)}`;

  return {
    statusCode: 302,
    headers: {
      location: authorizeUrl,
      'cache-control': 'no-store',
    },
    cookies,
    body: '',
  };
}
