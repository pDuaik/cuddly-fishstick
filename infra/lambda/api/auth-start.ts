// lambda/api/auth-start.ts
// CommonJS-compatible Lambda export: handler: "auth_start.handler"

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { createHash, randomBytes } from 'crypto';

import { enforceOriginVerify, requireEnv, env, buildCookie, json } from './helpers';

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

function safeNextPath(raw: string | undefined, fallback: string): string {
  // Allow only relative paths like "/app/page1.html".
  // Reject anything that could become an absolute URL (//, http:, https:, etc).
  if (!raw) return fallback;

  const v = raw.trim();
  if (!v.startsWith('/')) return fallback;
  if (v.startsWith('//')) return fallback;

  const lowered = v.toLowerCase();
  if (lowered.includes('://')) return fallback;

  return v;
}

export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { message: ov.message });

  const clientId = requireEnv('COGNITO_CLIENT_ID');
  const cognitoDomain = requireEnv('COGNITO_DOMAIN'); // e.g. auth.example.com
  const redirectUri = requireEnv('REDIRECT_URI'); // https://example.com/auth/callback

  const defaultPostLogin = env('POST_LOGIN_REDIRECT', '/app/page1.html') || '/app/page1.html';

  const qs = (event.queryStringParameters ?? {}) as Record<string, string | undefined>;
  const nextPath = safeNextPath(qs.next, defaultPostLogin);

  // cookie names (keep template-consistent)
  const stateCookieName = env('OAUTH_STATE_COOKIE_NAME', 'oauth_state') || 'oauth_state';
  const verifierCookieName = env('PKCE_VERIFIER_COOKIE_NAME', 'pkce_verifier') || 'pkce_verifier';
  const postLoginCookieName = env('POST_LOGIN_COOKIE_NAME', 'post_login') || 'post_login';

  // cookie path (must match auth-callback + auth-logout clear path)
  const authCookiePath = env('AUTH_COOKIE_PATH', '/auth') || '/auth';

  // mint state + pkce
  const state = b64url(randomBytes(24));
  const verifier = pkceVerifier();
  const challenge = pkceChallenge(verifier);

  // Auth cookies are short-lived
  const maxAgeSeconds = 300;

  // NOTE: These are NOT __Host- cookies because they are scoped to Path=/auth
  // (and __Host- requires Path=/)
  const authCookieAttrs = {
    path: authCookiePath,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax' as const,
    maxAge: maxAgeSeconds,
  };

  const cookies = [
    buildCookie(stateCookieName, state, authCookieAttrs),
    buildCookie(verifierCookieName, verifier, authCookieAttrs),
    buildCookie(postLoginCookieName, nextPath, authCookieAttrs),
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
