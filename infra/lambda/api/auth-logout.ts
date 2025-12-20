// lambda/api/auth-logout.ts
// CommonJS-compatible Lambda export: handler: "auth-logout.handler"

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { timingSafeEqual } from 'crypto';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

function getHeader(event: APIGatewayProxyEventV2, name: string): string {
  const headers = event.headers ?? {};
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return (v ?? '').toString();
  }
  return '';
}

function parseCookiesFromHeader(cookieHeader: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;

  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function parseCookiesFromList(cookieList: string[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const entry of cookieList ?? []) {
    for (const part of (entry ?? '').split(';')) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const name = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      if (name) out[name] = value;
    }
  }
  return out;
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

function env(name: string, fallback?: string): string {
  const v = (process.env[name] ?? '').trim();
  if (v) return v;
  return (fallback ?? '').trim();
}

function requireEnv(name: string): string {
  const v = (process.env[name] ?? '').trim();
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

function buildCookie(
  name: string,
  value: string,
  attrs: {
    path: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Lax' | 'Strict' | 'None';
    maxAge?: number;
    domain?: string;
  },
): string {
  const parts: string[] = [];
  parts.push(`${name}=${value}`);
  if (attrs.domain) parts.push(`Domain=${attrs.domain}`);
  parts.push(`Path=${attrs.path}`);
  if (attrs.httpOnly) parts.push('HttpOnly');
  if (attrs.secure) parts.push('Secure');
  if (attrs.sameSite) parts.push(`SameSite=${attrs.sameSite}`);
  if (typeof attrs.maxAge === 'number') parts.push(`Max-Age=${attrs.maxAge}`);
  return parts.join('; ');
}

function safeAbsoluteUrl(raw: string, fallback: string): string {
  // For logout redirect we expect an absolute https URL (your template passes appBaseUrl + "/")
  // If misconfigured, fall back safely.
  const v = (raw ?? '').trim();
  if (!v) return fallback;
  const lower = v.toLowerCase();
  if (!lower.startsWith('https://')) return fallback;
  return v;
}

export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const deny = enforceOriginVerify(event);
  if (deny) return deny;

  const tableName = requireEnv('SESSIONS_TABLE_NAME');

  const cookieName = env('COOKIE_NAME', 'session') || 'session';
  const csrfCookieName = env('CSRF_COOKIE_NAME', '__Host-csrf') || '__Host-csrf';

  // Where user ends up AFTER Cognito logout completes
  const postLogoutRedirect = safeAbsoluteUrl(
    env('POST_LOGOUT_REDIRECT', ''),
    'https://example.invalid/',
  );

  // Cognito details (Hosted UI logout)
  const cognitoDomain = env('COGNITO_DOMAIN', ''); // auth.example.com
  const cognitoClientId = env('COGNITO_CLIENT_ID', '');

  // CloudFront cookie attrs (MUST match how you set them on login)
  const cfCookieDomain = env('CF_COOKIE_DOMAIN', ''); // empty => host-only
  const cfCookiePath = env('CF_COOKIE_PATH', '/') || '/';

  // If you scoped PKCE cookies to /auth (recommended), clear with the same path.
  const authCookiePath = env('AUTH_COOKIE_PATH', '/auth') || '/auth';

  // Cookie names (must match /auth/start)
  const stateCookieName = env('OAUTH_STATE_COOKIE_NAME', 'oauth_state') || 'oauth_state';
  const verifierCookieName = env('PKCE_VERIFIER_COOKIE_NAME', 'pkce_verifier') || 'pkce_verifier';
  const postLoginCookieName = env('POST_LOGIN_COOKIE_NAME', 'post_login') || 'post_login';

  // Collect cookies from both HTTP API v2 shapes
  const cookiesIn = {
    ...parseCookiesFromHeader(getHeader(event, 'cookie')),
    ...parseCookiesFromList(event.cookies),
  };

  const sessionId = cookiesIn[cookieName];

  // Delete server-side session (best effort)
  if (sessionId) {
    try {
      await ddb.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { session_id: sessionId },
        }),
      );
    } catch {
      // best effort: ignore
    }
  }

  const outCookies: string[] = [];

  // 1) Clear app session cookie (HttpOnly)
  outCookies.push(
    buildCookie(cookieName, '', {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 0,
    }),
  );

  // 2) Clear CSRF cookie (NOT HttpOnly)
  // Note: "__Host-" cookies must NOT have Domain and must be Path=/
  outCookies.push(
    buildCookie(csrfCookieName, '', {
      path: '/',
      httpOnly: false,
      secure: true,
      sameSite: 'Lax',
      maxAge: 0,
    }),
  );

  // 3) Clear PKCE temp cookies (match Path used by /auth/start)
  const pkceAttrs = {
    path: authCookiePath,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax' as const,
    maxAge: 0,
  };
  outCookies.push(buildCookie(stateCookieName, '', pkceAttrs));
  outCookies.push(buildCookie(verifierCookieName, '', pkceAttrs));
  outCookies.push(buildCookie(postLoginCookieName, '', pkceAttrs));

  // 4) Clear CloudFront signed cookies (match Domain/Path used when setting them)
  const cfAttrs = {
    domain: cfCookieDomain || undefined,
    path: cfCookiePath,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax' as const,
    maxAge: 0,
  };
  outCookies.push(buildCookie('CloudFront-Key-Pair-Id', '', cfAttrs));
  outCookies.push(buildCookie('CloudFront-Policy', '', cfAttrs));
  outCookies.push(buildCookie('CloudFront-Signature', '', cfAttrs));

  // 5) Redirect through Cognito logout to clear Hosted UI session cookies
  const fallbackRedirect = postLogoutRedirect !== 'https://example.invalid/' ? postLogoutRedirect : '/';

  let location = fallbackRedirect;
  if (cognitoDomain && cognitoClientId) {
    // logout_uri must be an absolute URL that Cognito allows; we don't try to be clever here.
    const logoutUri = postLogoutRedirect !== 'https://example.invalid/' ? postLogoutRedirect : fallbackRedirect;

    const logoutUrl =
      `https://${cognitoDomain}/logout` +
      `?client_id=${encodeURIComponent(cognitoClientId)}` +
      `&logout_uri=${encodeURIComponent(logoutUri)}`;

    location = logoutUrl;
  }

  return {
    statusCode: 302,
    headers: {
      location,
      'cache-control': 'no-store',
    },
    cookies: outCookies,
    body: '',
  };
}
