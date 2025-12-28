// lambda/api/auth-logout.ts
// CommonJS-compatible Lambda export: handler: "auth-logout.handler"

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, DeleteCommand } from '@aws-sdk/lib-dynamodb';

import {
  enforceOriginVerify,
  requireEnv,
  env,
  getCookie,
  buildCookie,
  safeAbsoluteHttpsUrl,
  json,
} from './helpers';

import {
  PLATFORM_CSRF_COOKIE_NAME,
} from './platform-env';


const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { message: ov.message });

  const tableName = requireEnv('SESSIONS_TABLE_NAME');

  const cookieName = env('COOKIE_NAME', 'session') || 'session';
  const csrfCookieName = env(PLATFORM_CSRF_COOKIE_NAME, '__Host-csrf') || '__Host-csrf';

  // Where user ends up AFTER Cognito logout completes
  const postLogoutRedirect = safeAbsoluteHttpsUrl(env('POST_LOGOUT_REDIRECT', ''), 'https://example.invalid/');

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

  // Read session id from cookies (header + cookie list supported)
  const sessionId = getCookie(event, cookieName);

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

    location =
      `https://${cognitoDomain}/logout` +
      `?client_id=${encodeURIComponent(cognitoClientId)}` +
      `&logout_uri=${encodeURIComponent(logoutUri)}`;
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
