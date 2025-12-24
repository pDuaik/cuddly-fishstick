// lambda/api/auth-callback.ts
// CommonJS-compatible Lambda export: handler: "auth_callback.handler"

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

import {
  enforceOriginVerify,
  requireEnv,
  env,
  getCookie,
  decodeJwtPayload,
  safePostLoginRedirect,
  resp,
  buildCookie,
  loadPrivateKeyFromSecrets,
  buildPolicy,
  signPolicyRsaSha1,
  cfB64,
} from './helpers';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

export async function handler(event: any) {
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return resp(ov.statusCode, ov.message);

  const qs = event?.queryStringParameters ?? {};
  const code = (qs.code ?? '').toString();
  const returnedState = (qs.state ?? '').toString();
  if (!code) return resp(400, 'Missing ?code');

  // Tables
  const sessionsTableName = requireEnv('SESSIONS_TABLE_NAME');
  const userProfileTableName = requireEnv('USER_PROFILE_TABLE_NAME');

  const cookieName = env('COOKIE_NAME', 'session') || 'session';

  const csrfCookieName = env('CSRF_COOKIE_NAME', '__Host-csrf') || '__Host-csrf';
  const csrfHeaderName = env('CSRF_HEADER_NAME', 'X-CSRF-Token') || 'X-CSRF-Token';

  // Opaque user key cookie (stable per user, NOT Cognito sub)
  const opaqueCookieName = env('OPAQUE_ID_COOKIE_NAME', '__Host-uk') || '__Host-uk';

  const cognitoDomain = requireEnv('COGNITO_DOMAIN');
  const clientId = requireEnv('COGNITO_CLIENT_ID');
  const redirectUri = requireEnv('REDIRECT_URI');

  const ttlSeconds = Number.parseInt(env('SESSION_TTL_SECONDS', '3600'), 10) || 3600;
  const defaultPostLogin = env('POST_LOGIN_REDIRECT', '/app/page1.html') || '/app/page1.html';

  const stateCookieName = env('OAUTH_STATE_COOKIE_NAME', 'oauth_state') || 'oauth_state';
  const pkceCookieName = env('PKCE_VERIFIER_COOKIE_NAME', 'pkce_verifier') || 'pkce_verifier';
  const postLoginCookieName = env('POST_LOGIN_COOKIE_NAME', 'post_login') || 'post_login';

  const authCookiePath = env('AUTH_COOKIE_PATH', '/auth') || '/auth';

  // CloudFront signed cookies (Key Groups)
  const cfPublicKeyId = env('CF_PUBLIC_KEY_ID', '');
  const cfPrivateKeySecretArn = env('CF_PRIVATE_KEY_SECRET_ARN', '');
  const cfCookieDomain = env('CF_COOKIE_DOMAIN', '');
  const cfCookiePath = env('CF_COOKIE_PATH', '/') || '/';
  const cfCookieTtlSeconds = Number.parseInt(env('CF_COOKIE_TTL_SECONDS', String(ttlSeconds)), 10) || ttlSeconds;

  // REQUIRED: sign resources
  // e.g. CF_APP_RESOURCE=https://example.com/*
  const cfAppResource = requireEnv('CF_APP_RESOURCE');

  const appHost = (() => {
    try {
      return new URL(redirectUri).host;
    } catch {
      return '';
    }
  })();

  const clearTempAttrs = {
    path: authCookiePath,
    httpOnly: true,
    secure: true,
    sameSite: 'Lax' as const,
    maxAge: 0,
  };

  const clearTempCookies = (): string[] => [
    buildCookie(stateCookieName, '', clearTempAttrs),
    buildCookie(pkceCookieName, '', clearTempAttrs),
    buildCookie(postLoginCookieName, '', clearTempAttrs),
  ];

  const expectedState = getCookie(event, stateCookieName);
  const codeVerifier = getCookie(event, pkceCookieName);

  if (!expectedState || !codeVerifier) {
    return resp(400, 'Missing login cookies (state/pkce). Use /auth/start to begin login.', {
      cookies: clearTempCookies(),
    });
  }

  if (returnedState !== expectedState) {
    return resp(400, 'State mismatch', { cookies: clearTempCookies() });
  }

  const rawPostLogin = getCookie(event, postLoginCookieName) || '';
  const postLoginRedirect = safePostLoginRedirect(rawPostLogin, defaultPostLogin, appHost || '');

  // ------------------------------------------------------------
  // Exchange code for tokens
  // ------------------------------------------------------------
  const tokenUrl = `https://${cognitoDomain}/oauth2/token`;
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });

  let payload: any;
  try {
    const r = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });

    const text = await r.text();
    payload = JSON.parse(text);

    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text}`);
  } catch (e: any) {
    return resp(502, `Token exchange failed: ${e?.message ?? String(e)}`, {
      cookies: clearTempCookies(),
    });
  }

  const idToken = payload?.id_token as string | undefined;
  const accessToken = payload?.access_token as string | undefined;
  const refreshToken = (payload?.refresh_token as string | undefined) ?? '';

  if (!idToken || !accessToken) {
    return resp(502, `Token response missing tokens: ${JSON.stringify(payload)}`, {
      cookies: clearTempCookies(),
    });
  }

  const claims = decodeJwtPayload(idToken);
  const userSub = (claims?.sub as string) || 'unknown';

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + ttlSeconds;
  const sessionId = crypto.randomUUID().replace(/-/g, '');

  // ------------------------------------------------------------
  // Ensure opaque_id exists for this user (stable)
  // PK: user_sub, attribute: opaque_id
  // ------------------------------------------------------------
  let opaqueId = '';
  try {
    const got = await ddb.send(
      new GetCommand({
        TableName: userProfileTableName,
        Key: { user_sub: userSub },
        ProjectionExpression: 'opaque_id',
      }),
    );

    opaqueId = (got.Item?.opaque_id as string) || '';
    if (!opaqueId) {
      // 256-bit random -> base64url (~43 chars). Stable per user.
      opaqueId = crypto.randomBytes(32).toString('base64url');

      await ddb.send(
        new PutCommand({
          TableName: userProfileTableName,
          Item: {
            user_sub: userSub,
            opaque_id: opaqueId,
            created_at: now,
            updated_at: now,
          },
          // Optional hardening (recommended): do not overwrite if it already exists
          // Remove if you don't want conditional behavior yet.
          ConditionExpression: 'attribute_not_exists(user_sub)',
        }),
      );
    }
  } catch (e: any) {
    return resp(502, `Failed to resolve user profile: ${e?.message ?? String(e)}`, {
      cookies: clearTempCookies(),
    });
  }

  // ------------------------------------------------------------
  // Create session (TTL)
  // ------------------------------------------------------------
  await ddb.send(
    new PutCommand({
      TableName: sessionsTableName,
      Item: {
        session_id: sessionId,
        user_sub: userSub,
        created_at: now,
        expires_at: expiresAt,
        access_token: accessToken,
        refresh_token: refreshToken,
        id_token: idToken,
      },
    }),
  );

  const cookiesOut: string[] = [];

  // 1) App session cookie (HttpOnly)
  cookiesOut.push(
    buildCookie(cookieName, sessionId, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: ttlSeconds,
    }),
  );

  // 1b) Opaque user key cookie (HttpOnly, stable per user)
  cookiesOut.push(
    buildCookie(opaqueCookieName, opaqueId, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: ttlSeconds,
    }),
  );

  // 2) CSRF cookie (NOT HttpOnly)
  const csrfToken = crypto.randomBytes(32).toString('base64url');
  cookiesOut.push(
    buildCookie(csrfCookieName, csrfToken, {
      path: '/',
      httpOnly: false,
      secure: true,
      sameSite: 'Lax',
      maxAge: ttlSeconds,
    }),
  );
  void csrfHeaderName; // reserved for future CSRF header checks on write endpoints

  // 3) CloudFront signed cookies (strict: must be configured)
  if (!cfPublicKeyId || !cfPrivateKeySecretArn) {
    cookiesOut.push(...clearTempCookies());
    return resp(500, 'Server misconfigured: CloudFront Key Group signing not configured', { cookies: cookiesOut });
  }

  try {
    const privateKeyPem = await loadPrivateKeyFromSecrets(cfPrivateKeySecretArn);

    const cfExpires = now + cfCookieTtlSeconds;

    // ✅ Multi-resource policy: /app/* AND /u/*
    const policyBytes = buildPolicy(cfAppResource, cfExpires);

    const signatureBytes = signPolicyRsaSha1(privateKeyPem, policyBytes);

    const cfPolicy = cfB64(policyBytes);
    const cfSignature = cfB64(signatureBytes);

    const cfAttrs = {
      domain: cfCookieDomain || undefined,
      path: cfCookiePath,
      httpOnly: true,
      secure: true,
      sameSite: 'Lax' as const,
      maxAge: cfCookieTtlSeconds,
    };

    cookiesOut.push(buildCookie('CloudFront-Key-Pair-Id', cfPublicKeyId, cfAttrs));
    cookiesOut.push(buildCookie('CloudFront-Policy', cfPolicy, cfAttrs));
    cookiesOut.push(buildCookie('CloudFront-Signature', cfSignature, cfAttrs));
  } catch (e: any) {
    console.log('[cf-sign] failed to mint signed cookies', {
      name: e?.name,
      message: e?.message,
      code: e?.code,
      stack: e?.stack?.split('\n').slice(0, 3).join('\n'),
      httpStatus: e?.$metadata?.httpStatusCode,
      requestId: e?.$metadata?.requestId,
    });

    cookiesOut.push(...clearTempCookies());
    return resp(502, `Failed to mint CloudFront signed cookies: ${e?.message ?? String(e)}`, { cookies: cookiesOut });
  }

  // 4) Clear temp auth cookies
  cookiesOut.push(...clearTempCookies());

  return {
    statusCode: 302,
    headers: { location: postLoginRedirect, 'cache-control': 'no-store' },
    cookies: cookiesOut,
    body: '',
  };
}
