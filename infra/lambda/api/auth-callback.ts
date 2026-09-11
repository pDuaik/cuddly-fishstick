// lambda/api/auth-callback.ts
// CommonJS-compatible Lambda export: handler: "auth_callback.handler"

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import * as crypto from 'crypto';

import {
  enforceOriginVerify,
  requireEnv,
  env,
  getCookie,
  validateCognitoIdToken,
  safePostLoginRedirect,
  resp,
  buildCookie,
  loadPrivateKeyFromSsm,
  buildPolicy,
  signPolicyRsaSha1,
  signUserCookie,
  cfB64,
} from './helpers';

import {
  PLATFORM_CSRF_COOKIE_NAME,
} from './platform-env';


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

  const csrfCookieName = env(PLATFORM_CSRF_COOKIE_NAME, '__Host-csrf') || '__Host-csrf';

  // Opaque user key cookie (stable per user, NOT Cognito sub)
  const opaqueCookieName = env('OPAQUE_ID_COOKIE_NAME', '__Host-uk') || '__Host-uk';

  const cognitoDomain = requireEnv('COGNITO_DOMAIN');
  const clientId = requireEnv('COGNITO_CLIENT_ID');
  const cognitoIssuer = requireEnv('COGNITO_ISSUER');
  const redirectUri = requireEnv('REDIRECT_URI');

  const ttlSeconds = Number.parseInt(env('SESSION_TTL_SECONDS', '3600'), 10) || 3600;
  const defaultPostLogin = env('POST_LOGIN_REDIRECT', '/app/page1.html') || '/app/page1.html';

  const stateCookieName = env('OAUTH_STATE_COOKIE_NAME', 'oauth_state') || 'oauth_state';
  const pkceCookieName = env('PKCE_VERIFIER_COOKIE_NAME', 'pkce_verifier') || 'pkce_verifier';
  const postLoginCookieName = env('POST_LOGIN_COOKIE_NAME', 'post_login') || 'post_login';

  const authCookiePath = env('AUTH_COOKIE_PATH', '/auth') || '/auth';

  // CloudFront signed cookies (Key Groups)
  const cfPublicKeyId = env('CF_PUBLIC_KEY_ID', '');
  const cfPrivateKeyParameterArn = env('CF_PRIVATE_KEY_PARAMETER_ARN', '');
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

  let rawPostLogin = '';
  try {
    rawPostLogin = decodeURIComponent(getCookie(event, postLoginCookieName));
  } catch {
    // A malformed cookie falls back to the configured same-origin landing page.
  }
  const postLoginRedirect = safePostLoginRedirect(rawPostLogin, defaultPostLogin, appHost || '');

  if (!cfPublicKeyId || !cfPrivateKeyParameterArn) {
    return resp(500, 'Server misconfigured: CloudFront Key Group signing not configured', {
      cookies: clearTempCookies(),
    });
  }

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
      // Claims below are trusted only because this response comes directly
      // from the configured Cognito HTTPS endpoint, without redirects.
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });

    const text = await r.text();
    payload = JSON.parse(text);

    if (!r.ok) {
      console.log('[auth-callback] token endpoint returned non-2xx', {
        status: r.status,
        bodyLen: text.length,
      });
      throw new Error(`HTTP ${r.status}`);
    }
  } catch (e: any) {
    console.log('[auth-callback] token exchange failed', { name: e?.name });
    return resp(502, 'Token exchange failed', {
      cookies: clearTempCookies(),
    });
  }

  const idToken = typeof payload?.id_token === 'string' ? payload.id_token : '';
  const accessToken = typeof payload?.access_token === 'string' ? payload.access_token : '';
  const refreshToken = typeof payload?.refresh_token === 'string' ? payload.refresh_token : '';

  if (!idToken || !accessToken) {
    // Log only non-sensitive diagnostics (never token values)
    console.log('[auth-callback] token response missing required tokens', {
      hasIdToken: !!idToken,
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      keys: payload ? Object.keys(payload) : [],
    });

    // Do NOT echo payload to the browser
    return resp(502, 'Token exchange failed (missing required tokens)', {
      cookies: clearTempCookies(),
    });
  }

  const now = Math.floor(Date.now() / 1000);
  let userSub: string;
  try {
    userSub = validateCognitoIdToken(idToken, cognitoIssuer, clientId, now).sub;
  } catch {
    console.log('[auth-callback] token response contained invalid ID token claims');
    return resp(502, 'Token exchange failed (invalid ID token)', { cookies: clearTempCookies() });
  }

  const expiresAt = now + ttlSeconds;
  const sessionId = crypto.randomUUID().replace(/-/g, '');

  // ------------------------------------------------------------
  // Ensure opaque_id exists for this user (stable)
  // PK: user_sub, attribute: opaque_id
  // Atomic: no race conditions under concurrent logins
  // ------------------------------------------------------------
  let opaqueId = '';
  try {
    const candidateOpaque = crypto.randomBytes(32).toString('base64url');

    const upd = await ddb.send(
      new UpdateCommand({
        TableName: userProfileTableName,
        Key: { user_sub: userSub },
        UpdateExpression:
          'SET opaque_id = if_not_exists(opaque_id, :oid), created_at = if_not_exists(created_at, :now), updated_at = :now',
        ExpressionAttributeValues: {
          ':oid': candidateOpaque,
          ':now': now,
        },
        ReturnValues: 'ALL_NEW',
      }),
    );

    opaqueId = String(upd.Attributes?.opaque_id ?? '');
    if (!opaqueId) {
      throw new Error('User profile missing opaque_id after upsert');
    }
  } catch (e: any) {
    console.log('[auth-callback] failed to resolve user profile', { name: e?.name });
    return resp(502, 'Failed to resolve user profile', {
      cookies: clearTempCookies(),
    });
  }

  // Prepare credentials before persisting a usable session. No credentials
  // are returned until both signing and the session write have succeeded.
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

  // 3) CloudFront signed cookies
  try {
    const privateKeyPem = await loadPrivateKeyFromSsm(cfPrivateKeyParameterArn);

    // Bind the private S3 prefix to this authenticated identity. The edge
    // verifies this MAC before trusting the cookie's user selector.
    const userCookieTtl = Math.min(ttlSeconds, cfCookieTtlSeconds);
    const authenticatedUserCookie = await signUserCookie(opaqueId, now + userCookieTtl, appHost);
    cookiesOut.push(buildCookie(opaqueCookieName, authenticatedUserCookie, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: userCookieTtl,
    }));

    const cfExpires = now + cfCookieTtlSeconds;

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

    return resp(502, 'Failed to mint CloudFront signed cookies', { cookies: clearTempCookies() });
  }

  try {
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
        ConditionExpression: 'attribute_not_exists(session_id)',
      }),
    );
  } catch (e: any) {
    console.log('[auth-callback] failed to create session', { name: e?.name });
    return resp(503, 'Failed to create session; please start login again', { cookies: clearTempCookies() });
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
