import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

import {
  enforceOriginVerify,
  requireEnv,
  getCookie,
  decodeJwtPayload,
  safePostLoginRedirect,
  resp,
  loadPrivateKeyFromSecrets,
  buildPolicy,
  signPolicyRsaSha1,
  cfB64,
} from './auth-callback.helpers';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

export async function handler(event: any) {
  const ov = enforceOriginVerify(event);
  if (!ov.ok) return resp(ov.statusCode, ov.body);

  const qs = event?.queryStringParameters ?? {};
  const code = (qs.code ?? '').toString();
  const returnedState = (qs.state ?? '').toString();
  if (!code) return resp(400, 'Missing ?code');

  const tableName = requireEnv('SESSIONS_TABLE_NAME');
  const cookieName = (process.env.COOKIE_NAME ?? 'session').trim() || 'session';

  const csrfCookieName = (process.env.CSRF_COOKIE_NAME ?? '__Host-csrf').trim() || '__Host-csrf';
  const csrfHeaderName = (process.env.CSRF_HEADER_NAME ?? 'X-CSRF-Token').trim() || 'X-CSRF-Token';

  const cognitoDomain = requireEnv('COGNITO_DOMAIN');
  const clientId = requireEnv('COGNITO_CLIENT_ID');
  const redirectUri = requireEnv('REDIRECT_URI');

  const ttlSeconds = Number.parseInt((process.env.SESSION_TTL_SECONDS ?? '3600').trim(), 10) || 3600;
  const defaultPostLogin = (process.env.POST_LOGIN_REDIRECT ?? '/app/page1.html').trim() || '/app/page1.html';

  const stateCookieName = (process.env.OAUTH_STATE_COOKIE_NAME ?? 'oauth_state').trim() || 'oauth_state';
  const pkceCookieName = (process.env.PKCE_VERIFIER_COOKIE_NAME ?? 'pkce_verifier').trim() || 'pkce_verifier';
  const postLoginCookieName = (process.env.POST_LOGIN_COOKIE_NAME ?? 'post_login').trim() || 'post_login';

  const authCookiePath = (process.env.AUTH_COOKIE_PATH ?? '/auth').trim() || '/auth';

  /**
   * ✅ NEW SYSTEM (Key Groups)
   * CF_PUBLIC_KEY_ID is the CloudFront Public Key ID (from cloudfront.PublicKey.publicKeyId).
   * It is placed into the cookie field "CloudFront-Key-Pair-Id".
   */
  const cfPublicKeyId = (process.env.CF_PUBLIC_KEY_ID ?? '').trim();
  const cfPrivateKeySecretArn = (process.env.CF_PRIVATE_KEY_SECRET_ARN ?? '').trim();
  const cfCookieDomain = (process.env.CF_COOKIE_DOMAIN ?? '').trim();
  const cfCookiePath = (process.env.CF_COOKIE_PATH ?? '/').trim() || '/';
  const cfCookieTtlSeconds =
    Number.parseInt((process.env.CF_COOKIE_TTL_SECONDS ?? String(ttlSeconds)).trim(), 10) || ttlSeconds;

  // ✅ required: we only sign for /app/*
  const cfAppResource = requireEnv('CF_APP_RESOURCE');

  const appHost = (() => {
    try {
      return new URL(redirectUri).host;
    } catch {
      return '';
    }
  })();

  const clearTempCommon = `Path=${authCookiePath}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

  const expectedState = getCookie(event, stateCookieName);
  const codeVerifier = getCookie(event, pkceCookieName);

  if (!expectedState || !codeVerifier) {
    return resp(400, 'Missing login cookies (state/pkce). Use /auth/start to begin login.', {
      cookies: [
        `${stateCookieName}=; ${clearTempCommon}`,
        `${pkceCookieName}=; ${clearTempCommon}`,
        `${postLoginCookieName}=; ${clearTempCommon}`,
      ],
    });
  }

  if (returnedState !== expectedState) {
    return resp(400, 'State mismatch', {
      cookies: [
        `${stateCookieName}=; ${clearTempCommon}`,
        `${pkceCookieName}=; ${clearTempCommon}`,
        `${postLoginCookieName}=; ${clearTempCommon}`,
      ],
    });
  }

  const rawPostLogin = getCookie(event, postLoginCookieName) || '';
  const postLoginRedirect = safePostLoginRedirect(rawPostLogin, defaultPostLogin, appHost || '');

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
      cookies: [
        `${stateCookieName}=; ${clearTempCommon}`,
        `${pkceCookieName}=; ${clearTempCommon}`,
        `${postLoginCookieName}=; ${clearTempCommon}`,
      ],
    });
  }

  const idToken = payload?.id_token as string | undefined;
  const accessToken = payload?.access_token as string | undefined;
  const refreshToken = (payload?.refresh_token as string | undefined) ?? '';

  if (!idToken || !accessToken) {
    return resp(502, `Token response missing tokens: ${JSON.stringify(payload)}`, {
      cookies: [
        `${stateCookieName}=; ${clearTempCommon}`,
        `${pkceCookieName}=; ${clearTempCommon}`,
        `${postLoginCookieName}=; ${clearTempCommon}`,
      ],
    });
  }

  const claims = decodeJwtPayload(idToken);
  const userSub = (claims?.sub as string) || 'unknown';

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + ttlSeconds;
  const sessionId = crypto.randomUUID().replace(/-/g, '');

  await ddb.send(
    new PutCommand({
      TableName: tableName,
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

  cookiesOut.push(`${cookieName}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`);

  const csrfToken = crypto.randomBytes(32).toString('base64url');
  cookiesOut.push(`${csrfCookieName}=${csrfToken}; Path=/; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`);
  void csrfHeaderName;

  // ✅ strict: must be configured, no fallback behavior
  if (!cfPublicKeyId || !cfPrivateKeySecretArn) {
    cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);
    return resp(500, 'Server misconfigured: CloudFront Key Group signing not configured', { cookies: cookiesOut });
  }

  try {
    const privateKeyPem = await loadPrivateKeyFromSecrets(cfPrivateKeySecretArn);

    const cfExpires = now + cfCookieTtlSeconds;
    const policyBytes = buildPolicy(cfAppResource, cfExpires);
    const signatureBytes = signPolicyRsaSha1(privateKeyPem, policyBytes);

    const cfPolicy = cfB64(policyBytes);
    const cfSignature = cfB64(signatureBytes);

    let common = `Path=${cfCookiePath}; HttpOnly; Secure; SameSite=Lax; Max-Age=${cfCookieTtlSeconds}`;
    if (cfCookieDomain) common = `Domain=${cfCookieDomain}; ${common}`;

    // Cookie name stays CloudFront-Key-Pair-Id, but the value is the Public Key ID (Key Groups).
    cookiesOut.push(`CloudFront-Key-Pair-Id=${cfPublicKeyId}; ${common}`);
    cookiesOut.push(`CloudFront-Policy=${cfPolicy}; ${common}`);
    cookiesOut.push(`CloudFront-Signature=${cfSignature}; ${common}`);
  } catch (e: any) {
    cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);
    return resp(502, `Failed to mint CloudFront signed cookies: ${e?.message ?? String(e)}`, { cookies: cookiesOut });
  }

  cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
  cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
  cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);

  return {
    statusCode: 302,
    headers: { location: postLoginRedirect, 'cache-control': 'no-store' },
    cookies: cookiesOut,
    body: '',
  };
}
