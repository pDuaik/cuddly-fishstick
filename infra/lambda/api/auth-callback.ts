import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import crypto from 'crypto';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const secrets = new SecretsManagerClient({});

function timingSafeEqualStr(a: string, b: string): boolean {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}

function requireEnv(name: string): string {
    const v = (process.env[name] ?? '').trim();
    if (!v) throw new Error(`Missing env: ${name}`);
    return v;
}

function getHeader(event: any, name: string): string {
    const headers = event?.headers ?? {};
    const wanted = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === wanted) return String(v ?? '');
    }
    return '';
}

function enforceOriginVerify(event: any): { ok: true } | { ok: false; statusCode: number; body: string } {
    const headerName = (process.env.ORIGIN_VERIFY_HEADER_NAME ?? '').trim();
    const expected = (process.env.ORIGIN_VERIFY_HEADER_VALUE ?? '').trim();

    // Template stance: REQUIRED at day 1 => fail closed if missing
    if (!headerName || !expected) {
        return { ok: false, statusCode: 500, body: 'Server misconfigured: origin verify header not set' };
    }

    const actual = getHeader(event, headerName);
    if (!actual) return { ok: false, statusCode: 403, body: 'Forbidden (missing origin verify header)' };

    if (!timingSafeEqualStr(actual, expected)) {
        return { ok: false, statusCode: 403, body: 'Forbidden (bad origin verify header)' };
    }


    return { ok: true };
}

function parseCookieKv(cookieStr: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const part of (cookieStr || '').split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k) out[k] = v;
    }
    return out;
}

function getCookie(event: any, name: string): string {
    // HTTP API v2 cookies come as:
    // - headers.cookie
    // - event.cookies: string[]
    const cookieHeader = getHeader(event, 'cookie');
    const cookies: Record<string, string> = { ...parseCookieKv(cookieHeader) };

    for (const c of (event?.cookies ?? []) as string[]) {
        Object.assign(cookies, parseCookieKv(c));
    }

    return cookies[name] ?? '';
}

function b64urlDecodeToBuffer(input: string): Buffer {
    // base64url -> base64
    const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (b64.length % 4)) % 4;
    const padded = b64 + '='.repeat(padLen);
    return Buffer.from(padded, 'base64');
}

function decodeJwtPayload(token: string): Record<string, any> {
    const parts = token.split('.');
    if (parts.length < 2) return {};
    try {
        const buf = b64urlDecodeToBuffer(parts[1]);
        return JSON.parse(buf.toString('utf8')) as Record<string, any>;
    } catch {
        return {};
    }
}

/**
 * CloudFront signed cookies use a URL-safe base64 variant:
 *   + -> - , = -> _ , / -> ~
 */
function cfB64(data: Buffer): string {
    return data
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/=/g, '_')
        .replace(/\//g, '~');
}

function buildPolicy(resource: string, expiresEpoch: number): Buffer {
    const policy = {
        Statement: [
            {
                Resource: resource,
                Condition: { DateLessThan: { 'AWS:EpochTime': expiresEpoch } },
            },
        ],
    };
    // match python separators=(",",":")
    return Buffer.from(JSON.stringify(policy), 'utf8');
}

async function loadPrivateKeyFromSecrets(secretArn: string): Promise<string> {
    const resp = await secrets.send(new GetSecretValueCommand({ SecretId: secretArn }));
    if (resp.SecretString && resp.SecretString.trim()) return resp.SecretString;
    if (resp.SecretBinary) return Buffer.from(resp.SecretBinary as any).toString('utf8');
    throw new Error('Secret value was empty');
}

function signPolicyRsaSha1(privateKeyPem: string, message: Buffer): Buffer {
    const signer = crypto.createSign('RSA-SHA1');
    signer.update(message);
    signer.end();
    return signer.sign(privateKeyPem);
}

function safePostLoginRedirect(raw: string, defaultPath: string, appHost: string): string {
    // Prevent open redirect:
    // - allow only relative "/..."
    // - OR allow absolute same-host, normalize to path
    let s = (raw ?? '').trim();
    if (!s) return defaultPath;

    try {
        s = decodeURIComponent(s);
    } catch {
        // ignore
    }

    if (s.startsWith('/')) {
        if (s.startsWith('//')) return defaultPath;
        // block schemes anywhere
        if (s.toLowerCase().includes('://')) return defaultPath;
        return s;
    }

    try {
        const u = new URL(s);
        if ((u.protocol === 'https:' || u.protocol === 'http:') && u.host.toLowerCase() === appHost.toLowerCase()) {
            return `${u.pathname || '/'}${u.search || ''}${u.hash || ''}`;
        }
    } catch {
        // ignore
    }

    return defaultPath;
}

function resp(
    statusCode: number,
    body: string,
    opts?: { headers?: Record<string, string>; cookies?: string[] },
) {
    return {
        statusCode,
        headers: {
            'content-type': 'text/plain',
            'cache-control': 'no-store',
            ...(opts?.headers ?? {}),
        },
        cookies: opts?.cookies ?? [],
        body,
    };
}

export async function handler(event: any) {
    // ------------------------------------------------------------
    // Enforce CloudFront-only (day 1)
    // ------------------------------------------------------------
    const ov = enforceOriginVerify(event);
    if (!ov.ok) return resp(ov.statusCode, ov.body);

    const qs = event?.queryStringParameters ?? {};
    const code = (qs.code ?? '').toString();
    const returnedState = (qs.state ?? '').toString();

    if (!code) {
        return {
            statusCode: 400,
            headers: { 'content-type': 'text/plain' },
            body: 'Missing ?code',
        };
    }

    // ------------------------------------------------------------
    // Env / config
    // ------------------------------------------------------------
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

    // cookie Path used by /auth/start
    const authCookiePath = (process.env.AUTH_COOKIE_PATH ?? '/auth').trim() || '/auth';

    // CloudFront signed cookie config
    const cfKeyPairId = (process.env.CF_KEY_PAIR_ID ?? '').trim();
    const cfPrivateKeySecretArn = (process.env.CF_PRIVATE_KEY_SECRET_ARN ?? '').trim();
    const cfCookieDomain = (process.env.CF_COOKIE_DOMAIN ?? '').trim();
    const cfCookiePath = (process.env.CF_COOKIE_PATH ?? '/').trim() || '/';
    const cfCookieTtlSeconds =
        Number.parseInt((process.env.CF_COOKIE_TTL_SECONDS ?? String(ttlSeconds)).trim(), 10) || ttlSeconds;

    const cfAppResource = (process.env.CF_APP_RESOURCE ?? '').trim();
    const cfCreatorResource = (process.env.CF_CREATOR_RESOURCE ?? '').trim();

    // derive app host from redirectUri
    const appHost = (() => {
        try {
            return new URL(redirectUri).host;
        } catch {
            return '';
        }
    })();

    // clear temp cookies using same Path as /auth/start
    const clearTempCommon = `Path=${authCookiePath}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

    // ------------------------------------------------------------
    // PKCE + state validation
    // ------------------------------------------------------------
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

    // ------------------------------------------------------------
    // Exchange code -> tokens (PKCE)
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

        if (!r.ok) {
            throw new Error(`HTTP ${r.status}: ${text}`);
        }
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

    // ------------------------------------------------------------
    // Create session in DynamoDB
    // ------------------------------------------------------------
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

    // 1) Session cookie (HttpOnly)
    cookiesOut.push(
        `${cookieName}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`,
    );

    // 2) CSRF cookie (NOT HttpOnly)
    const csrfToken = crypto.randomBytes(32).toString('base64url');
    cookiesOut.push(
        `${csrfCookieName}=${csrfToken}; Path=/; Secure; SameSite=Lax; Max-Age=${ttlSeconds}`,
    );
    void csrfHeaderName; // used by client + protected POST routes

    // 3) CloudFront signed cookies (REQUIRED for your template posture)
    // If you want truly "required", fail if either is missing.
    if (!cfKeyPairId || !cfPrivateKeySecretArn) {
        // still clear temp cookies
        cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
        cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
        cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);

        return resp(500, 'Server misconfigured: CloudFront signing not configured', { cookies: cookiesOut });
    }

    try {
        const privateKeyPem = await loadPrivateKeyFromSecrets(cfPrivateKeySecretArn);

        // resource selection
        // - if creator resource exists, sign wide "https://<domain>/*" by setting CF_APP_RESOURCE accordingly in env
        // - otherwise sign app resource only
        let resource = cfAppResource;
        if (cfCreatorResource) {
            // safest deterministic behavior: if creator is enabled, sign the widest intended resource
            // (your ApiStack sets CF_* resources deterministically)
            resource = cfAppResource.replace(/\/app\/\*$/, '/*');
        }

        const cfExpires = now + cfCookieTtlSeconds;
        const policyBytes = buildPolicy(resource, cfExpires);
        const signatureBytes = signPolicyRsaSha1(privateKeyPem, policyBytes);

        const cfPolicy = cfB64(policyBytes);
        const cfSignature = cfB64(signatureBytes);

        let common = `Path=${cfCookiePath}; HttpOnly; Secure; SameSite=Lax; Max-Age=${cfCookieTtlSeconds}`;
        if (cfCookieDomain) common = `Domain=${cfCookieDomain}; ${common}`;

        cookiesOut.push(`CloudFront-Key-Pair-Id=${cfKeyPairId}; ${common}`);
        cookiesOut.push(`CloudFront-Policy=${cfPolicy}; ${common}`);
        cookiesOut.push(`CloudFront-Signature=${cfSignature}; ${common}`);
    } catch (e: any) {
        // clear temp cookies too
        cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
        cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
        cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);

        return resp(502, `Failed to mint CloudFront signed cookies: ${e?.message ?? String(e)}`, {
            cookies: cookiesOut,
        });
    }

    // 4) Clear temp login cookies
    cookiesOut.push(`${stateCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${pkceCookieName}=; ${clearTempCommon}`);
    cookiesOut.push(`${postLoginCookieName}=; ${clearTempCommon}`);

    return {
        statusCode: 302,
        headers: {
            location: postLoginRedirect,
            'cache-control': 'no-store',
        },
        cookies: cookiesOut,
        body: '',
    };
}
