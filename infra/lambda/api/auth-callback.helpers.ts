import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import crypto from 'crypto';

const secrets = new SecretsManagerClient({});

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export function requireEnv(name: string): string {
  const v = (process.env[name] ?? '').trim();
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

export function getHeader(event: any, name: string): string {
  const headers = event?.headers ?? {};
  const wanted = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === wanted) return String(v ?? '');
  }
  return '';
}

export function enforceOriginVerify(
  event: any,
): { ok: true } | { ok: false; statusCode: number; body: string } {
  const headerName = (process.env.ORIGIN_VERIFY_HEADER_NAME ?? '').trim();
  const expected = (process.env.ORIGIN_VERIFY_HEADER_VALUE ?? '').trim();

  // Required => fail closed
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

export function getCookie(event: any, name: string): string {
  const cookieHeader = getHeader(event, 'cookie');
  const cookies: Record<string, string> = { ...parseCookieKv(cookieHeader) };

  for (const c of (event?.cookies ?? []) as string[]) {
    Object.assign(cookies, parseCookieKv(c));
  }

  return cookies[name] ?? '';
}

function b64urlDecodeToBuffer(input: string): Buffer {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + '='.repeat(padLen);
  return Buffer.from(padded, 'base64');
}

export function decodeJwtPayload(token: string): Record<string, any> {
  const parts = token.split('.');
  if (parts.length < 2) return {};
  try {
    const buf = b64urlDecodeToBuffer(parts[1]);
    return JSON.parse(buf.toString('utf8')) as Record<string, any>;
  } catch {
    return {};
  }
}

export function cfB64(data: Buffer): string {
  return data.toString('base64').replace(/\+/g, '-').replace(/=/g, '_').replace(/\//g, '~');
}

export function buildPolicy(resource: string, expiresEpoch: number): Buffer {
  const policy = {
    Statement: [
      {
        Resource: resource,
        Condition: { DateLessThan: { 'AWS:EpochTime': expiresEpoch } },
      },
    ],
  };
  return Buffer.from(JSON.stringify(policy), 'utf8');
}

export async function loadPrivateKeyFromSecrets(secretArn: string): Promise<string> {
  const resp = await secrets.send(new GetSecretValueCommand({ SecretId: secretArn }));
  if (resp.SecretString && resp.SecretString.trim()) return resp.SecretString;
  if (resp.SecretBinary) return Buffer.from(resp.SecretBinary as any).toString('utf8');
  throw new Error('Secret value was empty');
}

export function signPolicyRsaSha1(privateKeyPem: string, message: Buffer): Buffer {
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(message);
  signer.end();
  return signer.sign(privateKeyPem);
}

export function safePostLoginRedirect(raw: string, defaultPath: string, appHost: string): string {
  let s = (raw ?? '').trim();
  if (!s) return defaultPath;

  try {
    s = decodeURIComponent(s);
  } catch {
    // ignore
  }

  if (s.startsWith('/')) {
    if (s.startsWith('//')) return defaultPath;
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

export function resp(
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
