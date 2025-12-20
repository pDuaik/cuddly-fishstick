// helpers.ts
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import crypto from 'crypto';

const secrets = new SecretsManagerClient({});

/** Generic event shape this helper supports (HTTP API v2 + authorizer-like). */
export type HeaderCookieEvent = {
  headers?: Record<string, string | undefined> | null;
  cookies?: string[] | null;
  queryStringParameters?: Record<string, string | undefined> | null;
};

export type OriginVerifyResult = { ok: true } | { ok: false; statusCode: number; message: string };

export type RespOpts = { headers?: Record<string, string>; cookies?: string[] };

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export function env(name: string, fallback = ''): string {
  const v = (process.env[name] ?? '').trim();
  return v || (fallback ?? '').trim();
}

export function requireEnv(name: string): string {
  const v = (process.env[name] ?? '').trim();
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

export function getHeader(event: HeaderCookieEvent | any, name: string): string {
  const headers = (event?.headers ?? {}) as Record<string, string | undefined>;
  const wanted = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === wanted) return String(v ?? '');
  }
  return '';
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

export function getCookie(event: HeaderCookieEvent | any, name: string): string {
  const cookieHeader = getHeader(event, 'cookie');
  const cookies: Record<string, string> = { ...parseCookieKv(cookieHeader) };

  for (const c of (event?.cookies ?? []) as string[]) {
    Object.assign(cookies, parseCookieKv(c));
  }

  return cookies[name] ?? '';
}

export function buildCookie(
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

const ssm = new SSMClient({});

// cache across warm invocations
let cached: { arnOrName: string; expected: string } | null = null;

function ssmParamNameFromArnOrName(arnOrName: string): string {
  const s = (arnOrName ?? '').trim();
  if (!s) return '';
  if (!s.startsWith('arn:')) return s;

  const marker = ':parameter/';
  const idx = s.indexOf(marker);
  if (idx === -1) return s; // let AWS error if malformed
  return s.slice(idx + marker.length);
}

async function getOriginVerifyExpected(): Promise<string> {
  const arnOrName = env('ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN', '');
  if (!arnOrName) return '';

  if (cached && cached.arnOrName === arnOrName) return cached.expected;

  const Name = ssmParamNameFromArnOrName(arnOrName);

  const out = await ssm.send(
    new GetParameterCommand({
      Name,
      WithDecryption: true,
    }),
  );

  const expected = (out.Parameter?.Value ?? '').trim();
  cached = { arnOrName, expected };
  return expected;
}

export async function enforceOriginVerify(event: HeaderCookieEvent | any): Promise<OriginVerifyResult> {
  const headerName = env('ORIGIN_VERIFY_HEADER_NAME', '');
  if (!headerName) {
    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify header not set' };
  }

  const actual = getHeader(event, headerName);
  if (!actual) return { ok: false, statusCode: 403, message: 'Forbidden (missing origin verify header)' };

  let expected = '';
  try {
    expected = await getOriginVerifyExpected();
  } catch {
    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify secret not readable' };
  }

  if (!expected) {
    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify secret empty' };
  }

  if (!timingSafeEqualStr(actual, expected)) {
    return { ok: false, statusCode: 403, message: 'Forbidden (bad origin verify header)' };
  }

  return { ok: true };
}

export async function originVerifyOk(event: HeaderCookieEvent | any): Promise<boolean> {
  return (await enforceOriginVerify(event)).ok;
}

export async function originVerifyOrDenyJson(event: HeaderCookieEvent | any): Promise<null | {
  statusCode: number;
  headers: Record<string, string>;
  cookies: string[];
  body: string;
}> {
  const ov = await enforceOriginVerify(event);
  if (ov.ok) return null;
  return json(ov.statusCode, { message: ov.message });
}


export function resp(statusCode: number, body: string, opts?: RespOpts) {
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

export function json(statusCode: number, obj: unknown, opts?: RespOpts) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(opts?.headers ?? {}),
    },
    cookies: opts?.cookies ?? [],
    body: JSON.stringify(obj),
  };
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

export function safeAbsoluteHttpsUrl(raw: string, fallback: string): string {
  const v = (raw ?? '').trim();
  if (!v) return fallback;
  if (!v.toLowerCase().startsWith('https://')) return fallback;
  return v;
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
