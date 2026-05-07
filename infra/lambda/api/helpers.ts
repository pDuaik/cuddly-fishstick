// helpers.ts
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import crypto from 'crypto';
import {
  PLATFORM_ORIGIN_VERIFY_HEADER_NAME,
  PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN,
} from './platform-env';

const DEBUG = (process.env.PLATFORM_DEBUG_LOGS ?? '').toLowerCase() === 'true';

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

  // If user passed a plain name, normalize it
  if (!s.startsWith('arn:')) {
    return s.startsWith('/') ? s : `/${s}`;
  }

  const marker = ':parameter/';
  const idx = s.indexOf(marker);
  if (idx === -1) return s; // let AWS error if malformed

  const name = s.slice(idx + marker.length); // might be "shared/parameter-store" or "/shared/parameter-store"
  return name.startsWith('/') ? name : `/${name}`;
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
      'content-type': 'text/plain; charset=utf-8',
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
      'content-type': 'application/json; charset=utf-8',
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
        Condition: {
          DateLessThan: { 'AWS:EpochTime': expiresEpoch },
        },
      },
    ],
  };
  return Buffer.from(JSON.stringify(policy));
}

export function env(name: string, fallback = ''): string {
  const v = (process.env[name] ?? '').trim();

  // Only log when explicitly debugging
  if (DEBUG) {
    console.log(`[env] ${name}: present=${!!v} len=${v.length} fallback=${fallback ? 'yes' : 'no'}`);
  }

  return v || (fallback ?? '').trim();
}


export function requireEnv(name: string): string {
  const v = (process.env[name] ?? '').trim();

  if (!v) {
    // Keep this (it’s useful and only happens on misconfig)
    console.log(`[requireEnv] missing ${name}`);
    throw new Error(`Missing env: ${name}`);
  }

  // Only log when explicitly debugging
  if (DEBUG) console.log(`[requireEnv] ${name}: present=true len=${v.length}`);

  return v;
}


async function getOriginVerifyExpected(): Promise<string> {
  const arnOrName = env(PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN, '');
  if (!arnOrName) {
    if (DEBUG)
      console.log('[origin-verify] SSM param not configured (PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN empty)');
    return '';
  }

  if (cached && cached.arnOrName === arnOrName) {
    if (DEBUG) {
      console.log('[origin-verify] using cached expected value', {
        arnOrName,
        expectedLen: cached.expected.length,
      });
    }
    return cached.expected;
  }

  const Name = ssmParamNameFromArnOrName(arnOrName);
  if (DEBUG)
    console.log('[origin-verify] fetching expected from SSM', {
      arnOrName,
      resolvedName: Name,
    });

  const out = await ssm.send(
    new GetParameterCommand({
      Name,
      WithDecryption: true,
    }),
  );

  const expected = (out.Parameter?.Value ?? '').trim();
  if (DEBUG)
    console.log('[origin-verify] SSM response', {
      resolvedName: Name,
      hasParameter: !!out.Parameter,
      hasValue: !!out.Parameter?.Value,
      valueLen: expected.length,
      // helpful when debugging region/account issues:
      version: out.Parameter?.Version,
      type: out.Parameter?.Type,
    });

  cached = { arnOrName, expected };
  return expected;
}

export async function enforceOriginVerify(event: HeaderCookieEvent | any): Promise<OriginVerifyResult> {
  const headerName = env(PLATFORM_ORIGIN_VERIFY_HEADER_NAME, '');
  if (!headerName) {
    console.log('[origin-verify] missing PLATFORM_ORIGIN_VERIFY_HEADER_NAME');
    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify header not set' };
  }

  const actual = getHeader(event, headerName);
  if (!actual) {
    console.log('[origin-verify] missing header on request', { headerName });
    return { ok: false, statusCode: 403, message: 'Forbidden (missing origin verify header)' };
  }

  let expected = '';
  try {
    expected = await getOriginVerifyExpected();
  } catch (err: any) {
    // ✅ this is the most important log for your current error
    console.log('[origin-verify] failed to read expected from SSM', {
      name: err?.name,
      message: err?.message,
      // AWS SDK v3 often includes this:
      statusCode: err?.$metadata?.httpStatusCode,
      requestId: err?.$metadata?.requestId,
    });

    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify secret not readable' };
  }

  if (!expected) {
    console.log('[origin-verify] expected value empty after SSM read');
    return { ok: false, statusCode: 500, message: 'Server misconfigured: origin verify secret empty' };
  }

  if (!timingSafeEqualStr(actual, expected)) {
    console.log('[origin-verify] header mismatch', {
      headerName,
      actualLen: actual.length,
      expectedLen: expected.length,
    });
    return { ok: false, statusCode: 403, message: 'Forbidden (bad origin verify header)' };
  }

  return { ok: true };
}

export function signPolicyRsaSha1(privateKeyPem: string, message: Buffer): Buffer {
  let keyObject: crypto.KeyObject;
  try {
    keyObject = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });
  } catch (e: any) {
    console.log('[cf-sign] createPrivateKey failed', {
      name: e?.name,
      message: e?.message,
      code: e?.code,
    });
    throw e;
  }

  const signer = crypto.createSign('RSA-SHA1');
  signer.update(message);
  signer.end();
  return signer.sign(keyObject);
}

export async function loadPrivateKeyFromSsm(paramName: string): Promise<string> {
  const out = await ssm.send(new GetParameterCommand({ Name: paramName, WithDecryption: true }));

  let raw = (out.Parameter?.Value ?? '').trim();
  const from = 'SSM SecureString';

  if (!raw) throw new Error('Parameter value was empty');

  // If JSON, extract key field
  if (raw.startsWith('{')) {
    const obj = JSON.parse(raw) as Record<string, unknown>;
    const candidate =
      (typeof obj.private_key === 'string' && obj.private_key) ||
      (typeof obj.privateKey === 'string' && obj.privateKey) ||
      (typeof obj.key === 'string' && obj.key) ||
      '';
    if (!candidate) throw new Error('Secret JSON missing private_key (or privateKey/key)');
    raw = candidate.trim();
  }

  // Convert literal "\n" sequences into real newlines (if present)
  raw = raw.replace(/\\n/g, '\n').trim();

  // Strip surrounding quotes (your log shows it starts with a quote)
  raw = raw.replace(/^['"]+|['"]+$/g, '').trim();

  // If it’s a one-line PEM (header/body/footer all in one line), reformat it.
  // e.g. "-----BEGIN PRIVATE KEY----- MIIE... -----END PRIVATE KEY-----"
  if (raw.includes('BEGIN PRIVATE KEY') && raw.includes('END PRIVATE KEY') && !raw.includes('\n')) {
    // gitleaks:allow
    const begin = '-----BEGIN PRIVATE KEY-----';
    // gitleaks:allow
    const end = '-----END PRIVATE KEY-----';

    const b = raw.indexOf(begin);
    const e = raw.indexOf(end);

    if (b === -1 || e === -1 || e <= b) throw new Error('PEM markers not found / malformed');

    const base64Body = raw
      .slice(b + begin.length, e)
      .replace(/\s+/g, '') // remove spaces
      .trim();

    // chunk into standard 64-char PEM lines
    const lines: string[] = [];
    for (let i = 0; i < base64Body.length; i += 64) {
      lines.push(base64Body.slice(i, i + 64));
    }

    raw = `${begin}\n${lines.join('\n')}\n${end}\n`;
  }

  // Safe diagnostics (no key leakage)
  if (DEBUG) {
    console.log('[secrets] private key loaded (safe metadata)', {
      paramName,
      from,
      len: raw.length,
      hasBegin: raw.includes('BEGIN'),
      hasPrivateKey: raw.includes('PRIVATE KEY'),
      hasNewlines: raw.includes('\n'),
    });
  }

  if (!raw.includes('BEGIN') || !raw.includes('PRIVATE KEY') || !raw.includes('END')) {
    throw new Error('Secret does not look like a PEM private key');
  }

  return raw;
}
