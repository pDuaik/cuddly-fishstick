// lambda/api/secure-http.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { enforceOriginVerify, getCookie, getHeader, json, requireEnv, timingSafeEqualStr } from './helpers';
import {
  PLATFORM_CSRF_COOKIE_NAME,
  PLATFORM_CSRF_HEADER_NAME,
} from './platform-env';

type HttpApiEventWithAuthorizer = APIGatewayProxyEventV2 & {
  requestContext: APIGatewayProxyEventV2['requestContext'] & {
    authorizer?: {
      lambda?: Record<string, unknown>;
    };
  };
};

export type SecureHttpCtx = {
  session_id: string;
  user_sub: string;
  method: string;
  requestId?: string;
};

export type SecureHttpInput = {
  body?: unknown;
  event: APIGatewayProxyEventV2;
};

export type SecureHttpOk = Record<string, unknown>;

// Non-exported on purpose: users should use httpOverride(), not construct this.
type SecureHttpOverride = {
  __override: true;
  statusCode: number;
  body: Record<string, unknown>;
};

// Convenience helper so business code can return overrides without repeating the sentinel.
export function httpOverride(statusCode: number, body: Record<string, unknown>) {
  return { __override: true, statusCode, body } as const;
}

export type SecureHttpResult = SecureHttpOk | ReturnType<typeof httpOverride>;

export type SecureHttpBusinessFn = (
  ctx: SecureHttpCtx,
  input: SecureHttpInput,
) => Promise<SecureHttpResult> | SecureHttpResult;

type SecureHttpOptions = {
  // reserved for future
};

function methodUpper(event: APIGatewayProxyEventV2): string | null {
  const m = String(event.requestContext?.http?.method ?? '').trim().toUpperCase();
  return m ? m : null;
}

function isSafeMethod(m: string): boolean {
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS';
}

function readAuthorizer(event: HttpApiEventWithAuthorizer): { session_id: string; user_sub: string } | null {
  const auth = event.requestContext.authorizer?.lambda ?? {};
  const session_id = (auth as any).session_id;
  const user_sub = (auth as any).user_sub;

  if (!session_id || !user_sub) return null;
  return { session_id: String(session_id), user_sub: String(user_sub) };
}

function parseJsonBody(event: APIGatewayProxyEventV2): { ok: true; body: unknown } | { ok: false } {
  if (!event.body) return { ok: true, body: undefined };

  try {
    const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf-8') : event.body;
    if (!raw.trim()) return { ok: true, body: undefined };
    return { ok: true, body: JSON.parse(raw) };
  } catch {
    return { ok: false };
  }
}

function enforceCsrfIfNeeded(
  event: APIGatewayProxyEventV2,
  method: string,
): { ok: true } | { ok: false; statusCode: number; message: string } {
  if (isSafeMethod(method)) return { ok: true };

  const cookieName = requireEnv(PLATFORM_CSRF_COOKIE_NAME);
  const headerName = requireEnv(PLATFORM_CSRF_HEADER_NAME);

  const tokenCookie = getCookie(event, cookieName);
  const tokenHeader = getHeader(event, headerName);

  if (!tokenCookie || !tokenHeader) {
    return { ok: false, statusCode: 403, message: 'Forbidden (missing CSRF token)' };
  }

  if (!timingSafeEqualStr(String(tokenCookie), String(tokenHeader))) {
    return { ok: false, statusCode: 403, message: 'Forbidden (bad CSRF token)' };
  }

  return { ok: true };
}

function isOverrideResult(v: unknown): v is SecureHttpOverride {
  if (!v || typeof v !== 'object') return false;
  const r = v as any;
  return r.__override === true && typeof r.statusCode === 'number' && r.body != null && typeof r.body === 'object';
}

function assertValidBusinessResult(v: unknown): asserts v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) {
    throw new Error('secureHttp businessFn must return an object (or use httpOverride(statusCode, body)).');
  }

  // Prevent collisions with platform-controlled fields/sentinels.
  const reservedKeys = ['ok', '__override'] as const;
  for (const k of reservedKeys) {
    if (k in (v as any)) {
      throw new Error(
        `secureHttp businessFn returned reserved key "${k}". Remove it, or use httpOverride(statusCode, body).`,
      );
    }
  }
}

export function secureHttp(businessFn: SecureHttpBusinessFn, _options?: SecureHttpOptions) {
  return async function handler(event: HttpApiEventWithAuthorizer): Promise<APIGatewayProxyResultV2> {
    const ov = await enforceOriginVerify(event);
    if (!ov.ok) return json(ov.statusCode, { ok: false, message: ov.message });

    const authed = readAuthorizer(event);
    if (!authed) return json(401, { ok: false, message: 'Unauthorized' });

    const method = methodUpper(event);
    if (!method) return json(400, { ok: false, message: 'Bad Request (missing method)' });

    const csrf = enforceCsrfIfNeeded(event, method);
    if (!csrf.ok) return json(csrf.statusCode, { ok: false, message: csrf.message });

    const parsed = parseJsonBody(event);
    if (!parsed.ok) return json(400, { ok: false, message: 'Invalid JSON body' });

    const ctx: SecureHttpCtx = {
      session_id: authed.session_id,
      user_sub: authed.user_sub,
      method,
      requestId: event.requestContext?.requestId,
    };

    try {
      const out = await businessFn(ctx, { body: parsed.body, event });

      // Guard: devs sometimes return { statusCode, body } expecting an early return.
      // That shape is NOT an override unless __override is present.
      if (
        out &&
        typeof out === 'object' &&
        !isOverrideResult(out) &&
        'statusCode' in (out as any) &&
        'body' in (out as any)
      ) {
        throw new Error('secureHttp: use httpOverride(statusCode, body) instead of returning { statusCode, body }.');
      }

      if (isOverrideResult(out)) {
        return json(out.statusCode, out.body);
      }

      const payload: unknown = out ?? {};
      assertValidBusinessResult(payload);

      return json(200, { ok: true, ...payload });
    } catch (e: any) {
      console.error('secureHttp businessFn error', {
        requestId: ctx.requestId,
        user_sub: ctx.user_sub,
        message: e?.message,
        stack: e?.stack,
      });

      return json(500, { ok: false, message: 'Internal error' });
    }
  };
}
