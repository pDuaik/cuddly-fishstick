// lambda/api/secure-http.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';

import {
  enforceOriginVerify,
  getCookie,
  getHeader,
  json,
  requireEnv,
  timingSafeEqualStr,
} from './helpers';

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

export type SecureHttpOverride = {
  statusCode: number;
  body: Record<string, unknown>;
};

export type SecureHttpResult = SecureHttpOk | SecureHttpOverride;

export type SecureHttpBusinessFn = (
  ctx: SecureHttpCtx,
  input: SecureHttpInput,
) => Promise<SecureHttpResult> | SecureHttpResult;

type SecureHttpOptions = {
  // reserved for future; keep minimal for now
};

function methodUpper(event: APIGatewayProxyEventV2): string {
  return String(event.requestContext?.http?.method ?? '').toUpperCase();
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
    const raw = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf-8')
      : event.body;

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

  const cookieName = requireEnv('CSRF_COOKIE_NAME');
  const headerName = requireEnv('CSRF_HEADER_NAME');

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
  return typeof r.statusCode === 'number' && r.body != null && typeof r.body === 'object';
}

export function secureHttp(businessFn: SecureHttpBusinessFn, _options?: SecureHttpOptions) {
  return async function handler(event: HttpApiEventWithAuthorizer): Promise<APIGatewayProxyResultV2> {
    // 1) CloudFront-only origin verification (fail closed)
    const ov = await enforceOriginVerify(event);
    if (!ov.ok) return json(ov.statusCode, { ok: false, message: ov.message });

    // 2) Authorizer context required
    const authed = readAuthorizer(event);
    if (!authed) return json(401, { ok: false, message: 'Unauthorized' });

    const method = methodUpper(event);

    // 3) CSRF enforcement by method (unsafe only)
    const csrf = enforceCsrfIfNeeded(event, method);
    if (!csrf.ok) return json(csrf.statusCode, { ok: false, message: csrf.message });

    // 4) JSON parsing and consistent errors
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

      // Business override: let handler return status + body exactly (no re-wrapping).
      if (isOverrideResult(out)) {
        return json(out.statusCode, out.body);
      }

      // Default success wrapper
      return json(200, { ok: true, ...(out ?? {}) });
    } catch (e: any) {
      // Keep it consistent and not leaky
      return json(500, { ok: false, message: e?.message ?? 'Internal error' });
    }
  };
}
