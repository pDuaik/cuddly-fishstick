// lambda/api/public-http.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { enforceOriginVerify, json } from './helpers';

export type PublicHttpCtx = {
  method: string;
  requestId?: string;
};

export type PublicHttpInput = {
  event: APIGatewayProxyEventV2;
};

export type PublicHttpOk = Record<string, unknown>;

// Non-exported on purpose: users should use publicHttpOverride(), not construct this.
type PublicHttpOverride = {
  __override: true;
  statusCode: number;
  body: Record<string, unknown>;
};

export function publicHttpOverride(statusCode: number, body: Record<string, unknown>) {
  return { __override: true, statusCode, body } as const;
}

export type PublicHttpResult = PublicHttpOk | ReturnType<typeof publicHttpOverride>;

export type PublicHttpBusinessFn = (
  ctx: PublicHttpCtx,
  input: PublicHttpInput,
) => Promise<PublicHttpResult> | PublicHttpResult;

function methodUpper(event: APIGatewayProxyEventV2): string | null {
  const m = String(event.requestContext?.http?.method ?? '').trim().toUpperCase();
  return m ? m : null;
}

function noContent(headers?: Record<string, string>): APIGatewayProxyResultV2 {
  return {
    statusCode: 204,
    headers: {
      'cache-control': 'no-store',
      ...(headers ?? {}),
    },
    body: '',
  };
}

function isOverrideResult(v: unknown): v is PublicHttpOverride {
  if (!v || typeof v !== 'object') return false;
  const r = v as any;
  return r.__override === true && typeof r.statusCode === 'number' && r.body != null && typeof r.body === 'object';
}

function assertValidBusinessResult(v: unknown): asserts v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) {
    throw new Error('publicHttp businessFn must return an object (or use publicHttpOverride(statusCode, body)).');
  }

  const reservedKeys = ['ok', '__override'] as const;
  for (const k of reservedKeys) {
    if (k in (v as any)) {
      throw new Error(
        `publicHttp businessFn returned reserved key "${k}". Remove it, or use publicHttpOverride(statusCode, body).`,
      );
    }
  }
}

export function publicHttp(businessFn: PublicHttpBusinessFn) {
  return async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
    const ov = await enforceOriginVerify(event);
    if (!ov.ok) return json(ov.statusCode, { ok: false, message: ov.message });

    const method = methodUpper(event);
    if (!method) return json(400, { ok: false, message: 'Bad Request (missing method)' });

    if (method === 'OPTIONS' || method === 'HEAD') {
      return noContent({ allow: 'GET, HEAD, OPTIONS' });
    }

    if (method !== 'GET') {
      return json(405, { ok: false, message: 'Method Not Allowed' }, { headers: { allow: 'GET, HEAD, OPTIONS' } });
    }

    const ctx: PublicHttpCtx = {
      method,
      requestId: event.requestContext?.requestId,
    };

    try {
      const out = await businessFn(ctx, { event });

      if (
        out &&
        typeof out === 'object' &&
        !isOverrideResult(out) &&
        'statusCode' in (out as any) &&
        'body' in (out as any)
      ) {
        throw new Error('publicHttp: use publicHttpOverride(statusCode, body) instead of returning { statusCode, body }.');
      }

      if (isOverrideResult(out)) {
        return json(out.statusCode, out.body);
      }

      const payload: unknown = out ?? {};
      assertValidBusinessResult(payload);

      return json(200, { ok: true, ...payload });
    } catch (e: any) {
      console.error('publicHttp businessFn error', {
        requestId: ctx.requestId,
        message: e?.message,
        stack: e?.stack,
      });

      return json(500, { ok: false, message: 'Internal error' });
    }
  };
}
