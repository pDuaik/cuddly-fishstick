// lambda/api/me.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { timingSafeEqual } from 'crypto';

type HttpApiEventWithAuthorizer = APIGatewayProxyEventV2 & {
  requestContext: APIGatewayProxyEventV2['requestContext'] & {
    authorizer?: {
      lambda?: Record<string, unknown>;
    };
  };
};

function getHeader(event: APIGatewayProxyEventV2, name: string): string {
  const headers = event.headers ?? {};
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return (v ?? '').toString();
  }
  return '';
}

function enforceOriginVerify(event: APIGatewayProxyEventV2): APIGatewayProxyResultV2 | null {
  const headerName = (process.env.ORIGIN_VERIFY_HEADER_NAME ?? '').trim();
  const expected = (process.env.ORIGIN_VERIFY_HEADER_VALUE ?? '').trim();

  if (!headerName || !expected) {
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Server misconfigured (origin verify not set)' }),
    };
  }

  const actual = getHeader(event, headerName);
  if (!actual) {
    return {
      statusCode: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Forbidden (missing origin verify header)' }),
    };
  }

  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  const ok = a.length === b.length && timingSafeEqual(a, b);

  if (!ok) {
    return {
      statusCode: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Forbidden (bad origin verify header)' }),
    };
  }

  return null;
}

export async function handler(event: HttpApiEventWithAuthorizer): Promise<APIGatewayProxyResultV2> {
  const deny = enforceOriginVerify(event);
  if (deny) return deny;

  const auth = event.requestContext.authorizer?.lambda ?? {};

  return {
    statusCode: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    },
    body: JSON.stringify({
      ok: true,
      authorizer: auth,
    }),
  };
}
