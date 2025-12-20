// lambda/api/session-authorizer.ts
// Handler for HTTP API Lambda Authorizer (SIMPLE response):
// returns { isAuthorized: boolean, context?: { ... } }

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { timingSafeEqual } from 'crypto';

type SimpleAuthResponse =
  | { isAuthorized: false }
  | { isAuthorized: true; context?: Record<string, string> };

type AuthorizerEvent = {
  headers?: Record<string, string | undefined>;
  cookies?: string[];
};

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

function getHeader(headers: Record<string, string | undefined> | undefined, name: string): string {
  const h = headers ?? {};
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(h)) {
    if (k.toLowerCase() === target) return (v ?? '').toString();
  }
  return '';
}

function parseCookiesFromHeader(cookieHeader: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;

  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function parseCookiesFromList(cookieList: string[] | undefined): Record<string, string> {
  // HTTP API v2 often provides cookies as ["a=b", "c=d"]
  // but proxies can sometimes supply "a=b; c=d"
  const out: Record<string, string> = {};
  for (const entry of cookieList ?? []) {
    for (const part of (entry ?? '').split(';')) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const name = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      if (name) out[name] = value;
    }
  }
  return out;
}

function enforceOriginVerify(event: AuthorizerEvent): boolean {
  const headerName = (process.env.ORIGIN_VERIFY_HEADER_NAME ?? '').trim();
  const expected = (process.env.ORIGIN_VERIFY_HEADER_VALUE ?? '').trim();

  // Template stance: must be configured (fail closed)
  if (!headerName || !expected) return false;

  const actual = getHeader(event.headers, headerName);
  if (!actual) return false;

  // Constant-time compare
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function handler(event: AuthorizerEvent): Promise<SimpleAuthResponse> {
  const tableName = (process.env.SESSIONS_TABLE_NAME ?? '').trim();
  if (!tableName) return { isAuthorized: false };

  const cookieName = (process.env.COOKIE_NAME ?? 'session').trim() || 'session';

  // CloudFront-only enforcement at day 1
  if (!enforceOriginVerify(event)) {
    return { isAuthorized: false };
  }

  // Read cookies from BOTH places (header + cookies list)
  const headerCookies = parseCookiesFromHeader(getHeader(event.headers, 'cookie'));
  const listCookies = parseCookiesFromList(event.cookies);
  const cookies = { ...headerCookies, ...listCookies };

  const sessionId = cookies[cookieName];
  if (!sessionId) return { isAuthorized: false };

  try {
    const resp = await ddb.send(
      new GetCommand({
        TableName: tableName,
        Key: { session_id: sessionId },
        ConsistentRead: false,
      }),
    );

    const item = resp.Item as undefined | { expires_at?: number; user_sub?: string };
    if (!item) return { isAuthorized: false };

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = Number(item.expires_at ?? 0);

    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      return { isAuthorized: false };
    }

    return {
      isAuthorized: true,
      context: {
        user_sub: (item.user_sub ?? 'unknown').toString(),
        session_id: sessionId,
      },
    };
  } catch {
    return { isAuthorized: false };
  }
}
