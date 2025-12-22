import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';

import { enforceOriginVerify, getCookie, getHeader, json, requireEnv, timingSafeEqualStr } from './helpers';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

type AuthedEvent = APIGatewayProxyEventV2 & {
  requestContext: {
    authorizer?: {
      lambda?: {
        session_id?: string;
        user_sub?: string;
      };
    };
  };
};

function requireAuthorizer(event: AuthedEvent) {
  const ctx = event.requestContext?.authorizer?.lambda;
  if (!ctx?.session_id || !ctx?.user_sub) return null;
  return { session_id: String(ctx.session_id), user_sub: String(ctx.user_sub) };
}

function enforceCsrf(event: AuthedEvent): { ok: true } | { ok: false; statusCode: number; message: string } {
  const cookieName = requireEnv('CSRF_COOKIE_NAME'); // e.g. "__Host-csrf"
  const headerName = requireEnv('CSRF_HEADER_NAME'); // e.g. "X-CSRF-Token"

  const tokenCookie = getCookie(event, cookieName);
  const tokenHeader = getHeader(event, headerName);

  if (!tokenCookie || !tokenHeader) {
    return { ok: false, statusCode: 403, message: 'Forbidden (missing CSRF token)' };
  }

  if (!timingSafeEqualStr(tokenCookie, tokenHeader)) {
    return { ok: false, statusCode: 403, message: 'Forbidden (bad CSRF token)' };
  }

  return { ok: true };
}

export async function handler(event: AuthedEvent): Promise<APIGatewayProxyResultV2> {
  // 1) CloudFront-only enforcement (fail closed)
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { ok: false, message: ov.message });

  // 2) Must be behind session authorizer (fail closed)
  const authed = requireAuthorizer(event);
  if (!authed) return json(401, { ok: false, message: 'Unauthorized' });

  // 3) CSRF double-submit validation (cookie + header must match)
  const csrf = enforceCsrf(event);
  if (!csrf.ok) return json(csrf.statusCode, { ok: false, message: csrf.message });

  // 4) Validate body (simple “increment” action)
  let body: any = {};
  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return json(400, { ok: false, message: 'Invalid JSON body' });
  }

  if (!body || body.action !== 'increment') {
    return json(400, { ok: false, message: 'Expected body: { "action": "increment" }' });
  }

  // 5) Increment counter in DynamoDB
  const tableName = requireEnv('DEMO_TABLE_NAME');
  const key = { pk: 'demo_counter' };

  const out = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: key,
      UpdateExpression: 'SET #v = if_not_exists(#v, :zero) + :one, #u = :u, #t = :t',
      ExpressionAttributeNames: {
        '#v': 'value',
        '#u': 'last_user_sub',
        '#t': 'updated_at',
      },
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':u': authed.user_sub,
        ':t': new Date().toISOString(),
      },
      ReturnValues: 'ALL_NEW',
    }),
  );

  const value = Number(out.Attributes?.value ?? 0);

  return json(200, {
    ok: true,
    demo_counter: value,
    updated_at: out.Attributes?.updated_at,
  });
}
