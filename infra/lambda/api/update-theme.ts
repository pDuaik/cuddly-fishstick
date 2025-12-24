// lambda/api/update-theme.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

import { enforceOriginVerify, getCookie, getHeader, json, requireEnv, timingSafeEqualStr } from './helpers';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

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
  const cookieName = requireEnv('CSRF_COOKIE_NAME'); // "__Host-csrf"
  const headerName = requireEnv('CSRF_HEADER_NAME'); // "X-CSRF-Token"

  const tokenCookie = getCookie(event, cookieName);
  const tokenHeader = getHeader(event, headerName);

  if (!tokenCookie || !tokenHeader) return { ok: false, statusCode: 403, message: 'Forbidden (missing CSRF token)' };
  if (!timingSafeEqualStr(tokenCookie, tokenHeader)) return { ok: false, statusCode: 403, message: 'Forbidden (bad CSRF token)' };

  return { ok: true };
}

function parseBody(event: AuthedEvent): any {
  if (!event.body) return {};
  try {
    return event.isBase64Encoded ? JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8')) : JSON.parse(event.body);
  } catch {
    throw new Error('Invalid JSON body');
  }
}

function normalizeHexColor(input: string): string | null {
  const v = (input ?? '').trim();
  if (!v) return null;
  // allow "#RRGGBB" only (keep it strict)
  if (!/^#[0-9a-fA-F]{6}$/.test(v)) return null;
  return v.toLowerCase();
}

export async function handler(event: AuthedEvent): Promise<APIGatewayProxyResultV2> {
  // 1) CloudFront-only
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { ok: false, message: ov.message });

  // 2) Session authorizer
  const authed = requireAuthorizer(event);
  if (!authed) return json(401, { ok: false, message: 'Unauthorized' });

  // 3) CSRF
  const csrf = enforceCsrf(event);
  if (!csrf.ok) return json(csrf.statusCode, { ok: false, message: csrf.message });

  // 4) Parse + validate input
  let body: any = {};
  try {
    body = parseBody(event);
  } catch (e: any) {
    return json(400, { ok: false, message: e?.message ?? 'Invalid JSON body' });
  }

  const bg = normalizeHexColor(String(body?.bg ?? body?.background ?? ''));
  if (!bg) {
    return json(400, { ok: false, message: 'Expected JSON body like: { "bg": "#32a852" }' });
  }

  // 5) Resolve opaque id from user profile table
  const profileTable = requireEnv('USER_PROFILE_TABLE_NAME');
  const got = await ddb.send(
    new GetCommand({
      TableName: profileTable,
      Key: { user_sub: authed.user_sub },
      ProjectionExpression: 'opaque_id',
    }),
  );

  const opaqueId = String(got.Item?.opaque_id ?? '');
  if (!opaqueId) return json(500, { ok: false, message: 'User profile missing opaque_id' });

  // 6) Write CSS to S3 (create/replace)
  const bucket = requireEnv('USERS_BUCKET_NAME');
  const key = `u/${opaqueId}/theme.css`;

  const css = `:root { --bg: ${bg}; }\n`;

  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: css,
      ContentType: 'text/css; charset=utf-8',
      CacheControl: 'no-store, no-cache, must-revalidate, max-age=0',
    }),
  );

  return json(200, {
    ok: true,
    key,
    bg,
  });
}
