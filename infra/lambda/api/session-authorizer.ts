// lambda/api/session-authorizer.ts
// Handler for HTTP API Lambda Authorizer (SIMPLE response):
// returns { isAuthorized: boolean, context?: { ... } }

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';

import { originVerifyOk, env, getCookie } from './helpers';

type SimpleAuthResponse =
  | { isAuthorized: false }
  | { isAuthorized: true; context?: Record<string, string> };

type AuthorizerEvent = {
  headers?: Record<string, string | undefined>;
  cookies?: string[];
};

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

export async function handler(event: AuthorizerEvent): Promise<SimpleAuthResponse> {
  const tableName = env('SESSIONS_TABLE_NAME', '');
  if (!tableName) return { isAuthorized: false };

  const cookieName = env('COOKIE_NAME', 'session') || 'session';

  // CloudFront-only enforcement at day 1 (fail closed)
  if (!await originVerifyOk(event)) {
    return { isAuthorized: false };
  }

  // Read cookie from either header or cookies list
  const sessionId = getCookie(event, cookieName);
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
