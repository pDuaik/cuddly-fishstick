// lambda/api/example-csrf-call.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';

import { requireEnv } from './helpers';
import { secureHttp } from './secure-http';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

export const handler = secureHttp(async (ctx, input) => {
  // Validate body (simple “increment” action)
  const body = input.body as any;

  if (!body || body.action !== 'increment') {
    // Keep behavior identical (400 + message)
    return {
      // NOTE: with current secureHttp pattern (plain object => 200),
      // we need the wrapper to support overriding status for this.
      // If your secureHttp already supports status overrides, use that.
      // Otherwise: see note below.
      statusCode: 400,
      body: { ok: false, message: 'Expected body: { "action": "increment" }' },
    } as any;
  }

  // Increment counter in DynamoDB
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
        ':u': ctx.user_sub,
        ':t': new Date().toISOString(),
      },
      ReturnValues: 'ALL_NEW',
    }),
  );

  const value = Number(out.Attributes?.value ?? 0);

  return {
    demo_counter: value,
    updated_at: out.Attributes?.updated_at,
  };
});
