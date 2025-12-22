// lambda/api/example-auth-call.ts
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { enforceOriginVerify, json } from './helpers';

type AuthedEvent = APIGatewayProxyEventV2 & {
  requestContext: {
    authorizer: {
      lambda: {
        session_id: string;
        user_sub: string;
      };
    };
  };
};

export async function handler(event: AuthedEvent): Promise<APIGatewayProxyResultV2> {
  // 1) CloudFront-only enforcement
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { message: ov.message });

  // 2) Session authorizer already ran (guaranteed here)
  const { session_id, user_sub } = event.requestContext.authorizer.lambda;

  // 3) Example “business logic”
  return json(200, {
    ok: true,
    message: 'This is an authenticated API call',
    example: {
      session_id,
      user_sub,
      server_time: new Date().toISOString(),
    },
  });
}
