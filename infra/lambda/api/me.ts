// lambda/api/me.ts

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';

import { enforceOriginVerify, json } from './helpers';

type HttpApiEventWithAuthorizer = APIGatewayProxyEventV2 & {
  requestContext: APIGatewayProxyEventV2['requestContext'] & {
    authorizer?: {
      lambda?: Record<string, unknown>;
    };
  };
};

export async function handler(event: HttpApiEventWithAuthorizer): Promise<APIGatewayProxyResultV2> {
  const ov = await enforceOriginVerify(event);
  if (!ov.ok) return json(ov.statusCode, { message: ov.message });

  const auth = event.requestContext.authorizer?.lambda ?? {};

  return json(200, {
    ok: true,
    authorizer: auth,
  });
}
