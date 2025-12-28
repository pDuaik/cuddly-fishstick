// infra/user/example-csrf-call.ts
import { secureHttp } from '../lambda/api/secure-http';

export const handler = secureHttp(async (ctx, input) => {
  return {
    message: 'example-csrf-call ok',
    method: ctx.method,
    received: input.body ?? null,
  };
});
