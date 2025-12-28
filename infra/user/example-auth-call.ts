// infra/user/example-auth-call.ts
import { secureHttp } from '../lambda/api/secure-http';

export const handler = secureHttp(async (ctx) => {
  return {
    message: 'example-auth-call ok',
    user_sub: ctx.user_sub,
  };
});
