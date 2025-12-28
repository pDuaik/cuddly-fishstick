// infra/user/ping.ts
import { secureHttp } from '../lambda/api/secure-http';

export const handler = secureHttp(async (ctx) => {
  return {
    message: 'pong',
    user_sub: ctx.user_sub,
  };
});
