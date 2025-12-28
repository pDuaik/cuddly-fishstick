// infra/user/ping.ts
import type { SecureHttpBusinessFn } from '../lambda/api/secure-http';

export const business: SecureHttpBusinessFn = async (ctx) => {
  return {
    message: 'pong',
    user_sub: ctx.user_sub,
  };
};
