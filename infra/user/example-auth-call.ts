// infra/user/example-auth-call.ts
import type { SecureHttpBusinessFn } from '../lambda/api/secure-http';

export const business: SecureHttpBusinessFn = async (ctx) => {
  return {
    message: 'example-auth-call ok',
    user_sub: ctx.user_sub,
  };
};
