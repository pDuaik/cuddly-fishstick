// infra/user/example-csrf-call.ts
import type { SecureHttpBusinessFn } from '../lambda/api/secure-http';

export const business: SecureHttpBusinessFn = async (ctx, input) => {
  return {
    message: 'example-csrf-call ok',
    method: ctx.method,
    received: input.body ?? null,
  };
};
