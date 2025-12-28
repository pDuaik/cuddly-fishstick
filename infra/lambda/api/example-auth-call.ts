// lambda/api/example-auth-call.ts
import { secureHttp } from './secure-http';

export const handler = secureHttp(async (ctx) => {
  return {
    message: 'This is an authenticated API call',
    example: {
      session_id: ctx.session_id,
      user_sub: ctx.user_sub,
      server_time: new Date().toISOString(),
    },
  };
});
