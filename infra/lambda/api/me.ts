// lambda/api/me.ts
import { secureHttp } from './secure-http';

export const handler = secureHttp((ctx) => {
  return {
    logged_in: true
  };
});
