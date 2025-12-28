// infra/user/index.ts
import * as path from 'path';
import type { UserExtensionCtx } from '../lib/user-extension';

const repoRoot = path.resolve(__dirname, '..');

export function register(ctx: UserExtensionCtx): void {
  // ------------------------------------------------------------
  // Example: authenticated GET /api/example-auth-call
  // secureHttp is enforced by the platform wrapper (non-optional)
  // ------------------------------------------------------------
  const exampleAuthCallFn = ctx.endpoint.createUserEndpoint({
    id: 'ExampleAuthCall',
    entry: path.join(repoRoot, 'user', 'example-auth-call.ts'),
    exportName: 'business', // default is 'business', kept explicit for clarity
  });

  ctx.api.registerApiRoute({
    path: '/api/example-auth-call',
    methods: ['GET'],
    fn: exampleAuthCallFn,
  });

  // ------------------------------------------------------------
  // Example: authenticated POST /api/example-csrf-call
  // CSRF is enforced automatically by secureHttp for non-safe methods
  // ------------------------------------------------------------
  const exampleCsrfCallFn = ctx.endpoint.createUserEndpoint({
    id: 'ExampleCsrfCall',
    entry: path.join(repoRoot, 'user', 'example-csrf-call.ts'),
    exportName: 'business',
  });

  ctx.api.registerApiRoute({
    path: '/api/example-csrf-call',
    methods: ['POST'],
    fn: exampleCsrfCallFn,
  });
}
