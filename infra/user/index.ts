// infra/user/index.ts
import * as path from 'path';
import type { UserExtensionCtx } from '../lib/user-extension';

const repoRoot = path.resolve(__dirname, '..');

export function register(ctx: UserExtensionCtx): void {
  // ------------------------------------------------------------
  // GET /api/ping
  // ------------------------------------------------------------
  const pingFn = ctx.endpoint.createUserEndpoint({
    id: 'Ping',
    entry: path.join(repoRoot, 'user', 'ping.ts'),
    // exportName defaults to "business"
  });

  ctx.api.registerApiRoute({
    path: '/api/ping',
    methods: ['GET'],
    fn: pingFn,
  });

  // ------------------------------------------------------------
  // GET /api/example-auth-call
  // ------------------------------------------------------------
  const exampleAuthCallFn = ctx.endpoint.createUserEndpoint({
    id: 'ExampleAuthCall',
    entry: path.join(repoRoot, 'user', 'example-auth-call.ts'),
  });

  ctx.api.registerApiRoute({
    path: '/api/example-auth-call',
    methods: ['GET'],
    fn: exampleAuthCallFn,
  });

  // ------------------------------------------------------------
  // POST /api/example-csrf-call
  // (CSRF automatically enforced by secureHttp)
  // ------------------------------------------------------------
  const exampleCsrfCallFn = ctx.endpoint.createUserEndpoint({
    id: 'ExampleCsrfCall',
    entry: path.join(repoRoot, 'user', 'example-csrf-call.ts'),
  });

  ctx.api.registerApiRoute({
    path: '/api/example-csrf-call',
    methods: ['POST'],
    fn: exampleCsrfCallFn,
  });
}
