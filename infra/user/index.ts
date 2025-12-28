// infra/user/index.ts
import type { UserExtensionCtx } from '../lib/user-extension';

export function register(ctx: UserExtensionCtx): void {
  // ------------------------------------------------------------
  // GET /api/ping
  // ------------------------------------------------------------
  const pingFn = ctx.endpoint.createUserEndpoint({
    id: 'Ping',
    entryRelativeToUserDir: 'ping.ts',
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
    entryRelativeToUserDir: 'example-auth-call.ts',
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
    entryRelativeToUserDir: 'example-csrf-call.ts',
  });

  ctx.api.registerApiRoute({
    path: '/api/example-csrf-call',
    methods: ['POST'],
    fn: exampleCsrfCallFn,
  });
}
