// infra/user/index.ts
import * as path from 'path';
import type { UserExtensionCtx } from '../lib/user-extension';

const repoRoot = path.resolve(__dirname, '..');

export function register(ctx: UserExtensionCtx): void {
    // ------------------------------------------------------------
    // Example: authenticated GET /api/example-auth-call
    // ------------------------------------------------------------
    const exampleAuthCallFn = ctx.lambda.createUserLambda({
        id: 'ExampleAuthCallFn',
        entry: path.join(repoRoot, 'user', 'example-auth-call.ts'),
    });

    ctx.api.registerApiRoute({
        path: '/api/example-auth-call',
        methods: [ctx.HttpMethod?.GET ?? 'GET'],
        fn: exampleAuthCallFn,
    });

    // ------------------------------------------------------------
    // Example: authenticated POST /api/example-csrf-call
    // (CSRF enforced automatically by secureHttp)
    // ------------------------------------------------------------
    const exampleCsrfCallFn = ctx.lambda.createUserLambda({
        id: 'ExampleCsrfCallFn',
        entry: path.join(repoRoot, 'user', 'example-csrf-call.ts'),
    });

    ctx.api.registerApiRoute({
        path: '/api/example-csrf-call',
        methods: [ctx.HttpMethod?.POST ?? 'POST'],
        fn: exampleCsrfCallFn,
    });
}
