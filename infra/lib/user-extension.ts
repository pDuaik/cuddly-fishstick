// infra/lib/user-extension.ts
import type { Construct } from 'constructs';
import type { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

/**
 * Allowed HTTP methods for user /api/* routes.
 * (Validated again at runtime in ApiStack registrar.)
 */
export type UserApiMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export type RegisterApiRouteInput = {
  /**
   * Must start with "/api/" and must NOT be under "/auth/".
   * (Enforced by ApiStack registrar.)
   */
  path: string;

  /**
   * One or more allowed methods.
   */
  methods: UserApiMethod[];

  /**
   * Lambda created by ctx.endpoint.createUserEndpoint().
   */
  fn: NodejsFunction;
};

export type CreateUserEndpointInput = {
  /**
   * Stable logical id (platform will prefix/sanitize internally to avoid collisions).
   * Example: "Ping", "InvoicesList", etc.
   */
  id: string;

  /**
   * Absolute path to a user module file.
   * The module must export a SecureHttpBusinessFn (see secure-http.ts types).
   *
   * Example:
   *   path.join(repoRoot, 'user', 'ping.ts')
   */
  entry: string;

  /**
   * Which named export to import from the user module as the business function.
   * Defaults to "business".
   */
  exportName?: string;

  /**
   * Extra env vars for the endpoint (merged).
   * Platform-required vars are injected automatically and cannot be overridden.
   */
  environment?: Record<string, string>;

  timeoutSeconds?: number;
  memorySizeMb?: number;
};

export type UserExtensionCtx = {
  /**
   * Construct scope for all user-owned resources created by the extension.
   */
  featuresScope: Construct;

  /**
   * Endpoint factory:
   * creates a Lambda whose handler is platform-owned and ALWAYS wraps user business with secureHttp().
   */
  endpoint: {
    createUserEndpoint(input: CreateUserEndpointInput): NodejsFunction;
  };

  /**
   * Route registrar:
   * registers /api/* routes and ALWAYS attaches the existing session authorizer.
   */
  api: {
    registerApiRoute(input: RegisterApiRouteInput): void;
  };
};

/**
 * Downstream user module must export:
 *   export function register(ctx: UserExtensionCtx): void { ... }
 */
export type UserRegisterFn = (ctx: UserExtensionCtx) => void;
