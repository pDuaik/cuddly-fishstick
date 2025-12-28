// infra/lib/user-extension.ts
import type { Construct } from 'constructs';
import type { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

export type UserApiMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export type RegisterApiRouteInput = {
  path: string;              // must start with /api/, must not be /auth/*
  methods: UserApiMethod[];  // validated
  fn: NodejsFunction;        // must be created via createUserEndpoint
};

export type CreateUserEndpointInput = {
  /**
   * Stable logical id. Will be prefixed internally to avoid collisions.
   */
  id: string;

  /**
   * Absolute path to the user module file (for now).
   * Example: path.join(repoRoot, 'user', 'example-auth-call.ts')
   */
  entry: string;

  /**
   * Which export from the user module is the business function.
   * Defaults to "business".
   */
  exportName?: string;

  environment?: Record<string, string>;
  timeoutSeconds?: number;
  memorySizeMb?: number;
};

export type UserExtensionCtx = {
  featuresScope: Construct;

  endpoint: {
    createUserEndpoint(input: CreateUserEndpointInput): NodejsFunction;
  };

  api: {
    registerApiRoute(input: RegisterApiRouteInput): void;
  };
};

// User module must export this
export type UserRegisterFn = (ctx: UserExtensionCtx) => void;
