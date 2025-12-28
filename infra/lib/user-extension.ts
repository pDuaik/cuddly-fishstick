// infra/lib/user-extension.ts
import type { Construct } from 'constructs';
import type * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import type { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

export type UserApiMethod =
  | apigwv2.HttpMethod
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'OPTIONS'
  | 'HEAD';

export type CreateUserLambdaInput = {
  /**
   * CDK construct id for the lambda.
   * Example: "HelloFn"
   */
  id: string;

  /**
   * Entry file path for NodejsFunction (absolute or relative; ApiStack will pass repoRoot usage).
   * Example: path.join(repoRoot, 'user', 'hello.ts')
   */
  entry: string;

  /**
   * Lambda handler export name (defaults to "handler").
   */
  handler?: string;

  /**
   * Additional env vars for the lambda.
   * Note: required security env vars are injected by the platform and cannot be overridden.
   */
  environment?: Record<string, string>;

  /**
   * Optional overrides (platform provides defaults).
   */
  timeoutSeconds?: number;
  memorySizeMb?: number;
};

export type RegisterApiRouteInput = {
  /**
   * Must start with "/api/" and must NOT be under "/auth/".
   * Example: "/api/hello"
   */
  path: string;

  /**
   * Allowed methods only. Always authenticated.
   */
  methods: UserApiMethod[];

  /**
   * Lambda created by createUserLambda.
   */
  fn: NodejsFunction;
};

export type UserLambdaFactory = {
  createUserLambda(input: CreateUserLambdaInput): NodejsFunction;
};

export type UserApiRegistrar = {
  registerApiRoute(input: RegisterApiRouteInput): void;
};

export type UserExtensionCtx = {
  /**
   * Scope dedicated to user-owned constructs (keeps user additions contained).
   */
  featuresScope: Construct;

  /**
   * Platform lambda factory (enforces runtime/bundling/security env defaults).
   */
  lambda: UserLambdaFactory;

  /**
   * Platform route registrar (enforces /api/* + authorizer always).
   */
  api: UserApiRegistrar;

  /**
   * Optional convenience re-export (lets users write HttpMethod.GET etc).
   * ApiStack will provide this at runtime.
   */
  HttpMethod?: typeof apigwv2.HttpMethod;
};

export type UserExtensionRegisterFn = (ctx: UserExtensionCtx) => void;

