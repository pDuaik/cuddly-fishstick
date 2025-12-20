import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigwv2Integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as apigwv2Authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as path from 'path';
import type { AppConfig } from './config';

export type ExtraApiRoute = {
  path: string; // must start with /api/
  method: string; // GET/POST/...
  lambdaArn: string; // existing lambda ARN
};

export interface ApiStackProps extends cdk.StackProps {
  config: AppConfig;

  sessionsTable: dynamodb.ITable;

  cognitoDomain: string;
  cognitoClientId: string;

  cfPublicKeyId: string;
  cfPrivateKeySecretArn: string;

  cfCookieDomain: string;
  cfCookiePath?: string; // default "/"
  cfCookieTtlSeconds?: number; // default 3600

  originVerifyHeaderName: string; // default "X-Origin-Verify"

  /**
   * ✅ Parameter Store *parameter ARN* (SecureString recommended)
   * Example:
   * arn:aws:ssm:eu-west-2:123456789012:parameter/my-origin-verify
   */
  originVerifyHeaderValueSecretArn: string;

  extraApiRoutes?: ExtraApiRoute[];
}

export class ApiStack extends cdk.Stack {
  public readonly httpApi: apigwv2.HttpApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const { projectName, stage, domain } = props.config;

    const requireNonEmpty = (name: string, v: string) => {
      const s = (v ?? '').trim();
      if (!s || s === '__REQUIRED__') throw new Error(`Missing required ApiStack prop "${name}".`);
      return s;
    };

    const cognitoDomain = requireNonEmpty('cognitoDomain', props.cognitoDomain);
    const cognitoClientId = requireNonEmpty('cognitoClientId', props.cognitoClientId);

    // ✅ Key Groups: Public Key ID (NOT legacy Trusted Signers "key pair id")
    const cfPublicKeyId = requireNonEmpty('cfPublicKeyId', props.cfPublicKeyId);
    const cfPrivateKeySecretArn = requireNonEmpty('cfPrivateKeySecretArn', props.cfPrivateKeySecretArn);
    const cfCookieDomain = requireNonEmpty('cfCookieDomain', props.cfCookieDomain);

    const originVerifyHeaderName = (props.originVerifyHeaderName || 'X-Origin-Verify').trim() || 'X-Origin-Verify';
    const originVerifyHeaderValueSecretArn = requireNonEmpty(
      'originVerifyHeaderValueSecretArn',
      props.originVerifyHeaderValueSecretArn,
    );

    const appBaseUrl = `https://${domain}`;
    const redirectUri = `${appBaseUrl}/auth/callback`;

    const cfCookiePath = (props.cfCookiePath ?? '/').trim() || '/';
    const cfCookieTtlSeconds = props.cfCookieTtlSeconds ?? 3600;

    // ✅ Only sign for app paths
    const cfAppResource = `${appBaseUrl}/app/*`;

    const cookieNames = {
      OAUTH_STATE_COOKIE_NAME: 'oauth_state',
      PKCE_VERIFIER_COOKIE_NAME: 'pkce_verifier',
      POST_LOGIN_COOKIE_NAME: 'post_login',
    };

    // Repo root is two levels above infra/bin typically; this is resilient from lib/
    const repoRoot = path.resolve(__dirname, '..');

    const lambdaDefaults = {
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      bundling: {
        target: 'node22',
        sourceMap: true,
      },
    } as const;

    // ---------------------------------------------------------------------
    // Core lambdas (bundled from TS)
    // ---------------------------------------------------------------------

    const authStartFn = new NodejsFunction(this, 'AuthStartFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(5),
      entry: path.join(repoRoot, 'lambda', 'api', 'auth-start.ts'),
      handler: 'handler',
      environment: {
        COGNITO_DOMAIN: cognitoDomain,
        COGNITO_CLIENT_ID: cognitoClientId,
        REDIRECT_URI: redirectUri,
        POST_LOGIN_REDIRECT: '/app/page1.html',

        ...cookieNames,

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueSecretArn,
      },
    });

    const authCallbackFn = new NodejsFunction(this, 'AuthCallbackFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(15),
      entry: path.join(repoRoot, 'lambda', 'api', 'auth-callback.ts'),
      handler: 'handler',
      environment: {
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,

        COGNITO_DOMAIN: cognitoDomain,
        COGNITO_CLIENT_ID: cognitoClientId,
        REDIRECT_URI: redirectUri,

        SESSION_TTL_SECONDS: String(cfCookieTtlSeconds),
        POST_LOGIN_REDIRECT: '/app/page1.html',
        COOKIE_NAME: 'session',

        ...cookieNames,

        /**
         * ✅ NEW SYSTEM (Key Groups):
         * This value is placed into the signed cookie field "CloudFront-Key-Pair-Id".
         * Despite the cookie field name, this is the CloudFront *Public Key ID*.
         */
        CF_PUBLIC_KEY_ID: cfPublicKeyId,

        CF_PRIVATE_KEY_SECRET_ARN: cfPrivateKeySecretArn,
        CF_COOKIE_DOMAIN: cfCookieDomain,
        CF_COOKIE_PATH: cfCookiePath,

        // ✅ Only app resource is passed now
        CF_APP_RESOURCE: cfAppResource,

        CF_COOKIE_TTL_SECONDS: String(cfCookieTtlSeconds),

        CSRF_COOKIE_NAME: '__Host-csrf',
        CSRF_HEADER_NAME: 'X-CSRF-Token',

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueSecretArn,
      },
    });
    props.sessionsTable.grantReadWriteData(authCallbackFn);

    // CloudFront private key (Secrets Manager)
    authCallbackFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:GetSecretValue'],
        resources: [cfPrivateKeySecretArn],
      }),
    );

    const authLogoutFn = new NodejsFunction(this, 'AuthLogoutFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(10),
      entry: path.join(repoRoot, 'lambda', 'api', 'auth-logout.ts'),
      handler: 'handler',
      environment: {
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,
        COOKIE_NAME: 'session',
        CSRF_COOKIE_NAME: '__Host-csrf',

        // must match /auth/start cookie Path
        AUTH_COOKIE_PATH: '/auth',

        ...cookieNames,

        POST_LOGOUT_REDIRECT: `${appBaseUrl}/`,

        COGNITO_DOMAIN: cognitoDomain,
        COGNITO_CLIENT_ID: cognitoClientId,

        CF_COOKIE_DOMAIN: cfCookieDomain,
        CF_COOKIE_PATH: cfCookiePath,

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueSecretArn,
      },
    });
    props.sessionsTable.grantReadWriteData(authLogoutFn);

    const sessionAuthorizerFn = new NodejsFunction(this, 'SessionAuthorizerFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(5),
      entry: path.join(repoRoot, 'lambda', 'api', 'session-authorizer.ts'),
      handler: 'handler',
      environment: {
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,
        COOKIE_NAME: 'session',

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueSecretArn,
      },
    });
    props.sessionsTable.grantReadData(sessionAuthorizerFn);

    const meFn = new NodejsFunction(this, 'MeFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(10),
      entry: path.join(repoRoot, 'lambda', 'api', 'me.ts'),
      handler: 'handler',
      environment: {
        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueSecretArn,
      },
    });

    // ---------------------------------------------------------------------
    // IAM: allow lambdas to read SSM Parameter Store value
    // We accept a full parameter ARN in settings; easiest is to allow GetParameter on that ARN.
    // ---------------------------------------------------------------------
    const allowReadOriginVerifyParam = (fn: lambda.Function) => {
      fn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['ssm:GetParameter'],
          resources: [originVerifyHeaderValueSecretArn],
        }),
      );
    };

    allowReadOriginVerifyParam(authStartFn);
    allowReadOriginVerifyParam(authCallbackFn);
    allowReadOriginVerifyParam(authLogoutFn);
    allowReadOriginVerifyParam(sessionAuthorizerFn);
    allowReadOriginVerifyParam(meFn);

    // ---------------------------------------------------------------------
    // HTTP API + Integrations
    // ---------------------------------------------------------------------
    this.httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: `${projectName}-${stage}-http-api`,
    });

    const startIntegration = new apigwv2Integrations.HttpLambdaIntegration('StartIntegration', authStartFn);
    const callbackIntegration = new apigwv2Integrations.HttpLambdaIntegration('CallbackIntegration', authCallbackFn);
    const logoutIntegration = new apigwv2Integrations.HttpLambdaIntegration('LogoutIntegration', authLogoutFn);
    const meIntegration = new apigwv2Integrations.HttpLambdaIntegration('MeIntegration', meFn);

    const authorizer = new apigwv2Authorizers.HttpLambdaAuthorizer('SessionAuthorizer', sessionAuthorizerFn, {
      responseTypes: [apigwv2Authorizers.HttpLambdaResponseType.SIMPLE],
      identitySource: ['$request.header.Cookie'],
    });

    this.httpApi.addRoutes({
      path: '/auth/start',
      methods: [apigwv2.HttpMethod.GET],
      integration: startIntegration,
    });

    this.httpApi.addRoutes({
      path: '/auth/callback',
      methods: [apigwv2.HttpMethod.GET],
      integration: callbackIntegration,
    });

    this.httpApi.addRoutes({
      path: '/auth/logout',
      methods: [apigwv2.HttpMethod.GET],
      integration: logoutIntegration,
    });

    this.httpApi.addRoutes({
      path: '/api/me',
      methods: [apigwv2.HttpMethod.GET],
      integration: meIntegration,
      authorizer,
    });

    // ---------------------------------------------------------------------
    // Extra authenticated endpoints (user-provided Lambda ARNs)
    // ---------------------------------------------------------------------
    for (const r of props.extraApiRoutes ?? []) {
      const routePath = (r.path ?? '').trim();
      const methodRaw = (r.method ?? '').trim().toUpperCase();
      const lambdaArn = (r.lambdaArn ?? '').trim();

      if (!routePath.startsWith('/api/')) throw new Error(`extraApiRoutes path must start with "/api/": ${routePath}`);
      if (routePath.startsWith('/auth/')) throw new Error(`extraApiRoutes cannot register under "/auth/": ${routePath}`);
      if (!lambdaArn.startsWith('arn:aws:lambda:'))
        throw new Error(`extraApiRoutes lambdaArn must be a Lambda ARN: ${lambdaArn}`);

      const allowed = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);
      if (!allowed.has(methodRaw))
        throw new Error(`extraApiRoutes method not allowed: ${methodRaw} (path: ${routePath})`);

      const fn = lambda.Function.fromFunctionArn(this, `ExtraFn${this.sanitizeId(routePath)}${methodRaw}`, lambdaArn);
      const integration = new apigwv2Integrations.HttpLambdaIntegration(
        `ExtraIntegration${this.sanitizeId(routePath)}${methodRaw}`,
        fn,
      );

      this.httpApi.addRoutes({
        path: routePath,
        methods: [methodRaw as apigwv2.HttpMethod],
        integration,
        authorizer,
      });
    }

    new cdk.CfnOutput(this, 'ApiEndpoint', { value: this.httpApi.apiEndpoint });
    new cdk.CfnOutput(this, 'HttpApiId', { value: this.httpApi.httpApiId });
  }

  private sanitizeId(input: string): string {
    return input.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 64);
  }
}
