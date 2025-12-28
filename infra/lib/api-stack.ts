// infra/lib/api-stack.ts
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
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { UserExtensionCtx, UserApiMethod } from './user-extension';
import * as user from '../user/index';

export interface ApiStackProps extends cdk.StackProps {
  config: AppConfig;

  sessionsTable: dynamodb.ITable;

  usersBucket: s3.IBucket;
  userProfileTable: dynamodb.ITable;

  cognitoDomain: string;
  cognitoClientId: string;

  cfPublicKeyId: string;
  cfPrivateKeySecretArn: string;

  cfCookieDomain: string;
  cfCookiePath?: string; // default "/"
  cfCookieTtlSeconds?: number; // default 3600

  originVerifyHeaderName: string; // default "X-Origin-Verify"
  originVerifyHeaderValueParameterArn: string;
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
    const originVerifyHeaderValueParameterArn = requireNonEmpty(
      'originVerifyHeaderValueParameterArn',
      props.originVerifyHeaderValueParameterArn,
    );

    const appBaseUrl = `https://${domain}`;
    const redirectUri = `${appBaseUrl}/auth/callback`;

    const cfCookiePath = (props.cfCookiePath ?? '/').trim() || '/';
    const cfCookieTtlSeconds = props.cfCookieTtlSeconds ?? 3600;

    // ✅ Stage 1: sign domain
    const cfResource = `${appBaseUrl}/*`;

    const cookieNames = {
      OAUTH_STATE_COOKIE_NAME: 'oauth_state',
      PKCE_VERIFIER_COOKIE_NAME: 'pkce_verifier',
      POST_LOGIN_COOKIE_NAME: 'post_login',
    };

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
    // IAM: allow lambdas to read SSM Parameter Store value
    // ---------------------------------------------------------------------
    const allowReadOriginVerifyParam = (fn: lambda.Function) => {
      fn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['ssm:GetParameter'],
          resources: [originVerifyHeaderValueParameterArn],
        }),
      );
    };

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
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(authStartFn);

    const authCallbackFn = new NodejsFunction(this, 'AuthCallbackFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(15),
      entry: path.join(repoRoot, 'lambda', 'api', 'auth-callback.ts'),
      handler: 'handler',
      environment: {
        // Sessions
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,

        // user profile table for opaque id resolution
        USER_PROFILE_TABLE_NAME: props.userProfileTable.tableName,
        // optional override if you want to change the cookie name later
        OPAQUE_ID_COOKIE_NAME: '__Host-uk',

        COGNITO_DOMAIN: cognitoDomain,
        COGNITO_CLIENT_ID: cognitoClientId,
        REDIRECT_URI: redirectUri,

        SESSION_TTL_SECONDS: String(cfCookieTtlSeconds),
        POST_LOGIN_REDIRECT: '/app/page1.html',
        COOKIE_NAME: 'session',

        ...cookieNames,

        CF_PUBLIC_KEY_ID: cfPublicKeyId,

        CF_PRIVATE_KEY_SECRET_ARN: cfPrivateKeySecretArn,
        CF_COOKIE_DOMAIN: cfCookieDomain,
        CF_COOKIE_PATH: cfCookiePath,

        CF_APP_RESOURCE: cfResource,
        CF_COOKIE_TTL_SECONDS: String(cfCookieTtlSeconds),

        CSRF_COOKIE_NAME: '__Host-csrf',
        CSRF_HEADER_NAME: 'X-CSRF-Token',

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(authCallbackFn);

    // DynamoDB permissions
    props.sessionsTable.grantReadWriteData(authCallbackFn);
    props.userProfileTable.grantReadWriteData(authCallbackFn);

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

        AUTH_COOKIE_PATH: '/auth',

        ...cookieNames,

        POST_LOGOUT_REDIRECT: `${appBaseUrl}/`,

        COGNITO_DOMAIN: cognitoDomain,
        COGNITO_CLIENT_ID: cognitoClientId,

        CF_COOKIE_DOMAIN: cfCookieDomain,
        CF_COOKIE_PATH: cfCookiePath,

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(authLogoutFn);
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
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(sessionAuthorizerFn);
    props.sessionsTable.grantReadData(sessionAuthorizerFn);

    const meFn = new NodejsFunction(this, 'MeFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(10),
      entry: path.join(repoRoot, 'lambda', 'api', 'me.ts'),
      handler: 'handler',
      environment: {
        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(meFn);

    const updateThemeFn = new NodejsFunction(this, 'UpdateThemeFn', {
      ...lambdaDefaults,
      timeout: cdk.Duration.seconds(10),
      entry: path.join(repoRoot, 'lambda', 'api', 'update-theme.ts'),
      handler: 'handler',
      environment: {
        USER_PROFILE_TABLE_NAME: props.userProfileTable.tableName,
        USERS_BUCKET_NAME: props.usersBucket.bucketName,

        CSRF_COOKIE_NAME: '__Host-csrf',
        CSRF_HEADER_NAME: 'X-CSRF-Token',

        ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
        ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      },
    });
    allowReadOriginVerifyParam(updateThemeFn);
    props.userProfileTable.grantReadData(updateThemeFn);
    props.usersBucket.grantPut(updateThemeFn, 'u/*');

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
    const updateThemeIntegration = new apigwv2Integrations.HttpLambdaIntegration('UpdateThemeIntegration', updateThemeFn);

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

    this.httpApi.addRoutes({
      path: '/api/theme',
      methods: [apigwv2.HttpMethod.POST],
      integration: updateThemeIntegration,
      authorizer,
    });

    // ---------------------------------------------------------------------
    // User extension: factory + registrar + discovery
    // ---------------------------------------------------------------------

    const featuresScope = new Construct(this, 'UserFeatures');

    const requiredUserEnv = {
      ORIGIN_VERIFY_HEADER_NAME: originVerifyHeaderName,
      ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: originVerifyHeaderValueParameterArn,
      CSRF_COOKIE_NAME: '__Host-csrf',
      CSRF_HEADER_NAME: 'X-CSRF-Token',
    } as const;

    const createUserLambda: UserExtensionCtx['lambda']['createUserLambda'] = (input) => {
      const idRaw = (input?.id ?? '').toString().trim();
      const entryRaw = (input?.entry ?? '').toString().trim();
      const handler = (input?.handler ?? 'handler').toString().trim() || 'handler';

      if (!idRaw) throw new Error('createUserLambda: "id" is required.');
      if (!entryRaw) throw new Error(`createUserLambda(${idRaw}): "entry" is required.`);

      const userEnv = (input.environment ?? {}) as Record<string, string>;

      // user cannot override required vars
      for (const k of Object.keys(requiredUserEnv)) {
        if (k in userEnv) {
          throw new Error(`createUserLambda(${idRaw}): environment cannot override required var "${k}".`);
        }
      }

      const fn = new NodejsFunction(featuresScope, idRaw, {
        ...lambdaDefaults,
        entry: entryRaw,
        handler,
        timeout:
          typeof input.timeoutSeconds === 'number' && Number.isFinite(input.timeoutSeconds)
            ? cdk.Duration.seconds(input.timeoutSeconds)
            : lambdaDefaults.timeout,
        memorySize:
          typeof input.memorySizeMb === 'number' && Number.isFinite(input.memorySizeMb)
            ? input.memorySizeMb
            : lambdaDefaults.memorySize,
        environment: {
          ...userEnv,
          ...requiredUserEnv,
        },
      });

      allowReadOriginVerifyParam(fn);

      return fn;
    };

    const allowedMethods = new Set<string>(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

    const normalizeMethod = (m: UserApiMethod): apigwv2.HttpMethod => {
      const s = String(m ?? '').trim().toUpperCase();
      if (!allowedMethods.has(s)) throw new Error(`registerApiRoute: method not allowed: ${s}`);
      return s as apigwv2.HttpMethod;
    };

    const registerApiRoute: UserExtensionCtx['api']['registerApiRoute'] = (input) => {
      const routePath = (input?.path ?? '').toString().trim();

      if (!routePath.startsWith('/api/')) {
        throw new Error(`registerApiRoute: path must start with "/api/": ${routePath}`);
      }
      if (routePath.startsWith('/auth/')) {
        throw new Error(`registerApiRoute: cannot register under "/auth/": ${routePath}`);
      }

      const methodsRaw = input?.methods ?? [];
      if (!Array.isArray(methodsRaw) || methodsRaw.length === 0) {
        throw new Error(`registerApiRoute(${routePath}): methods must be a non-empty array.`);
      }

      const fn = input?.fn;
      if (!fn) throw new Error(`registerApiRoute(${routePath}): "fn" is required.`);

      const methods = methodsRaw.map(normalizeMethod);

      const integration = new apigwv2Integrations.HttpLambdaIntegration(
        `UserIntegration${this.sanitizeId(routePath)}${methods.join('')}`,
        fn,
      );

      this.httpApi.addRoutes({
        path: routePath,
        methods,
        integration,
        authorizer, // ✅ always authenticated
      });
    };

    const ctx: UserExtensionCtx = {
      featuresScope,
      lambda: { createUserLambda },
      api: { registerApiRoute },
      HttpMethod: apigwv2.HttpMethod,
    };

    // Static import, no scanning. User module should export `register(ctx)`.
    user.register(ctx);

    new cdk.CfnOutput(this, 'ApiEndpoint', { value: this.httpApi.apiEndpoint });
    new cdk.CfnOutput(this, 'HttpApiId', { value: this.httpApi.httpApiId });
  }

  private sanitizeId(input: string): string {
    return input.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 64);
  }
}
