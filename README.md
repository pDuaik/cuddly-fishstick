# cuddly-fishstick

A reusable AWS CDK template for static websites with Cognito login, server-side API sessions, and CloudFront-protected content.

The repository contains infrastructure and example API business functions. Website files and their upload workflow belong to the consuming project. Each deployment serves one configured app domain.

## Architecture

Four stacks separate responsibilities:

- **DataStack:** private site/user S3 buckets, a DynamoDB sessions table with TTL, and a user-profile table mapping Cognito subjects to stable opaque IDs.
- **AuthStack:** Cognito user pool, OAuth authorization-code client, and Hosted UI custom domain.
- **ApiStack:** auth handlers, HTTP API, session authorizer, shared HTTP wrappers, and application extensions.
- **WebStack:** CloudFront, OAC, signed-cookie key group, response headers, user-path verification, and the two consolidated bucket policies.

| Viewer path | Origin | Access |
| --- | --- | --- |
| Default, including / | Site S3 | Public; normal CDN caching |
| /config/* | Site S3 | Public; no-store |
| /app/* | Site S3 | CloudFront signed cookies; no-store |
| /u/me/* | Users S3 | CloudFront signed cookies plus an authenticated user-selection cookie; no-store |
| /auth/* | HTTP API | Origin verification and route-specific OAuth checks |
| Private /api/* | HTTP API | Origin verification, server-side session, CSRF on unsafe methods |
| /api/public/* | HTTP API | Origin verification; unauthenticated GET/HEAD/OPTIONS |

All S3 buckets block public access. Their policies grant CloudFront read access only to the deployment's distribution through OAC. API Gateway remains network-reachable; Lambda handlers reject requests without the CloudFront-injected origin secret. This check is separate from the session check.

The edge function authenticates the opaque user ID, expiry and app host using HMAC-SHA256 before rewriting /u/me/* to /u/<opaque>/*. A modified or unsigned cookie, expired cookie, direct opaque path or traversal path is rejected. The HMAC uses the existing origin-verification secret with a distinct message purpose. That secret is therefore part of the trust boundary for both origin verification and per-user static reads.

## Authentication and sessions

Login starts at /auth/start, creates short-lived state/PKCE cookies and redirects to Cognito. Callback exchanges the code directly with Cognito over HTTPS, validates the ID-token claims, resolves the user profile and prepares signed cookies before persisting a session.

Cognito access, ID and refresh tokens stay in DynamoDB. The browser receives an HttpOnly session cookie, an authenticated HttpOnly user-selection cookie, a readable CSRF cookie and the CloudFront signed-cookie set. Private API routes perform strongly consistent session reads with authorizer caching disabled.

The default session and signed-cookie lifetime is one hour, configurable with cfCookieTtlSeconds. Cognito access/ID tokens last fifteen minutes. Refresh tokens are stored, but automatic refresh is not implemented.

Static cookies are bearer grants with their own expiry. Deleting an API session does not immediately revoke copies of already-issued static cookies. Logout clears browser credentials and deletes the API session; failed session deletion returns 503 instead of reporting success. GET /auth/logout remains available for existing website links.

## Configuration

Copy [settings.example.json](settings.example.json) to **settings.json at the repository root**, then replace the placeholder values. The local settings file is ignored by Git.

| Setting | Purpose |
| --- | --- |
| projectName / stage | Resource names; defaults to cuddly-fishstick / dev |
| domain | App DNS hostname, without scheme, port or path |
| certArnUsEast1 | Existing ACM certificate in us-east-1 covering app and Cognito custom domains |
| cfPublicKeyId | Existing CloudFront public key used by the trusted key group |
| cfPrivateKeyParameterArn | Existing SSM SecureString containing the corresponding signing private key |
| cfCookieDomain | App domain or its parent cookie domain |
| cfCookiePath | Must be / to cover both protected path families |
| cfCookieTtlSeconds | Positive integer lifetime; defaults to 3600 |
| originVerifyHeaderName | Custom header name; defaults to X-Origin-Verify |
| originVerifyHeaderValueParameterArn | Existing SSM **String** containing the shared origin-verification value |
| allowedFrameSrc / allowedConnectSrc | Extra HTTPS origins, blob: or data: allowed by those CSP directives |

Use a cryptographically random origin value (for example, 32 random bytes encoded as base64url), without surrounding whitespace. The Web stack reads it through an SSM parameter-value CloudFormation parameter. It Base64-encodes the resolved value before inserting it into function code, preventing code injection. Base64 is an encoding, not encryption: AWS principals allowed to retrieve distribution configuration or function code can access that value. Do not publish synthesized/deployed secret-bearing configuration.

The signing private key remains in SSM SecureString and is fetched with decryption by the callback. Raw PEM and JSON containing private_key, privateKey or key are supported. The supplied Lambda policy grants ssm:GetParameter; using a customer-managed KMS key also requires an appropriate kms:Decrypt grant and key policy.

SSM parameters must be in the deployment account/region. No Secrets Manager resource or client is used. The old cfPrivateKeySecretArn field is rejected with a migration message. The previous enableWaf flag has no implementation.

## DNS and deployment

The app requires DNS you control and a validated ACM certificate in us-east-1. Cognito's custom domain is auth.<app-domain>, with a leading www. removed from the app domain. For example, www.example.com uses auth.example.com; app.example.com uses auth.app.example.com.

Before first deployment, make the parent of the Cognito custom domain resolve with an A record. After deployment:

- Point the app domain to WebStack's CloudFrontDomainName output using your provider's appropriate CNAME or apex ALIAS/ANAME mechanism.
- Point the Cognito custom domain to AuthStack's CognitoCloudFrontDistribution output.

Work from infra/:

```sh
npm ci
npm run build
npm test
npm run synth
npx cdk diff --all
npx cdk deploy --all
```

The CDK app runs TypeScript directly; build output goes to infra/dist/. Account and region come from the CDK environment. The default landing page is /app/page1.html; the consuming website must provide it or use /auth/start?next=/app/another-page.html.

Upload website content separately to SiteBucketName. Use DistributionId for any public-asset invalidations. /config/* is public and must not contain credentials.

**Existing deployments must follow [UPGRADING.md](UPGRADING.md) before deploying these fixes.** Bucket-policy ownership requires a preparatory update, and existing unsigned user cookies require a fresh login.

For prod/production stages, buckets, tables and the Cognito pool default to retention on deletion/replacement. Other stage names retain disposable defaults, including automatic bucket cleanup. Direct CDK consumers can explicitly override removalPolicy. No backups, versioning or point-in-time recovery are enabled automatically.

## Extending the API

Implement register(ctx) in infra/user/index.ts. Create private endpoints through ctx.endpoint.createUserEndpoint() and register them through ctx.api.registerApiRoute(). Business modules export a business function:

```ts
import type { SecureHttpBusinessFn } from '../lambda/api/secure-http';

export const business: SecureHttpBusinessFn = async (ctx, input) => ({
  message: 'ok',
  user_sub: ctx.user_sub,
  received: input.body ?? null,
});
```

The generated entrypoint runs secureHttp: origin verification, authorizer-context checks, CSRF checks for unsafe methods, JSON parsing and response handling. Unsafe browser requests must include X-CSRF-Token matching the __Host-csrf cookie. Return an object, or use httpOverride(statusCode, body) for an explicit JSON response.

Public endpoints use ctx.publicEndpoint.createPublicEndpoint() and ctx.publicApi.registerPublicApiRoute(), with PublicHttpBusinessFn from public-http. Only /api/public/* and GET/HEAD/OPTIONS are allowed. HEAD/OPTIONS return without calling the business function. Public methods do not make side effects inside a GET business function safe.

Registrars verify that the supplied function came from the corresponding factory in the current deployment. Required environment variables and the PLATFORM_ namespace are reserved. Deployment code remains trusted CDK code; these checks catch accidental wiring mistakes and do not sandbox hostile extensions.

ctx.featuresScope is the scope for application resources, and ctx.platform.cognitoUserPoolId exposes the deployment's user pool ID. Grant additional resource access explicitly. The shipped examples are /api/ping, /api/example-auth-call and /api/example-csrf-call; no public example route is enabled by default.

POST /api/theme validates a small CSS-variable allowlist and writes the authenticated user's theme.css. Its write destination is resolved from the session's user_sub, rather than a client-supplied user ID.

## Validation and operational scope

Tests cover auth callbacks and failures, redirects, identity claims, CSRF/origin helper behavior, session reads, cookie signing/edge verification, policy ownership, retention, config validation and extension wiring. CDK wiring tests mock bundling; run synthesis to also bundle the actual handlers.

Origin-secret lookups in Lambda are cached for at most 60 seconds. Updating SSM alone does not update CloudFront or its edge function. Rotation automation and overlapping old/new keys are not implemented; coordinate a maintenance/deployment transition and fresh login if changing this value. Signing-key rotation separately requires overlapping trusted public keys until old cookies expire.

This template does not configure WAF, roles/tenant authorization, automatic token refresh, custom error-page routing, access-log pipelines or recovery policies. Applications must choose their own requirements for those capabilities.

MIT. See [LICENSE](LICENSE).
