# cuddly-fishstick

cuddly-fishstick is a production-grade serverless web foundation for developers who think with AI.

It provides a secure, cost-effective AWS backend with strict boundaries and fail-closed defaults, while deliberately exposing web primitives (HTML, CSS, and JavaScript) without framework-level abstraction.

The platform exists to protect identity, trust, and isolation, so you can focus on building the website and logic without compromising security.

## Philosophy

Modern AI is not a feature. It is a cognitive extension.

This project is built for the augmented mind: people who use AI to reason, explore, and build deliberately.

Platforms should not sell intelligence back to users. The job is to provide structure, guardrails, and legible primitives so you can create without breaking the system.

**Freedom inside the box. Safety at the edges.**

## What this is

A secure, production-grade serverless baseline for shipping websites and small products without inheriting architectural debt.

The system is built around a strict separation of responsibility:
*   The platform owns security boundaries. Identity, sessions, origin trust, CSRF, isolation, and fail-closed defaults are enforced centrally and cannot be bypassed.
*   You own the experience and business logic. HTML, CSS, JavaScript, and application behavior remain fully under your control, without framework-level abstraction.

It includes a user extension model that lets you add authenticated /api/* endpoints safely, using Lambda functions as glue without re-implementing or weakening the security model.

## Who this is for (and who it is not)

This project is not about building faster by hiding complexity. It removes unnecessary abstraction so the developer remains responsible for logic and intent, while the infrastructure provides guardrails that make mistakes hard and violations fail closed.

Accordingly, this is not:
*   Next.js
*   Vercel
*   A CMS
*   Low-code or no-code
*   Prompt-only application building
*   Beginner-friendly tooling
*   A replacement for learning how the web works

This is for builders who want clarity over convenience, responsibility over automation, and control without sacrificing safety.

## Threat model (the assumptions)

This template assumes:
*   The browser is untrusted.
*   The network is untrusted.
*   User code is fallible.
*   Any missing control must fail closed.

And it designs accordingly:
*   CloudFront is part of the security boundary, not just a CDN.
*   Direct origin access is treated as hostile.
*   Auth is centralized.
*   CSRF is enforced centrally.
*   User endpoints cannot bypass platform checks.

## Architecture at a glance

### Request lifecycle

1. **Browser → CloudFront**
1. CloudFront enforces:
     *   Signed cookies for protected paths
     *   Strict response security headers
1. **CloudFront → API Gateway** includes an **origin verify header** (secret in SSM)
1. **API Gateway Lambda Authorizer** validates session cookie against DynamoDB
1. **secureHttp() wrapper** enforces:
     *   Origin verification (CloudFront-only)
     *   Auth context presence
     *   CSRF token match for unsafe methods
     *   JSON body parsing + safe response shape
1. Your business code runs with a minimal, explicit context

### Storage

*   **DynamoDB**
    *   `sessions` table with TTL
    *   `user-profile` table for stable opaque user IDs
*   **S3**
    *   `siteBucket` for static site content
    *   `usersBucket` for per-user artifacts (`/u/*`, theme files)

## Repository layout

This repository contains **infra only**. I will provide the website example shortly.

Typical long-term structure:
*   `infra/` (this repo)
    *   CDK stacks, lambdas, platform security
    *   user extension registration under `infra/user/`
*   `website/` (separate repo)
    *   pure HTML/CSS/JS content
    *   deployed to the `siteBucket`

Why split repos:
*   Website iteration is fast and disposable.
*   Infrastructure changes are slow and deliberate.
*   Your design experiments should not drift the security model.

## Stacks

This app deploys four stacks:

*   **DataStack**
    *   DynamoDB sessions table (TTL)
    *   DynamoDB user profile table (stable opaque id)
    *   Private S3 buckets: site + users

*   **AuthStack**
    *   Cognito User Pool + Hosted UI custom domain (`auth.<rootDomain>`)
    *   OAuth code grant with PKCE

*   **ApiStack**
    *   HTTP API + Lambda Authorizer
    *   Auth handlers (`/auth/start`, `/auth/callback`, `/auth/logout`)
    *   Core API (`/api/me`, `/api/theme`)
    *   User extension loader and registrar

*   **WebStack**
    *   CloudFront distribution with:
        *   custom domain and terminating TLS
        *   Routing traffic to private origins based on path
        *   private S3 origins via OAC
        *   API origin with secret origin-verify header
        *   strict security headers (CSP, HSTS, etc)
        *   signed-cookie protection for `/app/*` and `/u/*`
        *   CloudFront Function that rewrites `/u/me/*` → `/u/<opaque>/*` and denies direct opaque paths

## Security boundaries (the guarantees)

### CloudFront gates capability

*   `/app/*` is protected by **CloudFront signed cookies**.
*   `/u/*` is protected by **CloudFront signed cookies** and is **no-store**.

### Only CloudFront is allowed to call the API

All auth and API lambdas enforce an **origin verify header**. If the request is not coming through CloudFront, it fails.

### Sessions are server-side

*   The browser holds a session id cookie.
*   The server stores session state in DynamoDB with TTL.

### CSRF is non-optional

Unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) require:

*   CSRF cookie (not HttpOnly)
*   Matching CSRF header

User endpoints cannot bypass this.

### User endpoints are wrapped, not trusted

User handlers are never invoked directly. ApiStack generates a tiny platform-owned entrypoint that always wraps your `business` export with `secureHttp()`.

## Configuration

This project reads configuration from a settings file discovered by `infra/bin/infra-helpers`.

Create the settings file and populate values. You must set these requirements inside your AWS account before deployment.

```json
{
  "projectName": "cuddly-fishstick",
  "stage": "dev",
  "enableWaf": false,

  "domain": "example.com",
  "certArnUsEast1": "arn:aws:acm:us-east-1:123456789012:certificate/xxxx",

  "cfPublicKeyId": "Kxxxxxxxxxxxx",
  "cfPrivateKeySecretArn": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:cloudfront/private-key-xxxxx",

  "cfCookieDomain": ".example.com",
  "cfCookiePath": "/",
  "cfCookieTtlSeconds": 3600,

  "originVerifyHeaderName": "X-Origin-Verify",
  "originVerifyHeaderValueParameterArn": "arn:aws:ssm:REGION:ACCOUNT:parameter/shared/origin-verify"
}
```

### Notes on the required fields

*   `domain`
    *   Public app domain served by CloudFront.
    *   Can be apex (`example.com`) or `www.example.com`.

*  `certArnUsEast1`
    *   Used by CloudFront and Cognito custom domains.
    *   Both services require ACM certificates issued in `us-east-1`.


*   `cfPublicKeyId` and `cfPrivateKeySecretArn`
    *   Used to mint CloudFront signed cookies on login.
    *   Public key lives in CloudFront Key Groups.
    *   Private key stays in Secrets Manager.

*   `originVerifyHeaderValueParameterArn`
    *   SSM parameter that holds the secret value CloudFront injects into origin requests.
    *   Lambdas read this parameter and fail if the header is missing or incorrect.

## DNS and certificates

**This project requires a custom domain.**

### Before your first deploy

*   You need a domain you control.
*   You need DNS access.
*   An ACM certificate for your app domain `<rootDomain>` or `www.<rootDomain>` and for the Cognito Hosted UI domain `auth.<rootDomain>`.

**Important:** If your DNS provider supports ALIAS / ANAME / flattening, use it, otherwise, you will need to **avoid the canonical name and use www instead**.

### Practical deployment tip:

Cognito validates the custom domain during deployment. If the domain does not resolve, deployment will fail.

192.0.2.1 is a reserved documentation IP and is safe to use as a temporary target. So, if you don't have an A record, create a temporary placeholder so the domain resolves.

```
A   example.com   →   192.0.2.1
```

### After deployment

*   Point your app domain to the CloudFront distribution domain.

#### If your DNS supports apex flattening (ALIAS/ANAME):
```
ALIAS/ANAME example.com → dxxxx.cloudfront.net
```
#### If your DNS does not support flattening at the apex:
```
CNAME www.example.com → dxxxx.cloudfront.net
(and redirect example.com → www.example.com)
```

*   Point `auth.<rootDomain>` to the Cognito custom domain target.
```
CNAME or ALIAS/ANAME auth.example.com → <cognito-domain-output>
```

## Extending the API (user extension model)

The platform expects a downstream module that exports:

```ts
export function register(ctx: UserExtensionCtx): void
```

Example:

*   Create endpoints with `ctx.endpoint.createUserEndpoint({...})`
*   Register routes with `ctx.api.registerApiRoute({...})`

Rules enforced by the platform:

*   Paths must be under `/api/`.
*   `/auth/*` is reserved.
*   Methods are allowlisted.
*   Required platform environment variables cannot be overridden.
*   Keys starting with the platform prefix are reserved.
*   All user endpoints are automatically authenticated.
*   CSRF is enforced automatically for unsafe methods.

Your business code stays clean:

```ts
export const business: SecureHttpBusinessFn = async (ctx, input) => {
  return {
    message: "ok",
    user_sub: ctx.user_sub,
    received: input.body ?? null,
  };
};
```

## Roadmap

*   Session TTL 10 minutes and Auto-refresh cookies
*   Error pages and CloudFront routing for:
    *   unauthorized
    *   forbidden
    *   not found

## License

MIT. See `LICENSE`.
