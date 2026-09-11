# Upgrading existing deployments

These instructions apply to deployments made before bucket policies were consolidated into WebStack. They are a one-time migration. New deployments use the normal configuration and skip the preparatory context.

The changes preserve bucket/table/user-pool/distribution construct IDs and the existing API routes. Review the CloudFormation diff for each consuming project before deployment; custom downstream modifications can change that outcome.

## Required configuration

Update repository-root settings.json to use cfPrivateKeyParameterArn pointing to the existing **SSM SecureString** signing key. Remove cfPrivateKeySecretArn. Moving from Secrets Manager requires placing the actual matching private key in SSM first; renaming an ARN does not migrate it.

The origin-verification value remains in its existing SSM **String** parameter. Keep its value unchanged during this migration. It now also authenticates user-selection cookies at the edge. No new secret or Secrets Manager service is required.

## Bucket-policy migration

The old template created two CloudFormation policy resources for each bucket: one in DataStack and one in WebStack. Removing a resource with Delete would delete the bucket's actual policy, including permissions managed by the other stack.

The preparatory deployment retains those old DataStack policy resources while applying DeletionPolicy/UpdateReplacePolicy Retain. It also updates WebStack's existing policies to include all SSL, cleanup and exact-distribution OAC statements.

From infra/:

```sh
npm ci
npm run build
npm test
npx cdk diff --all -c prepareBucketPolicyMigration=true
npx cdk deploy --all -c prepareBucketPolicyMigration=true
```

Wait for **every stack in this deployment** to finish successfully. Inspect the DataStack template to confirm the existing bucket-policy resources now have Retain, and confirm the WebStack policies contain the SSL deny and distribution-specific CloudFront allow. If a stack fails, resolve that failure before continuing.

Then deploy normally:

```sh
npx cdk diff --all
npx cdk deploy --all
```

The normal deployment removes only the retained duplicate DataStack policy resources from CloudFormation ownership. The two WebStack policy resources keep their logical IDs and remain the only policy owners. Normal DataStack synthesis contains no AWS::S3::BucketPolicy resources.

**Do not skip the preparatory deployment on an old installation. Do not re-enable prepareBucketPolicyMigration after the migration is complete.** Re-enabling it recreates competing policy owners. Do not store this flag in cdk.json or permanent project configuration.

Use a maintenance window for the migration: independent stack updates can briefly change origin permissions, and the cookie-format transition below can interrupt existing user-file requests.

The Web policies are retained when WebStack is removed. This keeps SSL enforcement for persistent buckets and preserves cleanup permissions while disposable DataStack buckets are deleted. The cleanup provider also receives bucket-scoped identity permissions, so a failed first Web deployment does not prevent DataStack rollback.

## Browser and API compatibility

The following interfaces remain: /auth/start, /auth/callback, GET /auth/logout, the existing /api/* routes, /u/me/*, and the endpoint factory/registrar API.

The __Host-uk cookie changes from a plain opaque ID to a signed, expiring value. Old unsigned cookies deliberately stop working for /u/me/*; users must sign out and sign in again. Deploy the API and Web changes together. During propagation, new cookies are incompatible with the previous edge function and old cookies are rejected by the new function.

Private API authorization is no longer cached for five minutes. Session reads are strongly consistent. Failed login signing returns no new usable session credentials. If session deletion fails during logout, the endpoint returns 503 and retains the session cookie for a retry while clearing the other browser credentials.

Existing extension code must pass functions from the matching factory to each registrar. Raw NodejsFunction instances and mixing public/private factories now fail synthesis; replace that wiring with the documented factories.

## Retention and remaining deployment prerequisites

prod and production now retain buckets, DynamoDB tables and Cognito user pools on deletion/replacement. Other stages retain disposable behavior. Review stage names in every consuming project; a stage called live or staging does not automatically receive the production default. Direct CDK consumers can override removalPolicy explicitly.

Changing the stage can rename resources; do not rename an existing stage as part of this migration merely to obtain retention. Use explicit stack props in such a consuming project.

The template does not create the domain, ACM certificate, CloudFront signing key or SSM parameter values. CloudFront and Cognito both need the us-east-1 certificate. AuthStack now exports CognitoCloudFrontDistribution for the Hosted UI DNS target.

Local regression tests and synthesis verify code and CloudFormation structure. Before serving production traffic, check real login/logout, /api/me, a CSRF-protected write, /app/* and /u/me/theme.css in the target deployment, including a second user and an altered cookie.
