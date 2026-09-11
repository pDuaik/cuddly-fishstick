# Platform infrastructure

This CDK application deploys the Data, Auth, API, and Web stacks. The repository [README](../README.md) describes the request flow and extension model; application endpoints are registered in `user/index.ts`.

## Configure

Copy `settings.example.json` to `settings.json` in the **repository root**, one level above this directory. Replace the example account, domains, certificate, public key ID, and SSM parameter ARNs with your deployment values. The real settings file is ignored by Git.

Both the CloudFront distribution and Cognito custom domain use `certArnUsEast1`. The certificate must be in `us-east-1` and cover the app domain and the derived Cognito domain (`auth.<domain>`, with a leading `www.` removed from the app domain).

The existing signing key and origin verification value are stored in **SSM Parameter Store**:

| Setting | Parameter contents | Parameter type |
| --- | --- | --- |
| `cfPrivateKeyParameterArn` | PEM private key matching `cfPublicKeyId` | `SecureString` |
| `originVerifyHeaderValueParameterArn` | Secret header value shared by CloudFront and the API | `String` |

Use parameters in the deployment account and region. The signing key can use the default SSM encryption key; a customer managed KMS key also requires an appropriate decrypt grant, which this configuration does not provision. The origin value uses `String` because it is resolved into the CloudFront configuration through a CloudFormation SSM parameter value. Restrict access to that parameter and distribution configuration.

`cfPrivateKeySecretArn` is obsolete and rejected. Migrating an existing settings file requires putting the signing key in an SSM parameter and supplying the parameter ARN; renaming a Secrets Manager ARN does not migrate the key. No Secrets Manager resources are required.

Keep `cfCookiePath` as `/` and use a positive integer `cfCookieTtlSeconds`. `cfCookieDomain` must be the app hostname or its parent domain. `allowedFrameSrc` and `allowedConnectSrc` are optional arrays of CSP source strings.

## Local checks

Run from this directory:

```sh
npm ci
npx tsc --noEmit
npm test -- --runInBand
npm run synth
```

Synthesis needs valid root settings and a CDK account/region configuration. It creates CloudFormation templates and bundles the Lambda handlers; it does not deploy them. `npm run diff` compares the templates with deployed stacks. Use `npx cdk deploy --all` when you intend to deploy the configured environment.

Existing installations must follow [UPGRADING.md](../UPGRADING.md) before deploying: the bucket-policy fix requires a one-time preparatory update, and existing users must sign in again for the authenticated user-cookie format.

## Deployment behavior

For stages named `prod` or `production` (case-insensitive), the data buckets, DynamoDB tables, and Cognito user pool default to `RETAIN` on deletion or replacement. Other stages keep disposable defaults, including automatic removal of bucket contents on stack deletion. Direct stack consumers can override `removalPolicy` on DataStack and AuthStack. Retention does not enable backups, object versioning, or recovery from application-level deletion.

The Auth stack outputs `CognitoCloudFrontDistribution`, the DNS target for its custom domain. This target is separate from the Web stack distribution used by the app domain. DNS records and the ACM certificate are managed outside this template.

Changing an SSM value does not automatically redeploy CloudFront. The origin header and API expectation must be changed together; this template does not provide scheduled key or secret rotation. The old `enableWaf` context setting had no implementation and has been removed.
