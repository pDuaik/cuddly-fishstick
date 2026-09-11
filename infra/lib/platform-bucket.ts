import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';

// Bucket calls addToResourcePolicy during super(), before subclass fields initialize.
const documents = new WeakMap<s3.IBucket, iam.PolicyDocument>();

/**
 * Collect bucket statements for the WebStack's single policy owner. This avoids
 * a Data -> Web dependency while preserving SSL and CDK cleanup permissions.
 */
export class PlatformBucket extends s3.Bucket {
  constructor(scope: Construct, id: string, props: s3.BucketProps) {
    super(scope, id, props);
    this.node.addValidation({ validate: () => this.resourcePolicyDocument.validateForResourcePolicy() });

    if (props.autoDeleteObjects) {
      const provider = cdk.Stack.of(this).node.tryFindChild('Custom::S3AutoDeleteObjectsCustomResourceProvider');
      if (!(provider instanceof cdk.CustomResourceProviderBase)) {
        throw new Error('PlatformBucket could not locate the CDK S3 cleanup provider. Its identity permissions are required before WebStack creates the bucket policy.');
      }
      // DataStack must also be deletable if WebStack never deployed successfully.
      // CDK normally grants these permissions only through the bucket policy.
      provider.addToRolePolicy({
        Effect: 'Allow',
        Action: ['s3:PutBucketPolicy', 's3:GetBucket*', 's3:List*', 's3:DeleteObject*'],
        Resource: [this.bucketArn, this.arnForObjects('*')],
      });
    }
  }

  get resourcePolicyDocument(): iam.PolicyDocument {
    let document = documents.get(this);
    if (!document) {
      document = new iam.PolicyDocument();
      documents.set(this, document);
    }
    return document;
  }

  override addToResourcePolicy(statement: iam.PolicyStatement): iam.AddToResourcePolicyResult {
    this.resourcePolicyDocument.addStatements(statement);
    return { statementAdded: true };
  }
}

/** Only for the first, preparatory deployment of an existing installation. */
export function prepareBucketPolicyMigration(scope: Construct): boolean {
  const value = scope.node.tryGetContext('prepareBucketPolicyMigration');
  return value === true || value === 'true';
}

export function bucketPolicyDocument(bucket: s3.IBucket): iam.PolicyDocument {
  if (bucket instanceof PlatformBucket) return bucket.resourcePolicyDocument;
  // The migration deployment keeps the old DataStack resources long enough to
  // persist Retain. Removing them in the next deployment must not delete S3's policy.
  if (prepareBucketPolicyMigration(bucket) && bucket.policy) {
    bucket.policy.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    return iam.PolicyDocument.fromJson(bucket.policy.document.toJSON());
  }
  throw new Error('WebStack requires PlatformBucket instances (or existing buckets during policy migration).');
}
