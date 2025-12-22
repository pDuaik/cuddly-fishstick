import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { AppConfig } from './config';

export interface DataStackProps extends cdk.StackProps {
  config: AppConfig;
  removalPolicy?: cdk.RemovalPolicy;
}

export class DataStack extends cdk.Stack {
  public readonly sessionsTable: dynamodb.Table;
  public readonly siteBucket: s3.Bucket;
  public readonly exampleTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const { projectName, stage } = props.config;
    const removalPolicy = props.removalPolicy ?? cdk.RemovalPolicy.DESTROY;

    // -------------------------
    // DynamoDB: sessions
    // -------------------------
    this.sessionsTable = new dynamodb.Table(this, 'SessionsTable', {
      tableName: `${projectName}-${stage}-sessions`,
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'expires_at',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy,
    });

    // -------------------------
    // DynamoDB: demo counter (CSRF POST example)
    // -------------------------
    this.exampleTable = new dynamodb.Table(this, 'ExampleTable', {
      tableName: `${projectName}-${stage}-example`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy,
    });


    // -------------------------
    // S3: private site bucket (CloudFront will be granted access later via OAC)
    // -------------------------
    this.siteBucket = new s3.Bucket(this, 'SiteBucket', {
      // Intentionally no bucketName: let CloudFormation ensure global uniqueness
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: false,

      // Template/POC friendly defaults; can be overridden per-environment via props
      removalPolicy,
      autoDeleteObjects: removalPolicy === cdk.RemovalPolicy.DESTROY,
    });

    // Outputs
    new cdk.CfnOutput(this, 'SessionsTableName', { value: this.sessionsTable.tableName });
    new cdk.CfnOutput(this, 'SessionsTableArn', { value: this.sessionsTable.tableArn });

    new cdk.CfnOutput(this, 'SiteBucketName', { value: this.siteBucket.bucketName });
    new cdk.CfnOutput(this, 'SiteBucketArn', { value: this.siteBucket.bucketArn });

    new cdk.CfnOutput(this, 'DemoTableName', { value: this.exampleTable.tableName });
    new cdk.CfnOutput(this, 'DemoTableArn', { value: this.exampleTable.tableArn });
  }
}
