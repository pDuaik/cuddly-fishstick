import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import type { AppConfig } from './config';

export interface DataStackProps extends cdk.StackProps {
  config: AppConfig;
  removalPolicy?: cdk.RemovalPolicy;
}

export class DataStack extends cdk.Stack {
  public readonly sessionsTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const { projectName, stage } = props.config;
    const removalPolicy = props.removalPolicy ?? cdk.RemovalPolicy.DESTROY;

    this.sessionsTable = new dynamodb.Table(this, 'SessionsTable', {
      tableName: `${projectName}-${stage}-sessions`,
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'expires_at',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy,
    });

    new cdk.CfnOutput(this, 'SessionsTableName', { value: this.sessionsTable.tableName });
    new cdk.CfnOutput(this, 'SessionsTableArn', { value: this.sessionsTable.tableArn });
  }
}
