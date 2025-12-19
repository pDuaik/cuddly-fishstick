import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AppConfig {
  projectName: string;
  stage: string;
  domainName?: string;
  hostedZoneName?: string;
  enableCustomDomain: boolean;
  enableWaf: boolean;
}

export interface InfraStackProps extends cdk.StackProps {
  config: AppConfig;
}

export class InfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: InfraStackProps) {
    super(scope, id, props);

    // Example: use props.config safely
    // console.log(props.config);
  }
}