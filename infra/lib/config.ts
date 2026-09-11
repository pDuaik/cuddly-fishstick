import * as cdk from 'aws-cdk-lib';

export interface AppConfig {
  projectName: string;
  stage: string;
  domain: string;
  certArnUsEast1: string;
}

/** Production data survives stack deletion/replacement; disposable stages keep their existing behavior. */
export function defaultRemovalPolicy(stage: string): cdk.RemovalPolicy {
  return ['prod', 'production'].includes(stage.trim().toLowerCase())
    ? cdk.RemovalPolicy.RETAIN
    : cdk.RemovalPolicy.DESTROY;
}
