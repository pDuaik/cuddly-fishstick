export interface AppConfig {
  projectName: string;
  stage: string;
  domain: string;
  cloudFrontCertArnUsEast1: string;
  cognitoDomainCertArn: string;
  enableWaf: boolean;
}
