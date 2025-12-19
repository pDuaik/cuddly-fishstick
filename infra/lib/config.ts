export interface AppConfig {
  projectName: string;
  stage: string;
  domainName?: string;
  hostedZoneName?: string;
  enableCustomDomain: boolean;
  enableWaf: boolean;
}
