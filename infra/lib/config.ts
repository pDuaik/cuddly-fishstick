// lib/config.ts
export interface AppConfig {
  projectName: string;
  stage: string;
  domain: string;
  certArnUsEast1: string;
  websitePath: string;
  enableWaf: boolean;
}
