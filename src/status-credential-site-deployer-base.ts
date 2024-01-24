// Type definition for BaseStatusCredentialSiteDeployer constructor method input
export interface BaseStatusCredentialSiteDeployerOptions {
  DB_SERVICE: string;
  DB_NAME: string;
  DB_URL: string;
  DB_STATUS_CRED_TABLE_NAME: string;
}

// Base class for status credential site deployer
export abstract class BaseStatusCredentialSiteDeployer {
  protected readonly databaseService: string;
  protected readonly databaseName: string;
  protected readonly databaseUrl: string;
  protected readonly statusCredentialTableName: string;

  constructor(options: BaseStatusCredentialSiteDeployerOptions) {
    const {
      DB_SERVICE,
      DB_NAME,
      DB_URL,
      DB_STATUS_CRED_TABLE_NAME
    } = options;
    this.databaseService = DB_SERVICE;
    this.databaseName = DB_NAME;
    this.databaseUrl = DB_URL;
    this.statusCredentialTableName = DB_STATUS_CRED_TABLE_NAME;
  }

  // runs deployment script for site hosting service
  abstract run(): Promise<string>;
}
