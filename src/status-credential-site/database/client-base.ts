import { VerifiableCredential } from '@digitalcredentials/vc-data-model';
import { env } from '../util';

// Database service
export enum DatabaseService {
  MongoDb = 'mongodb'
}

// Type definition for status credential record
export interface StatusCredentialRecord {
  id: string;
  credential: VerifiableCredential;
}

// Type definition for BaseDatabaseClient constructor method input
export interface BaseDatabaseClientOptions {
  databaseName: string;
  databaseUrl: string;
  statusCredentialTableName: string;
}

// Base class for database clients
export abstract class BaseDatabaseClient {
  protected databaseName: string;
  protected databaseUrl: string;
  protected statusCredentialTableName: string;

  constructor() {
    this.databaseName = env.DB_NAME;
    this.databaseUrl = env.DB_URL;
    this.statusCredentialTableName = env.DB_STATUS_CREDENTIAL_TABLE;
  }

  // retrieves single database record by field
  abstract getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T | null>;

  // retrieves multiple database records by field
  abstract getRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T[]>;

  // retrieves single database record by id
  async getRecordById<T>(tableName: string, id: string): Promise<T | null> {
    return this.getRecordByField(tableName, 'id', id);
  }

  // retrieves status credential record by ID
  async getStatusCredentialRecordById(statusCredentialId: string): Promise<StatusCredentialRecord | null> {
    const record = await this.getRecordById(this.statusCredentialTableName, statusCredentialId);
    return record as StatusCredentialRecord;
  }

  // retrieves status credential by ID
  async getStatusCredential(statusCredentialId: string): Promise<VerifiableCredential | null> {
    const statusCredentialRecord = await this.getStatusCredentialRecordById(statusCredentialId);
    if (statusCredentialRecord) {
      const { credential } = statusCredentialRecord;
      return credential;
    }
    return null;
  }
}
