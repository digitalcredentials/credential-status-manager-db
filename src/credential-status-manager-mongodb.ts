import dns from 'dns';
import { Db, Document, MongoClient } from 'mongodb';
import {
  BASE_MANAGER_REQUIRED_OPTIONS,
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions
} from './credential-status-manager-base.js';
import { BadRequestError } from './errors.js';
import { DidMethod } from './helpers.js';

// Implementation of BaseCredentialStatusManager for MongoDB
export class MongoDbCredentialStatusManager extends BaseCredentialStatusManager {
  private client!: MongoClient;

  constructor(options: BaseCredentialStatusManagerOptions) {
    const {
      statusCredentialTableName,
      configTableName,
      eventTableName,
      credentialEventTableName,
      databaseName,
      databaseUrl,
      databaseUsername,
      databasePassword,
      databaseHost,
      databasePort,
      didMethod,
      didSeed,
      didWebUrl,
      signUserCredential=false,
      signStatusCredential=false
    } = options;
    super({
      statusCredentialTableName,
      configTableName,
      eventTableName,
      credentialEventTableName,
      databaseName,
      databaseUrl,
      databaseUsername,
      databasePassword,
      databaseHost,
      databasePort,
      didMethod,
      didSeed,
      didWebUrl,
      signUserCredential,
      signStatusCredential
    });
    this.ensureProperConfiguration(options);
  }

  // ensures proper configuration of MongoDB status manager
  ensureProperConfiguration(options: BaseCredentialStatusManagerOptions): void {
    const missingOptions = [] as
      Array<keyof BaseCredentialStatusManagerOptions>;

    const isProperlyConfigured = BASE_MANAGER_REQUIRED_OPTIONS.every(
      (option: keyof BaseCredentialStatusManagerOptions) => {
        if (!options[option]) {
          missingOptions.push(option as any);
        }
        return !!options[option];
      }
    );

    if (!isProperlyConfigured) {
      throw new BadRequestError({
        message:
          'You have neglected to set the following required options for the ' +
          'MongoDB credential status manager: ' +
          `${missingOptions.map(o => `"${o}"`).join(', ')}.`
      });
    }

    if (this.didMethod === DidMethod.Web && !this.didWebUrl) {
      throw new BadRequestError({
        message:
          'The value of "didWebUrl" must be provided ' +
          'when using "didMethod" of type "web".'
      });
    }
  }

  // retrieves database URL
  async getDatabaseUrl(): Promise<string> {
    if (this.databaseUrl) {
      return this.databaseUrl;
    }

    return new Promise((resolve, reject) => {
      dns.resolveSrv(`_mongodb._tcp.${this.databaseHost}`, (error, records) => {
        if (error) {
          if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            // SRV records not found
            resolve(`mongodb://${this.databaseUsername}:${this.databasePassword}@${this.databaseHost}:${this.databasePort}?retryWrites=false`);
          } else {
            // other DNS-related error
            reject(error);
          }
        } else {
          if (records.length > 0) {
            // SRV records found
            resolve(`mongodb+srv://${this.databaseUsername}:${this.databasePassword}@${this.databaseHost}?retryWrites=false`);
          } else {
            // SRV records not found
            resolve(`mongodb://${this.databaseUsername}:${this.databasePassword}@${this.databaseHost}:${this.databasePort}?retryWrites=false`);
          }
        }
      }); 
    });
  }

  // resets database client
  // This function is necessary for cases in which components
  // of the database URL are liable to change regularly
  async resetDatabaseClient() {
    // get database URL
    const databaseUrl = await this.getDatabaseUrl();

    // configure MongoDB client
    this.client = new MongoClient(databaseUrl);
  }

  // connects to database
  async connectDatabase(): Promise<Db> {
    await this.resetDatabaseClient();
    await this.client.connect();
    return this.client.db(this.databaseName);
  }

  // disconnects from database
  async disconnectDatabase(): Promise<void> {
    await this.client.close();
  }

  // checks if caller has authority to manage status based on authorization credentials
  async hasAuthority(databaseUsername: string, databasePassword: string): Promise<boolean> {
    this.databaseUsername = databaseUsername;
    this.databasePassword = databasePassword;
    await this.resetDatabaseClient();
    let hasAccess;
    try {
      await this.connectDatabase();
      hasAccess = true;
    } catch (error) {
      hasAccess = false;
    } finally {
      await this.disconnectDatabase();
    }
    return hasAccess;
  }

  // checks if database exists
  async databaseExists(): Promise<boolean> {
    let exists;
    try {
      const database = await this.connectDatabase();
      const databaseList = await database.admin().listDatabases();
      exists = databaseList.databases.some(db => db.name === this.databaseName);
    } catch (error) {
      exists = false;
    } finally {
      await this.disconnectDatabase();
    }
    return exists;
  }

  // checks if database table exists
  async databaseTableExists(tableName: string): Promise<boolean> {
    let exists;
    try {
      const database = await this.connectDatabase();
      const tableListFiltered = await database.listCollections({ name: tableName }).toArray();
      exists = tableListFiltered.length !== 0;
    } catch (error) {
      exists = false;
    } finally {
      await this.disconnectDatabase();
    }
    return exists;
  }

  // checks if database table is empty
  async databaseTableEmpty(tableName: string): Promise<boolean> {
    let empty;
    try {
      const database = await this.connectDatabase();
      const table = database.collection(tableName);
      const recordCount = await table.countDocuments();
      empty = recordCount === 0;
    } catch (error) {
      empty = true;
    } finally {
      await this.disconnectDatabase();
    }
    return empty;
  }

  // executes function as transaction
  async executeAsTransaction<T>(func: <T>(options?: any) => Promise<T>): Promise<T> {
    await this.resetDatabaseClient();
    const session = this.client.startSession();
    return new Promise(async (resolve, reject) => {
      try {
        await session.withTransaction(async () => {
          try {
            const res = await func({
              client: this.client,
              session
            }) as T;
            resolve(res);
          } catch (error) {
            reject(error);
          } finally {
            await this.disconnectDatabase();
          }
        });
      } catch (error) {
        reject(error);
      } finally {
        await session.endSession();
      }
    });
  }

  // creates single database record
  async createRecord<T>(tableName: string, record: T, options?: any): Promise<void> {
    const { session } = options;
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    await table.insertOne(record as Document, { session });
    await this.disconnectDatabase();
  }

  // updates single database record
  async updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: any): Promise<void> {
    const { session } = options;
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    await table.findOneAndReplace({ [recordIdKey]: recordIdValue }, record as Document, { session });
    await this.disconnectDatabase();
  }

  // retrieves any database record
  async getAnyRecord<T>(tableName: string): Promise<T | null> {
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    const record = await table.findOne();
    await this.disconnectDatabase();
    return record as T | null;
  }

  // retrieves single database record by field
  async getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T | null> {
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    const query = { [fieldKey]: fieldValue };
    const record = await table.findOne(query);
    await this.disconnectDatabase();
    return record as T | null;
  }

  // retrieves multiple database records by field
  async getRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T[]> {
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    const query = { [fieldKey]: fieldValue };
    const recordsRaw = table.find(query);
    const records = await recordsRaw.toArray();
    await this.disconnectDatabase();
    return records as T[];
  }

  // retrieves all records in table
  async getAllRecords<T>(tableName: string): Promise<T[]> {
    const database = await this.connectDatabase();
    const table = database.collection(tableName);
    const records = await table.find().toArray();
    await this.disconnectDatabase();
    return records as T[];
  }
}
