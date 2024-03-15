/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import dns from 'dns';
import {
  ClientSession,
  Db,
  Document,
  MongoClient,
  ReadConcernLevel,
  ReadPreference,
  TransactionOptions
} from 'mongodb';
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  DatabaseConnectionOptions,
  DatabaseService
} from './credential-status-manager-base.js';
import { BadRequestError, WriteConflictError } from './errors.js';

// Type definition for MongoDB connection
interface MongoDbConnection {
  client: MongoClient;
  database: Db;
}

// Type definition for the input of the function passed to
// MongoDB's implementation of executeTransaction
export type MongoDbConnectionOptions = DatabaseConnectionOptions & {
  client?: MongoClient;
  session?: ClientSession;
};

// Implementation of BaseCredentialStatusManager for MongoDB
export class MongoDbCredentialStatusManager extends BaseCredentialStatusManager {
  constructor(options: BaseCredentialStatusManagerOptions) {
    super(options);
    this.databaseService = DatabaseService.MongoDB;
  }

  // helper method for getDatabaseUrl
  async getDatabaseUrlHelper(options?: MongoDbConnectionOptions): Promise<string> {
    const {
      databaseUrl,
      databaseHost,
      databasePort,
      databaseUsername,
      databasePassword
    } = options ?? {};

    if (databaseUrl) {
      return databaseUrl;
    }

    if (!(databaseHost && databasePort && databaseUsername && databasePassword)) {
      throw new BadRequestError({
        message:
          'The caller must either provide a value for "databaseUrl" or a value each for ' +
          `"databaseHost", "databasePort", "databaseUsername", and "databasePassword".`
      });
    }

    return new Promise((resolve, reject) => {
      dns.resolveSrv(`_mongodb._tcp.${databaseHost}`, (error, records) => {
        if (error) {
          if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            // SRV records not found
            resolve(`mongodb://${databaseUsername}:${databasePassword}@${databaseHost}:${databasePort}?retryWrites=false`);
          } else {
            // other DNS-related error
            reject(error);
          }
        } else {
          if (records.length > 0) {
            // SRV records found
            resolve(`mongodb+srv://${databaseUsername}:${databasePassword}@${databaseHost}?retryWrites=false`);
          } else {
            // SRV records not found
            resolve(`mongodb://${databaseUsername}:${databasePassword}@${databaseHost}:${databasePort}?retryWrites=false`);
          }
        }
      }); 
    });
  }

  // retrieve database URL
  async getDatabaseUrl(options?: MongoDbConnectionOptions): Promise<string> {
    const optionsObject = options ?? {};

    if (Object.entries(optionsObject).length === 0) {
      return this.getDatabaseUrlHelper({
        databaseUrl: this.databaseUrl,
        databaseHost: this.databaseHost,
        databasePort: this.databasePort,
        databaseUsername: this.databaseUsername,
        databasePassword: this.databasePassword
      });
    }

    return this.getDatabaseUrlHelper(options);
  }

  // retrieve database client
  async getDatabaseClient(options?: MongoDbConnectionOptions): Promise<MongoClient> {
    // get database URL
    const databaseUrl = await this.getDatabaseUrl(options);
    // create fresh MongoDB client
    const client = new MongoClient(databaseUrl);
    return client;
  }

  // connects to database
  async connectDatabase(options?: MongoDbConnectionOptions): Promise<MongoDbConnection> {
    const { client } = options ?? {};
    if (client) {
      await client.connect();
      const database = client.db(this.databaseName);
      return { client, database };
    }
    const newClient = await this.getDatabaseClient(options);
    await newClient.connect();
    const database = newClient.db(this.databaseName);
    return { client: newClient, database };
  }

  // disconnects from database
  async disconnectDatabase(client?: MongoClient): Promise<void> {
    if (client) {
      await client.close();
    }
  }

  // executes function as transaction
  async executeTransaction(func: (options?: MongoDbConnectionOptions) => Promise<any>): Promise<any> {
    let done = false;
    while (!done) {
      const { client } = await this.connectDatabase();
      const session = client.startSession();
      const transactionOptions: TransactionOptions = {
        readPreference: ReadPreference.primary,
        readConcern: { level: ReadConcernLevel.local },
        writeConcern: { w: 'majority' },
        maxTimeMS: 30000
      };
      try {
        const finalResult = await session.withTransaction(async () => {
          const funcResult = await func({ client, session });
          done = true;
          return funcResult;
        }, transactionOptions);
        done = true;
        return finalResult;
      } catch (error) {
        if (!(error instanceof WriteConflictError)) {
          done = true;
          throw error;
        }
        const delay = Math.floor(Math.random() * 1000);
        await new Promise(resolve => setTimeout(resolve, delay));
      } finally {
        await session.endSession();
        await this.disconnectDatabase(client);
      }
    }
  }

  // checks if caller has authority to manage status based on authorization credentials
  async hasAuthority(options?: MongoDbConnectionOptions): Promise<boolean> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      await database.command({ ping: 1 });
      return true;
    } catch (error) {
      return false;
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // creates database
  // (databases are implicitly created in MongoDB)
  async createDatabase(options?: MongoDbConnectionOptions): Promise<void> {}

  // creates database table
  // (database tables are implicitly created in MongoDB)
  async createDatabaseTable(tableName: string, options?: MongoDbConnectionOptions): Promise<void> {}

  // checks if database exists
  async databaseExists(options?: MongoDbConnectionOptions): Promise<boolean> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(this.configTableName);
      const record = await table.findOne({}, { session });
      return !!record;
    } catch (error: any) {
      if (error.codeName === 'NamespaceNotFound') {
        return false;
      }
      throw error;
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // checks if database table exists
  async databaseTableExists(tableName: string, options?: MongoDbConnectionOptions): Promise<boolean> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const record = await table.findOne({}, { session });
      return !!record;
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // checks if database table is empty
  async databaseTableEmpty(tableName: string, options?: MongoDbConnectionOptions): Promise<boolean> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = {};
      const recordCount = await table.countDocuments(query, { session });
      return recordCount === 0;
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // creates single database record
  async createRecord<T>(tableName: string, record: T, options?: MongoDbConnectionOptions): Promise<void> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      await table.insertOne(record as Document, { session });
    } catch (error: any) {
      if (error.codeName === 'WriteConflict') {
        throw new WriteConflictError({
          message: error.message
        });
      }
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // updates single database record
  async updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: MongoDbConnectionOptions): Promise<void> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = { [recordIdKey]: recordIdValue };
      await table.findOneAndReplace(query, record as Document, { session });
    } catch (error: any) {
      if (error.codeName === 'WriteConflict') {
        throw new WriteConflictError({
          message: error.message
        });
      }
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

  // retrieves any database record
  async getAnyRecord<T>(tableName: string, options?: MongoDbConnectionOptions): Promise<T | null> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    let record;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = {};
      record = await table.findOne(query, { session });
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
    return record as T | null;
  }

  // retrieves single database record by field
  async getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: MongoDbConnectionOptions): Promise<T | null> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    let record;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = { [fieldKey]: fieldValue };
      record = await table.findOne(query, { session });
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
    return record as T | null;
  }

  // retrieves all database records
  async getAllRecords<T>(tableName: string, options?: MongoDbConnectionOptions): Promise<T[]> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    let records = [];
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = {};
      records = await table.find(query, { session }).toArray();
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
    return records as T[];
  }

  // retrieves all database records by field
  async getAllRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: MongoDbConnectionOptions): Promise<T[]> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    let records = [];
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = { [fieldKey]: fieldValue };
      records = await table.find(query, { session }).toArray();
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
    return records as T[];
  }
}
