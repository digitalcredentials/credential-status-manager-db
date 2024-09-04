/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { Mutex } from 'async-mutex';
import dns from 'dns';
import {
  ClientSession,
  Db,
  Document,
  MongoClient,
  ReadConcernLevel,
  ReadPreference,
  TransactionOptions,
  WithId
} from 'mongodb';
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  DatabaseConnectionOptions,
  DatabaseService
} from './credential-status-manager-base.js';
import { BadRequestError, InvalidDatabaseTransactionError, StatusListCapacityError, WriteConflictError } from './errors.js';
import { ConcurrencyLimiter } from './concurrency-limiter.js';

// Type definition for MongoDB connection
export interface MongoDbConnection {
  client: MongoClient;
  database: Db;
}

// Type definition for the input of the function passed to
// MongoDB's implementation of executeTransaction
export type MongoDbConnectionOptions = DatabaseConnectionOptions & {
  client?: MongoClient;
  session?: ClientSession;
};

// This is a general database timeout
const GENERAL_DATABASE_TIMEOUT_MS = 30 * 60 * 1000; // 30 mins

// This limits the number of concurrent transactions
// (assumes that there is one client process running transactions in parallel)
const CONCURRENCY_LIMIT = 200;
const MAX_POOL_SIZE = CONCURRENCY_LIMIT + 100;
const concurrencyLimiter = new ConcurrencyLimiter(CONCURRENCY_LIMIT);

// This reuses the database URL across transactions
// (cache expires after 5 mins)
const DB_URL_CACHE_DURATION_MS = 5 * 60 * 1000;
const databaseUrlCache = new Map<string, { url: string; expirationTime: number; }>();

// This reuses the MongoDB database client across transactions
// (cache expires after 5 mins)
const DB_CLIENT_CACHE_DURATION_MS = 5 * 60 * 1000;
const databaseClientCache = new Map<string, { client: MongoClient; expirationTime: number; }>();

// This controls which transactions can open or close a database connection
const databaseClientLock = new Mutex();

// This tracks the number of active transactions
let activeDatabaseTransactionsCounter = 0;
const activeDatabaseTransactionsCounterLock = new Mutex();

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
    
    // attempt to retrieve cached SRV info and check if still valid
    const databaseHostKey = `_mongodb._tcp.${databaseHost}`;
    const currentTime = Date.now();
    if (databaseUrlCache.has(databaseHostKey)) {
      const databaseUrlCacheEntry = databaseUrlCache.get(databaseHostKey);
      if (databaseUrlCacheEntry) {
        const { url, expirationTime } = databaseUrlCacheEntry;
        if (currentTime < expirationTime) {
          return Promise.resolve(url);
        }
      }
    }

    return new Promise((resolve, reject) => {
      let url = `mongodb://${databaseUsername}:${databasePassword}@${databaseHost}:${databasePort}?retryWrites=false`;
      const expirationTime = currentTime + DB_URL_CACHE_DURATION_MS;
      dns.resolveSrv(databaseHostKey, (error, records) => {
        if (error) {
          if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            // SRV records not found
            databaseUrlCache.set(databaseHostKey, {
              url,
              expirationTime
            });
            resolve(url);
          } else {
            // other DNS-related error
            reject(error);
          }
        } else {
          if (records.length > 0) {
            // SRV records found
            url = `mongodb+srv://${databaseUsername}:${databasePassword}@${databaseHost}?retryWrites=false`;
            databaseUrlCache.set(databaseHostKey, {
              url,
              expirationTime
            });
            resolve(url);
          } else {
            // SRV records not found
            databaseUrlCache.set(databaseHostKey, {
              url,
              expirationTime
            });
            resolve(url);
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

  // retrieves database client (assumes calling only from connectDatabase, which locks the client)
  async getDatabaseClient(options?: MongoDbConnectionOptions): Promise<MongoClient> {
    // get database URL
    const databaseUrl = await this.getDatabaseUrl(options);

    // attempt to retrieve cached database client and check if still valid
    const currentTime = Date.now();
    if (databaseClientCache.has(databaseUrl)) {
      const databaseClientCacheEntry = databaseClientCache.get(databaseUrl);
      if (databaseClientCacheEntry) {
        const { client, expirationTime } = databaseClientCacheEntry;
        if (currentTime < expirationTime) {
          const databaseConnected = await this.isDatabaseConnected(client);
          if (!databaseConnected) {
            await client.connect();
          }
          return client;
        }
      }
    }

    // create fresh MongoDB client, connect it to database,
    // and cache it for future transactions
    const client = new MongoClient(
      databaseUrl, {
        maxPoolSize: MAX_POOL_SIZE,
        serverSelectionTimeoutMS: GENERAL_DATABASE_TIMEOUT_MS,
        socketTimeoutMS: GENERAL_DATABASE_TIMEOUT_MS
      }
    );
    await client.connect();
    const expirationTime = currentTime + DB_CLIENT_CACHE_DURATION_MS;
    databaseClientCache.set(databaseUrl, { client, expirationTime });
    return client;
  }

  // connects to database
  async connectDatabase(options?: MongoDbConnectionOptions): Promise<MongoDbConnection> {
    // acquire a lock on the client to ensure that only one
    // transaction opens a connection on it
    const release = await databaseClientLock.acquire();
    try {
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
    } finally {
      release();
    }
  }

  // disconnects from database
  async disconnectDatabase(client?: MongoClient): Promise<void> {
    // acquire a lock on the client and the active database transaction counter
    // to ensure that a transaction closes a connection only when there are no
    // active transactions
    const clientRelease = await databaseClientLock.acquire();
    const counterRelease = await activeDatabaseTransactionsCounterLock.acquire();
    try {
      if (!client) {
        return;
      }
      const databaseConnected = await this.isDatabaseConnected(client);
      if (!databaseConnected) {
        return;
      }
      activeDatabaseTransactionsCounter -= 1;
      if (activeDatabaseTransactionsCounter === 0) {
        await client.close();
      }
    } finally {
      counterRelease();
      clientRelease();
    }
  }

  // checks if database is connected
  async isDatabaseConnected(client: MongoClient): Promise<boolean> {
    try {
      await client.db().command({ ping: 1 });
      return true;
    } catch (error) {
      return false;
    }
  }

  // handles errors that can occur from any transaction
  handleGeneralErrors(error: any): void {
    if (error.codeName === 'NoSuchTransaction' || error.codeName === 'CursorNotFound') {
      // throw error that will be caught by executeTransaction for retry
      throw new InvalidDatabaseTransactionError();
    }
    // unhandled error that we should allow to halt execution
    throw error;
  }

  // executes function as transaction
  async executeTransaction(func: (options?: MongoDbConnectionOptions) => Promise<any>): Promise<any> {
    return concurrencyLimiter.execute(async () => {
      // acquire a lock on the active database transaction counter
      // as early as possible in order to signal that the connection
      // should remain open
      const release = await activeDatabaseTransactionsCounterLock.acquire();
      try {
        activeDatabaseTransactionsCounter += 1;
      } finally {
        release();
      }
      let done = false;
      while (!done) {
        let client: MongoClient | undefined;
        let session: ClientSession | undefined;
        const transactionOptions: TransactionOptions = {
          readPreference: ReadPreference.primary,
          readConcern: { level: ReadConcernLevel.local },
          writeConcern: { w: 'majority' },
          maxTimeMS: GENERAL_DATABASE_TIMEOUT_MS
        };
        try {
          ({ client } = await this.connectDatabase());
          session = client.startSession();
          const finalResult = await session.withTransaction(async () => {
            const funcResult = await func({ client, session });
            return funcResult;
          }, transactionOptions);
          done = true;
          await this.disconnectDatabase(client);
          return finalResult;
        } catch (error) {
          if (!(error instanceof WriteConflictError ||
            error instanceof InvalidDatabaseTransactionError ||
            error instanceof StatusListCapacityError)) {
            done = true;
            await this.disconnectDatabase(client);
            throw error;
          }
          const delay = Math.floor(Math.random() * 1000);
          await new Promise(resolve => setTimeout(resolve, delay));
        } finally {
          if (session) {
            await session.endSession();
          }
        }
      }
    });
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

  // creates unique database table index
  // (database tables are implicitly created in MongoDB)
  async createUniqueDatabaseTableIndex(tableName: string, fields: string[], options?: MongoDbConnectionOptions): Promise<void> {
    const optionsObject = options ?? {};
    const { client: clientCandidate, session } = optionsObject;
    let client = clientCandidate;
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const uniqueFieldMap = Object.fromEntries(fields.map(f => [f, 1]));
      await table.createIndex(uniqueFieldMap, { unique: true, sparse: true });
    } catch (error: any) {
      this.handleGeneralErrors(error);
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
  }

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
      this.handleGeneralErrors(error);
      return false;
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
    } catch (error: any) {
      this.handleGeneralErrors(error);
      return false;
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
    } catch (error: any) {
      this.handleGeneralErrors(error);
      return true;
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
      if (error.codeName === 'WriteConflict' || error.codeName === 'DuplicateKey' || error.code === 11000) {
        throw new WriteConflictError({
          message: error.message
        });
      }
      this.handleGeneralErrors(error);
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
      this.handleGeneralErrors(error);
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
    } catch (error: any) {
      this.handleGeneralErrors(error);
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
    } catch (error: any) {
      this.handleGeneralErrors(error);
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
    let records: Array<WithId<Document>> = [];
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = {};
      records = await table.find(query, { session }).toArray();
    } catch (error: any) {
      this.handleGeneralErrors(error);
      return [];
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
    let records: Array<WithId<Document>> = [];
    try {
      const databaseConnection = await this.connectDatabase(options);
      const { database } = databaseConnection;
      ({ client } = databaseConnection);
      const table = database.collection(tableName);
      const query = { [fieldKey]: fieldValue };
      records = await table.find(query, { session }).toArray();
    } catch (error: any) {
      this.handleGeneralErrors(error);
      return [];
    } finally {
      if (!session) {
        // otherwise handled in executeTransaction
        await this.disconnectDatabase(client);
      }
    }
    return records as T[];
  }
}
