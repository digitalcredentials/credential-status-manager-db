import { Db, MongoClient } from 'mongodb';
import { BaseDatabaseClient } from './client-base';

// Implementation of BaseDatabaseClient for MongoDB
export class MongoDatabaseClient extends BaseDatabaseClient {
  private client!: MongoClient;

  // resets database client
  // This function is necessary for cases in which components
  // of the database URL are liable to change regularly
  async resetDatabaseClient() {
    // configure MongoDB client
    this.client = new MongoClient(this.databaseUrl);
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
}
