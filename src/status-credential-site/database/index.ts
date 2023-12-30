import { env } from '../util';
import { BaseDatabaseClient, DatabaseService } from './client-base';
import { MongoDatabaseClient } from './client-mongo';

// retrieves database client
export const getDatabaseClient = (): BaseDatabaseClient => {
  const databaseService = env.DB_SERVICE as DatabaseService;
  switch (databaseService) {
    case DatabaseService.MongoDb:
      return new MongoDatabaseClient();
    default:
      throw new Error(
        '"DB_SERVICE" must be one of the following values: ' +
        `${Object.values(DatabaseService).map(s => `"${s}"`).join(', ')}.`
      );
  }
};
