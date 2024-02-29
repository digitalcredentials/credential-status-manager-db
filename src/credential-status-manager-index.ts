/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  DatabaseConnectionOptions,
  DatabaseService
} from './credential-status-manager-base.js';
import {
  MongoDbCredentialStatusManager
} from './credential-status-manager-mongodb.js';
import {
  BadRequestError,
  InternalServerError,
  InvalidCredentialsError,
  InvalidDatabaseStateError,
  MissingDatabaseError,
  MissingDatabaseTableError
} from './errors.js';

/* eslint-disable @typescript-eslint/restrict-template-expressions */

// Type definition for base options of createStatusManager function input
interface CredentialStatusManagerBaseOptions {
  databaseService: DatabaseService;
  autoDeployDatabase?: boolean;
}

// Type definition for createStatusManager function input
type CredentialStatusManagerOptions = CredentialStatusManagerBaseOptions &
  BaseCredentialStatusManagerOptions;

// creates credential status manager
export async function createStatusManager(options: CredentialStatusManagerOptions)
: Promise<BaseCredentialStatusManager> {
  const {
    databaseService,
    databaseUrl,
    databaseHost,
    databasePort,
    databaseUsername,
    databasePassword,
    statusCredentialSiteOrigin,
    autoDeployDatabase = true
  } = options;
  let statusManager: BaseCredentialStatusManager;

  if (!statusCredentialSiteOrigin) {
    throw new BadRequestError({
      message:
        '"statusCredentialSiteOrigin" must be configured in order ' +
        'for verifiers to retrieve credential status during verification.'
    });
  }

  if (!databaseUrl && !(databaseHost && databasePort && databaseUsername && databasePassword)) {
    throw new BadRequestError({
      message:
        'The caller must either provide a value for "databaseUrl" or a value each for ' +
        `"databaseHost", "databasePort", "databaseUsername", and "databasePassword".`
    });
  }

  switch (databaseService) {
    case DatabaseService.MongoDB:
      statusManager = new MongoDbCredentialStatusManager(options);
      break;
    default:
      throw new BadRequestError({
        message:
          '"databaseService" must be one of the following values: ' +
          `${Object.values(DatabaseService).map(s => `"${s}"`).join(', ')}.`
      });
  }

  await statusManager.executeTransaction(async (options?: DatabaseConnectionOptions) => {
    // determine if client has access to this database instance
    const hasAccess = await statusManager.hasAuthority({
      databaseUrl,
      databaseHost,
      databasePort,
      databaseUsername,
      databasePassword,
      ...options
    });
    if (!hasAccess) {
      throw new InvalidCredentialsError({ statusManager });
    }

    // determine if database instance exists
    let databaseExists;
    try {
      databaseExists = await statusManager.databaseExists(options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to check for database existence: ${error.message}`
      });
    }

    // setup credential status database
    if (autoDeployDatabase) {
      if (!databaseExists) {
        // initialize database if autoDeployDatabase is configured
        // and it does not yet exist from an earlier deployment
        await statusManager.createDatabaseResources(options);
        await statusManager.initializeDatabaseResources(options);
      }

      // database should have valid configuration by this point
      const databaseState = await statusManager.getDatabaseState(options);
      if (!databaseState.valid) {
        throw databaseState.error as InvalidDatabaseStateError;
      }
    } else {
      // database should already exist if autoDeployDatabase is not configured
      if (!databaseExists) {
        throw new MissingDatabaseError({ statusManager });
      }

      // database tables should already exist if autoDeployDatabase is not configured
      const tablesExist = await statusManager.databaseTablesExist(options);
      if (!tablesExist) {
        throw new MissingDatabaseTableError({ statusManager });
      }

      const tablesEmpty = await statusManager.databaseTablesEmpty(options);
      if (!tablesEmpty) {
        // database tables should have valid configuration if
        // they are not empty and autoDeployDatabase is not configured
        const databaseState = await statusManager.getDatabaseState(options);
        if (!databaseState.valid) {
          throw databaseState.error as InvalidDatabaseStateError;
        }
      } else {
        // database tables should be initialized if
        // they are empty and autoDeployDatabase is not configured
        await statusManager.initializeDatabaseResources(options);
      }
    }
  });

  return statusManager;
}
