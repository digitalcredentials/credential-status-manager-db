/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  DatabaseService,
  SiteService
} from './credential-status-manager-base.js';
import {
  MongoDbCredentialStatusManager
} from './credential-status-manager-mongodb.js';
import {
  BadRequestError,
  InternalServerError,
  InvalidCredentialsError,
  InvalidStateError,
  MissingDatabaseError,
  MissingDatabaseTableError
} from './errors.js';

// Type definition for base options of createStatusManager function input
interface CredentialStatusManagerBaseOptions {
  autoDeployDatabase?: boolean;
  autoDeploySite?: boolean;
  databaseService: DatabaseService;
  siteService: SiteService;
}

// Type definition for createStatusManager function input
type CredentialStatusManagerOptions = CredentialStatusManagerBaseOptions &
  BaseCredentialStatusManagerOptions;

// creates credential status manager
export async function createStatusManager(options: CredentialStatusManagerOptions)
: Promise<BaseCredentialStatusManager> {
  const {
    autoDeployDatabase=true,
    autoDeploySite=true,
    databaseService,
    siteService,
    siteUrl,
    databaseUrl,
    databaseHost,
    databasePort,
    databaseUsername,
    databasePassword
  } = options;
  let statusManager: BaseCredentialStatusManager;

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

  await statusManager.executeTransaction(async (options?: any) => {
    // retrieve signing material
    if (!autoDeploySite && !siteUrl) {
      throw new BadRequestError({
        message:
          '"siteUrl" must be configured when "autoDeploySite" is false.'
      });
    }

    // retrieve relevant data from status database configuration
    const hasAccess = await statusManager.hasAuthority(databaseUsername, databasePassword, options);
    if (!hasAccess) {
      throw new InvalidCredentialsError({ statusManager });
    }

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

      // database should be properly configured by this point
      const tablesProperlyConfigured = await statusManager.databaseTablesProperlyConfigured(options);
      if (!tablesProperlyConfigured) {
        throw new InvalidStateError({ statusManager });
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
        // database tables should be properly configured if
        // they are not empty and autoDeployDatabase is not configured
        const tablesProperlyConfigured = await statusManager.databaseTablesProperlyConfigured(options);
        if (!tablesProperlyConfigured) {
          throw new InvalidStateError({ statusManager });
        }
      } else {
        // database tables should be initialized if
        // they are empty and autoDeployDatabase is not configured
        await statusManager.initializeDatabaseResources(options);
      }
    }

    // setup credential status website if autoDeploySite is configured
    if (autoDeploySite) {
      await statusManager.deployStatusCredentialWebsite(siteService);
    }
  });

  return statusManager;
}
