/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import { v4 as uuid } from 'uuid';
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  Config,
  CredentialStatusManagerService,
  composeStatusCredential
} from './credential-status-manager-base.js';
import {
  MongoDbCredentialStatusManager
} from './credential-status-manager-mongodb.js';
import {
  BadRequestError,
  InvalidCredentialsError,
  InvalidStateError,
  MissingDatabaseError,
  MissingDatabaseTableError
} from './errors.js';
import { signCredential, getSigningMaterial } from './helpers.js';

// Type definition for base options of createStatusManager function input
interface CredentialStatusManagerBaseOptions {
  service: CredentialStatusManagerService;
}

// Type definition for createStatusManager function input
type CredentialStatusManagerOptions = CredentialStatusManagerBaseOptions &
  BaseCredentialStatusManagerOptions;

// creates credential status manager
export async function createStatusManager(options: CredentialStatusManagerOptions)
: Promise<BaseCredentialStatusManager> {
  const {
    service,
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
  let statusManager: BaseCredentialStatusManager;

  if (!databaseUrl && !(databaseHost && databasePort && databaseUsername && databasePassword)) {
    throw new BadRequestError({
      message:
        'The caller must either provide a value for "databaseUrl" or a value each for ' +
        `"databaseHost", "databasePort", "databaseUsername", and "databasePassword".`
    });
  }

  switch (service) {
    case CredentialStatusManagerService.MongoDb:
      statusManager = new MongoDbCredentialStatusManager({
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
      break;
    default:
      throw new BadRequestError({
        message:
          '"service" must be one of the following values: ' +
          `${Object.values(CredentialStatusManagerService).map(s => `"${s}"`).join(', ')}.`
      });
  }

  statusManager.executeAsTransaction(async (options?: any) => {
    // retrieve signing material
    const { issuerDid } = await getSigningMaterial({
      didMethod,
      didSeed,
      didWebUrl
    });

    // retrieve relevant data from status database configuration
    const hasAccess = await statusManager.hasAuthority(databaseUsername, databasePassword);
    if (!hasAccess) {
      throw new InvalidCredentialsError({ statusManager });
    }

    const databaseExists = await statusManager.databaseExists();
    if (!databaseExists) {
      throw new MissingDatabaseError({ statusManager });
    }

    const tablesExist = await statusManager.databaseTablesExist();
    if (!tablesExist) {
      throw new MissingDatabaseTableError({ statusManager });
    }

    const tablesEmpty = await statusManager.databaseTablesEmpty();
    if (!tablesEmpty) {
      const tablesProperlyConfigured = await statusManager.databaseTablesProperlyConfigured();
      if (!tablesProperlyConfigured) {
        throw new InvalidStateError({ statusManager });
      }
    } else {
      // create and persist status config
      const statusCredentialId = statusManager.generateStatusCredentialId();
      const config: Config = {
        id: uuid(),
        latestStatusCredentialId: statusCredentialId,
        latestCredentialsIssuedCounter: 0,
        allCredentialsIssuedCounter: 0
      };
      await statusManager.createConfig(config, options);

      // create status credential
      const statusCredentialUrlBase = statusManager.getStatusCredentialUrlBase();
      const statusCredentialUrl = `${statusCredentialUrlBase}/${statusCredentialId}`;
      let statusCredential = await composeStatusCredential({
        issuerDid,
        credentialId: statusCredentialUrl
      });

      // sign status credential if necessary
      if (signStatusCredential) {
        statusCredential = await signCredential({
          credential: statusCredential,
          didMethod,
          didSeed,
          didWebUrl
        });
      }

      // create and persist status data
      await statusManager.createStatusCredential({
        id: statusCredentialId,
        credential: statusCredential
      }, options);

      // setup credential status website
      await statusManager.deployCredentialStatusWebsite();
    }
  });

  return statusManager;
}
