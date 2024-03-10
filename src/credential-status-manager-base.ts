/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { createCredential, createList, decodeList } from '@digitalcredentials/vc-bitstring-status-list';
import { VerifiableCredential } from '@digitalcredentials/vc-data-model';
import { v4 as uuid } from 'uuid';
import {
  BadRequestError,
  CustomError,
  InternalServerError,
  InvalidDatabaseStateError,
  NotFoundError,
  WriteConflictError
} from './errors.js';
import {
  DidMethod,
  deriveStatusCredentialId,
  getCredentialSubjectObject,
  getDateString,
  getSigningMaterial,
  signCredential,
  validateCredential
} from './helpers.js';

/* eslint-disable @typescript-eslint/restrict-template-expressions */

// Number of credentials tracked in a list
const CREDENTIAL_STATUS_LIST_SIZE = 100000;

// Status credential type
const STATUS_CREDENTIAL_TYPE = 'BitstringStatusListCredential';

// Status credential subject type
const STATUS_CREDENTIAL_SUBJECT_TYPE = 'BitstringStatusList';

// Credential status type
const CREDENTIAL_STATUS_TYPE = 'BitstringStatusListEntry';

// Database hosting service
export enum DatabaseService {
  MongoDB = 'mongodb'
  // MySQL = 'mysql' // TODO - implement this
}

// Purposes status of a status credential
export enum StatusPurpose {
  Revocation = 'revocation',
  Suspension = 'suspension'
}

// States of credential resulting from caller actions and tracked in the event log
export enum CredentialState {
  Active = 'active',
  Revoked = 'revoked',
  Suspended = 'suspended'
}

// Type definition for event
interface EventRecord {
  id: string;
  timestamp: string;
  credentialId: string;
  credentialIssuer: string;
  credentialSubject?: string;
  credentialState: CredentialState;
  verificationMethod: string;
  statusCredentialId: string;
  credentialStatusIndex: number;
}

// Type definition for credential status config
export interface ConfigRecord {
  id: string;
  statusCredentialSiteOrigin: string;
  latestStatusCredentialId: string;
  latestCredentialsIssuedCounter: number;
  allCredentialsIssuedCounter: number;
}

// Type definition for status credential record
export interface StatusCredentialRecord {
  id: string;
  credential: VerifiableCredential;
}

// Type definition for credential event record
// (saves latest event for credential)
export interface CredentialEventRecord {
  credentialId: string;
  eventId: string;
}

// Type definition for composeStatusCredential function input
interface ComposeStatusCredentialOptions {
  issuerDid: string;
  credentialId: string;
  statusList?: any;
  statusPurpose?: StatusPurpose;
}

// Type definition for attachCredentialStatus method input
interface AttachCredentialStatusOptions {
  credential: any;
  statusPurpose?: StatusPurpose;
}

// Type definition for attachCredentialStatus method output
type AttachCredentialStatusResult = ConfigRecord & {
  credential: any;
  newUserCredential: boolean;
  newStatusCredential: boolean;
};

// Type definition for allocateStatus method input
interface AllocateStatusOptions {
  credential: VerifiableCredential;
  statusPurpose?: StatusPurpose;
}

// Type definition for updateStatus method input
interface UpdateStatusOptions {
  credentialId: string;
  credentialState?: CredentialState;
}

// Type definition for getDatabaseState method output
interface GetDatabaseStateResult {
  valid: boolean;
  error?: InvalidDatabaseStateError;
}

// Type definition for database connection options
export interface DatabaseConnectionOptions {
  databaseUrl?: string;
  databaseHost?: string;
  databasePort?: number;
  databaseUsername?: string;
  databasePassword?: any;
  [x: string]: any;
}

// Type definition for BaseCredentialStatusManager constructor method input
export interface BaseCredentialStatusManagerOptions {
  statusCredentialSiteOrigin: string;
  statusCredentialTableName?: string;
  configTableName?: string;
  eventTableName?: string;
  credentialEventTableName?: string;
  databaseName?: string;
  databaseUrl?: string;
  databaseHost?: string;
  databasePort?: number;
  databaseUsername: string;
  databasePassword: string;
  didMethod: DidMethod;
  didSeed: string;
  didWebUrl?: string;
  signStatusCredential?: boolean;
  signUserCredential?: boolean;
}

// Minimal set of options required for configuring BaseCredentialStatusManager
export const BASE_MANAGER_REQUIRED_OPTIONS: Array<keyof BaseCredentialStatusManagerOptions> = [
  'didMethod',
  'didSeed'
];

// Base class for database clients
export abstract class BaseCredentialStatusManager {
  protected readonly statusCredentialSiteOrigin: string;
  protected readonly statusCredentialTableName: string;
  protected readonly configTableName: string;
  protected readonly eventTableName: string;
  protected readonly credentialEventTableName: string;
  protected databaseService!: DatabaseService;
  protected readonly databaseName: string;
  protected readonly databaseUrl?: string;
  protected readonly databaseHost?: string;
  protected readonly databasePort?: number;
  protected readonly databaseUsername: string;
  protected readonly databasePassword: string;
  protected readonly didMethod: DidMethod;
  protected readonly didSeed: string;
  protected readonly didWebUrl?: string;
  protected readonly signStatusCredential: boolean;
  protected readonly signUserCredential: boolean;

  constructor(options: BaseCredentialStatusManagerOptions) {
    const {
      statusCredentialSiteOrigin,
      statusCredentialTableName,
      configTableName,
      eventTableName,
      credentialEventTableName,
      databaseName,
      databaseUrl,
      databaseHost,
      databasePort,
      databaseUsername,
      databasePassword,
      didMethod,
      didSeed,
      didWebUrl,
      signStatusCredential,
      signUserCredential
    } = options;
    this.statusCredentialSiteOrigin = statusCredentialSiteOrigin;
    this.statusCredentialTableName = statusCredentialTableName ?? 'StatusCredential';
    this.configTableName = configTableName ?? 'Config';
    this.eventTableName = eventTableName ?? 'Event';
    this.credentialEventTableName = credentialEventTableName ?? 'CredentialEvent';
    this.databaseName = databaseName ?? 'credentialStatus';
    this.databaseUrl = databaseUrl;
    this.databaseHost = databaseHost;
    this.databasePort = databasePort;
    this.databaseUsername = databaseUsername;
    this.databasePassword = databasePassword;
    this.didMethod = didMethod;
    this.didSeed = didSeed;
    this.didWebUrl = didWebUrl;
    this.signStatusCredential = signStatusCredential ?? true;
    this.signUserCredential = signUserCredential ?? false;
    this.validateConfiguration(options);
  }

  // ensures valid configuration of credential status manager
  validateConfiguration(options: BaseCredentialStatusManagerOptions): void {
    const missingOptions = [] as
      Array<keyof BaseCredentialStatusManagerOptions>;

    const hasValidConfiguration = BASE_MANAGER_REQUIRED_OPTIONS.every(
      (option: keyof BaseCredentialStatusManagerOptions) => {
        if (!options[option]) {
          missingOptions.push(option as any);
        }
        return !!options[option];
      }
    );

    if (!hasValidConfiguration) {
      throw new BadRequestError({
        message:
          'You have neglected to set the following required options ' +
          'for a credential status manager: ' +
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

  // retrieves database name
  getDatabaseName(): string {
    return this.databaseName;
  }

  // retrieves database table names
  getDatabaseTableNames(): string[] {
    return [
      this.statusCredentialTableName,
      this.configTableName,
      this.eventTableName,
      this.credentialEventTableName
    ];
  }

  // generates new status credential ID
  // Note: We assume this method will never generate an ID that
  // has previously been generated for a status credential in this system
  generateStatusCredentialId(): string {
    return Math.random().toString(36).substring(2, 12).toUpperCase();
  }

  // generates new user credential ID
  // Note: We assume this method will never generate an ID that
  // has previously been generated for a user credential in this system
  generateUserCredentialId(): string {
    return `urn:uuid:${uuid()}`;
  }

  // attaches status to credential
  async attachCredentialStatus({ credential, statusPurpose = StatusPurpose.Revocation }: AttachCredentialStatusOptions, options?: DatabaseConnectionOptions): Promise<AttachCredentialStatusResult> {
    // copy credential and delete appropriate fields
    const credentialCopy = Object.assign({}, credential);
    delete credentialCopy.credentialStatus;
    delete credentialCopy.proof;

    // ensure that credential has ID
    if (!credentialCopy.id) {
      // Note: This assumes that uuid will never generate an ID that
      // conflicts with an ID that has already been tracked in the event log
      credentialCopy.id = this.generateUserCredentialId();
    }

    // validate credential before attaching status
    validateCredential(credentialCopy);

    // retrieve config
    let {
      id,
      statusCredentialSiteOrigin,
      latestStatusCredentialId,
      latestCredentialsIssuedCounter,
      allCredentialsIssuedCounter
    } = await this.getConfigRecord(options);

    // retrieve latest relevant event for credential with given ID
    const event = await this.getLatestEventRecordForCredential(credentialCopy.id, options);

    // do not allocate new entry if ID is already being tracked
    if (event) {
      // retrieve relevant event
      const { statusCredentialId, credentialStatusIndex } = event;

      // attach credential status
      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
      const credentialStatusId = `${statusCredentialUrl}#${credentialStatusIndex}`;
      const credentialStatus = {
        id: credentialStatusId,
        type: CREDENTIAL_STATUS_TYPE,
        statusPurpose,
        statusListIndex: credentialStatusIndex.toString(),
        statusListCredential: statusCredentialUrl
      };

      return {
        id,
        credential: {
          ...credentialCopy,
          credentialStatus
        },
        newUserCredential: false,
        newStatusCredential: false,
        statusCredentialSiteOrigin,
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        allCredentialsIssuedCounter
      };
    }

    // allocate new entry if ID is not yet being tracked
    let newStatusCredential = false;
    if (latestCredentialsIssuedCounter >= CREDENTIAL_STATUS_LIST_SIZE) {
      newStatusCredential = true;
      latestCredentialsIssuedCounter = 0;
      latestStatusCredentialId = this.generateStatusCredentialId();
    }
    allCredentialsIssuedCounter++;
    latestCredentialsIssuedCounter++;

    // attach credential status
    const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;
    const credentialStatusIndex = latestCredentialsIssuedCounter;
    const credentialStatusId = `${statusCredentialUrl}#${credentialStatusIndex}`;
    const credentialStatus = {
      id: credentialStatusId,
      type: CREDENTIAL_STATUS_TYPE,
      statusPurpose,
      statusListIndex: credentialStatusIndex.toString(),
      statusListCredential: statusCredentialUrl
    };

    return {
      id,
      credential: {
        ...credentialCopy,
        credentialStatus
      },
      newUserCredential: true,
      newStatusCredential,
      statusCredentialSiteOrigin,
      latestStatusCredentialId,
      latestCredentialsIssuedCounter,
      allCredentialsIssuedCounter
    };
  }

  // allocates status for credential
  async allocateStatus({ credential, statusPurpose = StatusPurpose.Revocation }: AllocateStatusOptions): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: DatabaseConnectionOptions) => {
      // report error for compact JWT credentials
      if (typeof credential === 'string') {
        throw new BadRequestError({
          message: 'This library does not support compact JWT credentials.'
        });
      }

      // attach status to credential
      let {
        credential: credentialWithStatus,
        newUserCredential,
        newStatusCredential,
        latestStatusCredentialId,
        ...attachCredentialStatusResultRest
      } = await this.attachCredentialStatus({ credential, statusPurpose }, options);

      // retrieve signing material
      const {
        didMethod,
        didSeed,
        didWebUrl,
        signStatusCredential,
        signUserCredential
      } = this;
      const {
        issuerDid,
        verificationMethod
      } = await getSigningMaterial({
        didMethod,
        didSeed,
        didWebUrl
      });

      // sign credential if necessary
      if (signUserCredential) {
        credentialWithStatus = await signCredential({
          credential: credentialWithStatus,
          didMethod,
          didSeed,
          didWebUrl
        });
      }

      // return credential without updating database resources
      // if we are already accounting for this credential
      if (!newUserCredential) {
        return credentialWithStatus;
      }

      // create new status credential only if the last one has reached capacity
      if (newStatusCredential) {
        // create status credential
        const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;
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

        // create and persist status credential record
        await this.createStatusCredentialRecord({
          id: latestStatusCredentialId,
          credential: statusCredential
        }, options);
      }

      // extract relevant data from credential status
      const {
        statusListCredential: statusCredentialUrl,
        statusListIndex
      } = credentialWithStatus.credentialStatus;

      // retrieve status credential ID from status credential URL
      const statusCredentialId = deriveStatusCredentialId(statusCredentialUrl);

      // create new event record
      const credentialSubjectObject = getCredentialSubjectObject(credentialWithStatus);
      const eventId = uuid();
      const event: EventRecord = {
        id: eventId,
        timestamp: getDateString(),
        credentialId: credentialWithStatus.id as string,
        credentialIssuer: issuerDid,
        credentialSubject: credentialSubjectObject?.id,
        credentialState: CredentialState.Active,
        verificationMethod,
        statusCredentialId,
        credentialStatusIndex: parseInt(statusListIndex)
      };
      await this.createEventRecord(event, options);
      await this.createCredentialEventRecord({
        credentialId: credentialWithStatus.id as string,
        eventId
      }, options);

      // persist updates to config record
      await this.updateConfigRecord({
        latestStatusCredentialId,
        ...attachCredentialStatusResultRest
      }, options);

      return credentialWithStatus;
    });
  }

  // allocates revocation status for credential
  async allocateRevocationStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurpose: StatusPurpose.Revocation });
  }

  // allocates suspension status for credential
  async allocateSuspensionStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurpose: StatusPurpose.Suspension });
  }

  // updates status of credential
  async updateStatus({
    credentialId,
    credentialState = CredentialState.Revoked
  }: UpdateStatusOptions): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: DatabaseConnectionOptions) => {
      // retrieve latest relevant event for credential with given ID
      const oldEvent = await this.getLatestEventRecordForCredential(credentialId, options);

      // unable to find credential with given ID
      if (!oldEvent) {
        throw new NotFoundError({
          message: `Unable to find credential with ID "${credentialId}".`
        });
      }

      // retrieve relevant event
      const {
        credentialSubject,
        statusCredentialId,
        credentialStatusIndex
      } = oldEvent;

      // retrieve signing material
      const {
        didMethod,
        didSeed,
        didWebUrl,
        signStatusCredential
      } = this;
      const {
        issuerDid,
        verificationMethod
      } = await getSigningMaterial({
        didMethod,
        didSeed,
        didWebUrl
      });

      // retrieve status credential
      const statusCredentialBefore = await this.getStatusCredential(statusCredentialId, options);

      // report error for compact JWT credentials
      if (typeof statusCredentialBefore === 'string') {
        throw new BadRequestError({
          message: 'This library does not support compact JWT credentials.'
        });
      }

      // update status credential
      const statusCredentialSubjectObjectBefore = getCredentialSubjectObject(statusCredentialBefore);
      const statusCredentialListEncodedBefore = statusCredentialSubjectObjectBefore.encodedList;
      const statusCredentialListDecoded = await decodeList({
        encodedList: statusCredentialListEncodedBefore
      });
      switch (credentialState) {
        case CredentialState.Active:
          statusCredentialListDecoded.setStatus(credentialStatusIndex, false); // active credential is represented as 0 bit
          break;
        case CredentialState.Revoked:
          statusCredentialListDecoded.setStatus(credentialStatusIndex, true); // revoked credential is represented as 1 bit
          break;
        default:
          throw new BadRequestError({
            message:
              '"credentialState" must be one of the following values: ' +
              `${Object.values(CredentialState).map(s => `"${s}"`).join(', ')}.`
          });
      }
      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
      let statusCredential = await composeStatusCredential({
        issuerDid,
        credentialId: statusCredentialUrl,
        statusList: statusCredentialListDecoded
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

      // persist status credential record
      await this.updateStatusCredentialRecord({
        id: statusCredentialId,
        credential: statusCredential
      }, options);

      // create new event record
      const eventId = uuid();
      const newEventRecord: EventRecord = {
        id: eventId,
        timestamp: getDateString(),
        credentialId,
        credentialIssuer: issuerDid,
        credentialSubject,
        credentialState,
        verificationMethod,
        statusCredentialId,
        credentialStatusIndex
      };
      await this.createEventRecord(newEventRecord, options);
      await this.updateCredentialEventRecord({
        credentialId,
        eventId
      }, options);

      return statusCredential;
    });
  }

  // revokes credential
  async revokeCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({ credentialId, credentialState: CredentialState.Revoked });
  }

  // suspends credential
  async suspendCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({ credentialId, credentialState: CredentialState.Suspended });
  }

  // checks status of credential with given ID
  async checkStatus(credentialId: string, options?: DatabaseConnectionOptions): Promise<EventRecord> {
    // retrieve latest relevant event for credential with given ID
    const event = await this.getLatestEventRecordForCredential(credentialId, options);

    // unable to find credential with given ID
    if (!event) {
      throw new NotFoundError({
        message: `Unable to find credential with ID "${credentialId}".`
      });
    }

    return event;
  }

  // retrieves database URL
  abstract getDatabaseUrl(options?: DatabaseConnectionOptions): Promise<string>;

  // executes function as transaction
  abstract executeTransaction(func: (options?: DatabaseConnectionOptions) => Promise<any>): Promise<any>;

  // checks if caller has authority to manage status based on authorization credentials
  abstract hasAuthority(options?: DatabaseConnectionOptions): Promise<boolean>;

  // creates database
  abstract createDatabase(options?: DatabaseConnectionOptions): Promise<void>;

  // creates database table
  abstract createDatabaseTable(tableName: string, options?: DatabaseConnectionOptions): Promise<void>;

  // creates database tables
  async createDatabaseTables(options?: DatabaseConnectionOptions): Promise<void> {
    const tableNames = this.getDatabaseTableNames();
    for (const tableName of tableNames) {
      try {
        await this.createDatabaseTable(tableName, options);
      } catch (error: any) {
        throw new InternalServerError({
          message: `Unable to create database table "${tableName}": ${error.message}`
        });
      }
    }
  }

  // creates database resources
  async createDatabaseResources(options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createDatabase(options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create database "${this.databaseName}": ${error.message}`
      });
    }
    await this.createDatabaseTables(options);
  }

  // initializes database resources
  async initializeDatabaseResources(options?: DatabaseConnectionOptions): Promise<void> {
    // retrieve signing material
    const {
      didMethod,
      didSeed,
      didWebUrl
    } = this;
    const { issuerDid } = await getSigningMaterial({
      didMethod,
      didSeed,
      didWebUrl
    });

    // create and persist status config record
    const statusCredentialId = this.generateStatusCredentialId();
    const configRecord: ConfigRecord = {
      id: uuid(),
      statusCredentialSiteOrigin: this.statusCredentialSiteOrigin,
      latestStatusCredentialId: statusCredentialId,
      latestCredentialsIssuedCounter: 0,
      allCredentialsIssuedCounter: 0
    };
    await this.createConfigRecord(configRecord, options);

    // compose status credential
    const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
    let statusCredential = await composeStatusCredential({
      issuerDid,
      credentialId: statusCredentialUrl
    });

    // sign status credential if necessary
    if (this.signStatusCredential) {
      statusCredential = await signCredential({
        credential: statusCredential,
        didMethod,
        didSeed,
        didWebUrl
      });
    }

    // create and persist status credential record
    await this.createStatusCredentialRecord({
      id: statusCredentialId,
      credential: statusCredential
    }, options);
  }

  // checks if database exists
  abstract databaseExists(options?: DatabaseConnectionOptions): Promise<boolean>;

  // checks if database table exists
  abstract databaseTableExists(tableName: string, options?: DatabaseConnectionOptions): Promise<boolean>;

  // checks if database tables exist
  async databaseTablesExist(options?: DatabaseConnectionOptions): Promise<boolean> {
    const tableNames = this.getDatabaseTableNames();
    const config = await this.getConfigRecord(options);
    for (const tableName of tableNames) {
      // these tables are only required after credentials have been issued
      if (
        tableName === this.eventTableName ||
        tableName === this.credentialEventTableName
      ) {
        if (config.allCredentialsIssuedCounter === 0) {
          continue;
        }
      }
      let tableExists;
      try {
        tableExists = await this.databaseTableExists(tableName, options);
      } catch (error: any) {
        throw new InternalServerError({
          message: `Unable to check for database table existence: ${error.message}`
        });
      }
      if (!tableExists) {
        return false;
      }
    }
    return true;
  }

  // checks if database table is empty
  abstract databaseTableEmpty(tableName: string, options?: DatabaseConnectionOptions): Promise<boolean>;

  // checks if database tables are empty
  async databaseTablesEmpty(options?: DatabaseConnectionOptions): Promise<boolean> {
    const tableNames = this.getDatabaseTableNames();
    const config = await this.getConfigRecord(options);
    for (const tableName of tableNames) {
      // these tables are only required after credentials have been issued
      if (
        tableName === this.eventTableName ||
        tableName === this.credentialEventTableName
      ) {
        if (config.allCredentialsIssuedCounter === 0) {
          continue;
        }
      }
      let tableEmpty;
      try {
        tableEmpty = await this.databaseTableEmpty(tableName, options);
      } catch (error: any) {
        throw new InternalServerError({
          message: `Unable to check for database table emptiness: ${error.message}`
        });
      }
      if (!tableEmpty) {
        return false;
      }
    }
    return true;
  }

  // retrieves database state
  async getDatabaseState(options?: DatabaseConnectionOptions): Promise<GetDatabaseStateResult> {
    try {
      // retrieve config
      const {
        statusCredentialSiteOrigin,
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        allCredentialsIssuedCounter
      } = await this.getConfigRecord(options);

      // ensure that the status credential site origins match
      if (this.statusCredentialSiteOrigin !== statusCredentialSiteOrigin) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'There is a mismatch between the site origin ' +
              'that you instantiated this credential status manager with ' +
              `(${statusCredentialSiteOrigin}) ` +
              'and the site origin that you are trying to use now ' +
              `(${this.statusCredentialSiteOrigin}).`
          })
        };
      }

      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;
      const statusCredentials = await this.getAllStatusCredentials(options);

      // ensure that status is consistent
      let hasLatestStatusCredentialId = false;
      const invalidStatusCredentialIds = [];
      for (const statusCredential of statusCredentials) {
        // ensure that status credential has valid type
        if (typeof statusCredential === 'string') {
          return {
            valid: false,
            error: new InvalidDatabaseStateError({
              message: 'This library does not support compact JWT ' +
                `status credentials: ${statusCredential}`
            })
          };
        }

        // ensure that status credential is well formed
        const statusCredentialSubjectObject = getCredentialSubjectObject(statusCredential);
        hasLatestStatusCredentialId = hasLatestStatusCredentialId || (statusCredential.id?.endsWith(latestStatusCredentialId) ?? false);
        const hasValidStatusCredentialType = statusCredential.type.includes(STATUS_CREDENTIAL_TYPE);
        const hasValidStatusCredentialSubId = statusCredentialSubjectObject.id?.startsWith(statusCredentialUrl) ?? false;
        const hasValidStatusCredentialSubType = statusCredentialSubjectObject.type === STATUS_CREDENTIAL_SUBJECT_TYPE;
        const hasValidStatusCredentialSubStatusPurpose = statusCredentialSubjectObject.statusPurpose === StatusPurpose.Revocation;
        const hasValidStatusCredentialFormat = hasValidStatusCredentialType &&
                                               hasValidStatusCredentialSubId &&
                                               hasValidStatusCredentialSubType &&
                                               hasValidStatusCredentialSubStatusPurpose;
        if (!hasValidStatusCredentialFormat) {
          invalidStatusCredentialIds.push(statusCredential.id);
        }
      }
      if (invalidStatusCredentialIds.length !== 0) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'Status credentials with the following IDs ' +
              'have an invalid format: ' +
              `${invalidStatusCredentialIds.map(id => `"${id as string}"`).join(', ')}`
          })
        };
      }

      // ensure that latest status credential is being tracked in the config
      if (!hasLatestStatusCredentialId) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: `Latest status credential ("${latestStatusCredentialId}") ` +
              'is not being tracked in config.'
          })
        };
      }

      // retrieve credential IDs from event log
      const credentialIds = await this.getAllCredentialIds(options);
      const credentialIdsCounter = credentialIds.length;
      const credentialsIssuedCounter = (statusCredentials.length - 1) *
                                       CREDENTIAL_STATUS_LIST_SIZE +
                                       latestCredentialsIssuedCounter;
      const hasValidEventsLogToConfig = credentialIdsCounter === allCredentialsIssuedCounter;
      const hasValidEventsConfigToReality = allCredentialsIssuedCounter === credentialsIssuedCounter;

      if (!hasValidEventsLogToConfig) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'There is a mismatch between the credentials tracked ' +
              `in the event log (${credentialIdsCounter}) ` +
              'and the credentials tracked ' +
              `in the config (${allCredentialsIssuedCounter}).`
          })
        };
      }

      if (!hasValidEventsConfigToReality) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'There is a mismatch between the credentials tracked ' +
              `in the config (${allCredentialsIssuedCounter}) ` +
              'and the credentials tracked ' +
              `in reality (${credentialsIssuedCounter}).`
          })
        };
      }

      // ensure that all checks pass
      return { valid: true };
    } catch (error: any) {
      return {
        valid: false,
        error: new InvalidDatabaseStateError({ message: error.message })
      };
    }
  }

  // creates single database record
  abstract createRecord<T>(tableName: string, record: T, options?: DatabaseConnectionOptions): Promise<void>;

  // creates status credential record
  async createStatusCredentialRecord(statusCredentialRecord: StatusCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.statusCredentialTableName, statusCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create status credential: ${error.message}`
      });
    }
  }

  // creates config record
  async createConfigRecord(configRecord: ConfigRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.configTableName, configRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create config: ${error.message}`
      });
    }
  }

  // creates event record
  async createEventRecord(eventRecord: EventRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.eventTableName, eventRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event: ${error.message}`
      });
    }
  }

  // creates credential event record
  async createCredentialEventRecord(credentialEventRecord: CredentialEventRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.credentialEventTableName, credentialEventRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event for credential: ${error.message}`
      });
    }
  }

  // updates single database record
  abstract updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: DatabaseConnectionOptions): Promise<void>;

  // updates status credential record
  async updateStatusCredentialRecord(statusCredentialRecord: StatusCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      const { id } = statusCredentialRecord;
      await this.updateRecord(this.statusCredentialTableName, 'id', id, statusCredentialRecord, options);
    } catch (error: any) {
      if (error instanceof WriteConflictError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to update status credential: ${error.message}`
      });
    }
  }

  // updates config record
  async updateConfigRecord(configRecord: ConfigRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      const { id } = configRecord;
      await this.updateRecord(this.configTableName, 'id', id, configRecord, options);
    } catch (error: any) {
      if (error instanceof WriteConflictError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to update config: ${error.message}`
      });
    }
  }

  // updates credential event record
  async updateCredentialEventRecord(credentialEventRecord: CredentialEventRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      const { credentialId } = credentialEventRecord;
      await this.updateRecord(this.credentialEventTableName, 'credentialId', credentialId, credentialEventRecord, options);
    } catch (error: any) {
      if (error instanceof WriteConflictError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to update event for credential: ${error.message}`
      });
    }
  }

  // retrieves any database record
  abstract getAnyRecord<T>(tableName: string, options?: DatabaseConnectionOptions): Promise<T | null>;

  // retrieves config ID
  async getConfigId(options?: DatabaseConnectionOptions): Promise<string> {
    let record;
    try {
      record = await this.getAnyRecord(this.configTableName, options);
      if (!record) {
        throw new NotFoundError({
          message: 'Unable to find config.'
        });
      }
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to get config ID: ${error.message}`
      });
    }
    return (record as ConfigRecord).id;
  }

  // retrieves single database record by field
  abstract getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: DatabaseConnectionOptions): Promise<T | null>;

  // retrieves single database record by id
  async getRecordById<T>(tableName: string, id: string, options?: DatabaseConnectionOptions): Promise<T | null> {
    return this.getRecordByField(tableName, 'id', id, options);
  }

  // retrieves status credential record by ID
  async getStatusCredentialRecordById(statusCredentialId: string, options?: DatabaseConnectionOptions): Promise<StatusCredentialRecord> {
    let record;
    try {
      record = await this.getRecordById(this.statusCredentialTableName, statusCredentialId, options);
      if (!record) {
        throw new NotFoundError({
          message: `Unable to find status credential with ID "${statusCredentialId}".`
        });
      }
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to get status credential with ID "${statusCredentialId}": ${error.message}`
      });
    }
    return record as StatusCredentialRecord;
  }

  // retrieves status credential by ID
  async getStatusCredential(statusCredentialId?: string, options?: DatabaseConnectionOptions): Promise<VerifiableCredential> {
    let statusCredentialFinal;
    if (statusCredentialId) {
      statusCredentialFinal = statusCredentialId;
    } else {
      ({ latestStatusCredentialId: statusCredentialFinal } = await this.getConfigRecord(options));
    }
    const { credential } = await this.getStatusCredentialRecordById(statusCredentialFinal, options);
    return credential;
  }

  // retrieves config by ID
  async getConfigRecord(options?: DatabaseConnectionOptions): Promise<ConfigRecord> {
    let configId;
    let record;
    try {
      configId = await this.getConfigId(options);
      record = await this.getRecordById(this.configTableName, configId, options);
      if (!record) {
        throw new NotFoundError({
          message: `Unable to find config with ID "${configId}".`
        });
      }
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to get config with ID "${configId}": ${error.message}`
      });
    }
    return record as ConfigRecord;
  }

  // retrieves latest event featuring credential with given ID
  async getLatestEventRecordForCredential(credentialId: string, options?: DatabaseConnectionOptions): Promise<EventRecord | null> {
    let eventRecord;
    try {
      const credentialEventRecord = await this.getRecordByField<CredentialEventRecord>(this.credentialEventTableName, 'credentialId', credentialId, options);
      if (!credentialEventRecord) {
        return null;
      }
      const { eventId } = credentialEventRecord;
      eventRecord = await this.getRecordById(this.eventTableName, eventId, options);
      if (!eventRecord) {
        return null;
      }
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get latest event for credential with ID "${credentialId}": ${error.message}`
      });
    }
    return eventRecord as EventRecord;
  }

  // retrieves all records in table
  abstract getAllRecords<T>(tableName: string, options?: DatabaseConnectionOptions): Promise<T[]>;

  // retrieves all status credential records
  async getAllStatusCredentialRecords(options?: DatabaseConnectionOptions): Promise<StatusCredentialRecord[]> {
    return this.getAllRecords(this.statusCredentialTableName, options);
  }

  // retrieves all credential event records
  async getAllCredentialEventRecords(options?: DatabaseConnectionOptions): Promise<EventRecord[]> {
    return this.getAllRecords(this.credentialEventTableName, options);
  }

  // retrieves all credential IDs
  async getAllCredentialIds(options?: DatabaseConnectionOptions): Promise<string[]> {
    let credentialIds = [];
    try {
      const credentialEventRecords = await this.getAllCredentialEventRecords(options);
      credentialIds = credentialEventRecords.map(e => e.credentialId);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get all credential IDs: ${error.message}`
      });
    }
    return credentialIds;
  }

  // retrieves all status credentials
  async getAllStatusCredentials(options?: DatabaseConnectionOptions): Promise<VerifiableCredential[]> {
    let statusCredentials = [];
    try {
      const statusCredentialRecords = await this.getAllStatusCredentialRecords(options);
      statusCredentials = statusCredentialRecords.map(r => r.credential);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get all status credentials: ${error.message}`
      });
    }
    return statusCredentials;
  }
}

// composes BitstringStatusListCredential
export async function composeStatusCredential({
  issuerDid,
  credentialId,
  statusList,
  statusPurpose = StatusPurpose.Revocation
}: ComposeStatusCredentialOptions): Promise<VerifiableCredential> {
  // determine whether or not to create a new status credential
  if (!statusList) {
    statusList = await createList({ length: CREDENTIAL_STATUS_LIST_SIZE });
  }

  // create status credential
  let credential = await createCredential({
    id: credentialId,
    list: statusList,
    statusPurpose
  });
  credential = {
    ...credential,
    issuer: issuerDid,
    validFrom: getDateString()
  };

  return credential;
}
