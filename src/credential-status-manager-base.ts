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
  getCredentialSubjectObject,
  getDateString,
  getSigningMaterial,
  signCredential,
  validateCredential
} from './helpers.js';

/* eslint-disable @typescript-eslint/restrict-template-expressions */
/* eslint-disable @typescript-eslint/consistent-type-assertions */

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

// Purpose of status credential
enum StatusPurpose {
  Revocation = 'revocation',
  Suspension = 'suspension'
}

// All supported status purposes
const SUPPORTED_STATUS_PURPOSES = Object.values(StatusPurpose);

// Type definition for credential status info
type CredentialStatusInfo = {
  [purpose in StatusPurpose]: {
    statusCredentialId: string;
    statusListIndex: number;
    valid: boolean;
  };
}

// Type definition for status credential info
type StatusCredentialInfo = {
  [purpose in StatusPurpose]: {
    latestStatusCredentialId: string;
    latestCredentialsIssuedCounter: number;
    statusCredentialsCounter: number;
  };
}

// Type definition for status credential record
export interface StatusCredentialRecord {
  id: string;
  purpose: StatusPurpose;
  credential: VerifiableCredential;
}

// Type definition for user credential record
interface UserCredentialRecord {
  id: string;
  issuer: string;
  subject?: string;
  statusInfo: CredentialStatusInfo;
}

// Type definition for event record
interface EventRecord {
  id: string;
  timestamp: string;
  credentialId: string;
  statusPurpose: StatusPurpose;
  valid: boolean;
}

// Type definition for credential event record
// (saves latest event for credential)
export interface CredentialEventRecord {
  credentialId: string;
  eventId: string;
}

// Type definition for credential status config record
export interface ConfigRecord {
  id: string;
  statusCredentialSiteOrigin: string;
  statusCredentialInfo: StatusCredentialInfo
  credentialsIssuedCounter: number;
}

// Type definition for composeStatusCredential function input
interface ComposeStatusCredentialOptions {
  issuerDid: string;
  credentialId: string;
  statusPurpose: StatusPurpose;
  statusList?: any;
}

// Type definition for attachCredentialStatus method input
interface AttachCredentialStatusOptions {
  credential: any;
  statusPurposes: StatusPurpose[];
}

// Type definition for attachCredentialStatus method output
type AttachCredentialStatusResult = ConfigRecord & {
  credential: any;
  credentialStatusInfo: CredentialStatusInfo;
  newUserCredential: boolean;
  newStatusCredential: {
    [purpose in StatusPurpose]: boolean;
  };
};

// Type definition for allocateStatus method input
interface AllocateStatusOptions {
  credential: VerifiableCredential;
  statusPurposes: StatusPurpose[];
}

// Type definition for updateStatus method input
interface UpdateStatusOptions {
  credentialId: string;
  statusPurpose: StatusPurpose;
  invalidate: boolean;
}

// Type definition for shouldUpdateCredentialStatusInfo method input
interface ShouldUpdateCredentialStatusInfoOptions {
  statusInfo: CredentialStatusInfo;
  statusPurpose: StatusPurpose;
  invalidate: boolean;
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
  userCredentialTableName?: string;
  eventTableName?: string;
  credentialEventTableName?: string;
  configTableName?: string;
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
  protected readonly userCredentialTableName: string;
  protected readonly eventTableName: string;
  protected readonly credentialEventTableName: string;
  protected readonly configTableName: string;
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
      userCredentialTableName,
      eventTableName,
      credentialEventTableName,
      configTableName,
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
    this.userCredentialTableName = userCredentialTableName ?? 'UserCredential';
    this.eventTableName = eventTableName ?? 'Event';
    this.credentialEventTableName = credentialEventTableName ?? 'CredentialEvent';
    this.configTableName = configTableName ?? 'Config';
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
      this.userCredentialTableName,
      this.eventTableName,
      this.credentialEventTableName,
      this.configTableName
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

  // composes credentialStatus field of credential
  composeCredentialStatus(credentialStatusInfo: CredentialStatusInfo): any {
    let credentialStatus: any = [];
    for (const [statusPurpose, statusData] of Object.entries(credentialStatusInfo)) {
      const { statusCredentialId, statusListIndex } = statusData;
      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
      const credentialStatusId = `${statusCredentialUrl}#${statusListIndex}`;
      credentialStatus.push({
        id: credentialStatusId,
        type: CREDENTIAL_STATUS_TYPE,
        statusPurpose,
        statusListCredential: statusCredentialUrl,
        statusListIndex: statusListIndex.toString()
      });
    }
    if (credentialStatus.length === 1) {
      credentialStatus = credentialStatus[0];
    }
    return credentialStatus;
  }

  // attaches status to credential
  async attachCredentialStatus({ credential, statusPurposes }: AttachCredentialStatusOptions, options?: DatabaseConnectionOptions): Promise<AttachCredentialStatusResult> {
    // copy credential and delete appropriate fields
    const credentialCopy = Object.assign({}, credential);
    delete credentialCopy.credentialStatus;
    delete credentialCopy.proof;

    // ensure that credential has ID
    let credentialContainsId = true;
    if (!credentialCopy.id) {
      credentialContainsId = false;
      // Note: This assumes that uuid will never generate an ID that
      // conflicts with an ID that has already been tracked in the event log
      credentialCopy.id = this.generateUserCredentialId();
    }

    // validate credential before attaching status
    validateCredential(credentialCopy);

    // retrieve config
    let {
      statusCredentialInfo,
      credentialsIssuedCounter,
      ...configRecordRest
    } = await this.getConfigRecord(options);

    // only search for credential if it was passed with an ID
    if (credentialContainsId) {
      // retrieve record for credential with given ID
      const credentialRecord = await this.getUserCredentialRecordById(credentialCopy.id, options);

      // do not allocate new entry if ID is already being tracked
      if (credentialRecord) {
        // retrieve relevant credential data
        const { statusInfo } = credentialRecord;

        // compose credentialStatus field of credential
        const credentialStatus = this.composeCredentialStatus(statusInfo);

        // compose newStatusCredential, which determines whether to create
        // a new status credential by purpose
        const newStatusCredentialEntries =
          Object.keys(statusInfo).map(purpose => {
            return [purpose, false];
          });
        const newStatusCredential = Object.fromEntries(newStatusCredentialEntries);

        return {
          credential: {
            ...credentialCopy,
            credentialStatus
          },
          newStatusCredential,
          newUserCredential: false,
          credentialStatusInfo: statusInfo,
          statusCredentialInfo,
          credentialsIssuedCounter,
          ...configRecordRest
        };
      }
    }

    // compose credentialStatus field of credential
    const statusInfo = {} as CredentialStatusInfo;
    const newStatusCredential = {} as { [purpose in StatusPurpose]: boolean };
    for (const statusPurpose of statusPurposes) {
      let {
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        statusCredentialsCounter
      } = statusCredentialInfo[statusPurpose];

      // allocate new entry if ID is not yet being tracked
      newStatusCredential[statusPurpose] = false;
      if (latestCredentialsIssuedCounter >= CREDENTIAL_STATUS_LIST_SIZE) {
        newStatusCredential[statusPurpose] = true;
        latestCredentialsIssuedCounter = 0;
        latestStatusCredentialId = this.generateStatusCredentialId();
        statusCredentialsCounter++;
      }
      latestCredentialsIssuedCounter++;

      // update status credential info
      statusCredentialInfo[statusPurpose] = {
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        statusCredentialsCounter
      };

      // update credential status info
      statusInfo[statusPurpose] = {
        statusCredentialId: latestStatusCredentialId,
        statusListIndex: latestCredentialsIssuedCounter,
        valid: true
      };
    }
    const credentialStatus = this.composeCredentialStatus(statusInfo);
    credentialsIssuedCounter++;

    return {
      credential: {
        ...credentialCopy,
        credentialStatus
      },
      newStatusCredential,
      newUserCredential: true,
      credentialStatusInfo: statusInfo,
      statusCredentialInfo,
      credentialsIssuedCounter,
      ...configRecordRest
    };
  }

  // allocates status for credential
  async allocateStatus({ credential, statusPurposes }: AllocateStatusOptions): Promise<VerifiableCredential> {
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
        newStatusCredential,
        newUserCredential,
        credentialStatusInfo,
        statusCredentialInfo,
        ...attachCredentialStatusResultRest
      } = await this.attachCredentialStatus({ credential, statusPurposes }, options);

      // retrieve signing material
      const {
        didMethod,
        didSeed,
        didWebUrl,
        signStatusCredential,
        signUserCredential
      } = this;
      const {
        issuerDid
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

      // create status credential for each purpose
      for (const [statusPurpose, newStatusCred] of Object.entries(newStatusCredential)) {
        // compose new status credential only if the last one has reached capacity
        const { latestStatusCredentialId } = statusCredentialInfo[statusPurpose as StatusPurpose];
        if (newStatusCred) {
          const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;
          let statusCredential = await composeStatusCredential({
            issuerDid,
            credentialId: statusCredentialUrl,
            statusPurpose: statusPurpose as StatusPurpose
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

          // create status credential record
          await this.createStatusCredentialRecord({
            id: latestStatusCredentialId,
            purpose: statusPurpose as StatusPurpose,
            credential: statusCredential
          }, options);
        }
      }

      // create user credential record
      const credentialId = credentialWithStatus.id as string;
      const credentialSubjectObject = getCredentialSubjectObject(credentialWithStatus);
      const credentialRecord: UserCredentialRecord = {
        id: credentialId,
        issuer: issuerDid,
        subject: credentialSubjectObject?.id,
        statusInfo: credentialStatusInfo
      };
      await this.createUserCredentialRecord(credentialRecord, options);

      // create a new event and credential event record for each purpose
      const timestamp = getDateString();
      for (const statusPurpose of statusPurposes) {
        // create new event record
        const eventId = uuid();
        const event: EventRecord = {
          id: eventId,
          timestamp,
          credentialId,
          statusPurpose,
          valid: true
        };
        await this.createEventRecord(event, options);
        await this.createCredentialEventRecord({
          credentialId,
          eventId
        }, options);
      }

      // update config record
      await this.updateConfigRecord({
        statusCredentialInfo,
        ...attachCredentialStatusResultRest
      }, options);

      return credentialWithStatus;
    });
  }

  // allocates revocation status for credential
  async allocateRevocationStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: [StatusPurpose.Revocation] });
  }

  // allocates suspension status for credential
  async allocateSuspensionStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: [StatusPurpose.Suspension] });
  }

  // allocates all supported statuses
  async allocateAllStatuses(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: SUPPORTED_STATUS_PURPOSES });
  }

  // updates status of credential
  async updateStatus({
    credentialId, statusPurpose, invalidate
  }: UpdateStatusOptions): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: DatabaseConnectionOptions) => {
      // retrieve record for credential with given ID
      const oldCredentialRecord = await this.getUserCredentialRecordById(credentialId, options);

      // unable to find credential with given ID
      if (!oldCredentialRecord) {
        throw new NotFoundError({
          message: `Unable to find credential with ID "${credentialId}".`
        });
      }

      // retrieve relevant credential info
      const { statusInfo, ...oldCredentialRecordRest } = oldCredentialRecord;

      // report error when caller attempts to allocate for an unavailable purpose
      const availablePurposes = Object.keys(statusInfo) as StatusPurpose[];
      if (!availablePurposes.includes(statusPurpose)) {
        throw new BadRequestError({
          message:
            `This credential does not contain ${statusPurpose} status info.`
        });
      }

      // retrieve relevant credential status info
      const { statusCredentialId, statusListIndex, valid } = statusInfo[statusPurpose];

      // retrieve status credential
      const statusCredentialBefore = await this.getStatusCredential(statusCredentialId, options);

      // report error for compact JWT credentials
      if (typeof statusCredentialBefore === 'string') {
        throw new BadRequestError({
          message: 'This library does not support compact JWT credentials.'
        });
      }

      // determine if credential status info should be updated
      const shouldUpdate = this.shouldUpdateCredentialStatusInfo({
        statusInfo, statusPurpose, invalidate
      });

      // if no update is required, report status credential to caller as is
      if (!shouldUpdate) {
        return statusCredentialBefore;
      }

      // retrieve signing material
      const {
        didMethod,
        didSeed,
        didWebUrl,
        signStatusCredential
      } = this;
      const {
        issuerDid
      } = await getSigningMaterial({
        didMethod,
        didSeed,
        didWebUrl
      });

      // update status credential
      const statusCredentialSubjectObjectBefore = getCredentialSubjectObject(statusCredentialBefore);
      const statusCredentialListEncodedBefore = statusCredentialSubjectObjectBefore.encodedList;
      const statusCredentialListDecoded = await decodeList({
        encodedList: statusCredentialListEncodedBefore
      });
      statusCredentialListDecoded.setStatus(statusListIndex, invalidate);
      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
      let statusCredential = await composeStatusCredential({
        issuerDid,
        credentialId: statusCredentialUrl,
        statusList: statusCredentialListDecoded,
        statusPurpose
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

      // update status credential record
      await this.updateStatusCredentialRecord({
        id: statusCredentialId,
        purpose: statusPurpose,
        credential: statusCredential
      }, options);

      // update user credential record
      const newCredentialRecord: UserCredentialRecord = {
        statusInfo: {
          ...statusInfo,
          [statusPurpose]: {
            ...statusInfo[statusPurpose],
            valid: !valid
          }
        },
        ...oldCredentialRecordRest
      };
      await this.updateUserCredentialRecord(newCredentialRecord, options);

      // create new event record
      const eventId = uuid();
      const newEventRecord: EventRecord = {
        id: eventId,
        timestamp: getDateString(),
        credentialId,
        statusPurpose,
        valid: !invalidate
      };
      await this.createEventRecord(newEventRecord, options);
      await this.updateCredentialEventRecord({
        credentialId,
        eventId
      }, options);

      return statusCredential;
    });
  }

  // determines if credential status info should be updated
  shouldUpdateCredentialStatusInfo({
    statusInfo, statusPurpose, invalidate
  }: ShouldUpdateCredentialStatusInfoOptions): boolean {
    // prevent activation of credentials that have been revoked
    const revoked = !statusInfo[StatusPurpose.Revocation].valid;
    if (revoked && statusPurpose !== StatusPurpose.Revocation && !invalidate) {
      throw new BadRequestError({
        message:
          `This credential cannot be activated for any purpose, since it has been revoked.`
      });
    }

    // determine if the status action would lead to a change in state
    const invokedStatusInfo = statusInfo[statusPurpose];
    const { valid } = invokedStatusInfo;
    return valid === invalidate;
  }

  // revokes credential
  async revokeCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({
      credentialId,
      statusPurpose: StatusPurpose.Revocation,
      invalidate: true
    });
  }

  // suspends credential
  async suspendCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({
      credentialId,
      statusPurpose: StatusPurpose.Suspension,
      invalidate: true
    });
  }

  // retrieves status of credential with given ID
  async getStatus(credentialId: string, options?: DatabaseConnectionOptions): Promise<CredentialStatusInfo> {
    // retrieve user credential record
    const record = await this.getUserCredentialRecordById(credentialId, options);

    // unable to find credential with given ID
    if (!record) {
      throw new NotFoundError({
        message: `Unable to find credential with ID "${credentialId}".`
      });
    }

    return record.statusInfo;
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

    // compose status credential
    const statusCredentialInfo = {} as StatusCredentialInfo;
    for (const statusPurpose of SUPPORTED_STATUS_PURPOSES) {
      const statusCredentialId = this.generateStatusCredentialId();
      statusCredentialInfo[statusPurpose] = {
        latestStatusCredentialId: statusCredentialId,
        latestCredentialsIssuedCounter: 0,
        statusCredentialsCounter: 1
      };

      // compose status credential
      const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${statusCredentialId}`;
      let statusCredential = await composeStatusCredential({
        issuerDid,
        credentialId: statusCredentialUrl,
        statusPurpose
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

      // create status credential record
      await this.createStatusCredentialRecord({
        id: statusCredentialId,
        purpose: statusPurpose,
        credential: statusCredential
      }, options);
    }

    // create status config record
    const configRecord: ConfigRecord = {
      id: uuid(),
      statusCredentialSiteOrigin: this.statusCredentialSiteOrigin,
      statusCredentialInfo,
      credentialsIssuedCounter: 0
    };
    await this.createConfigRecord(configRecord, options);
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
        tableName === this.userCredentialTableName ||
        tableName === this.eventTableName ||
        tableName === this.credentialEventTableName
      ) {
        if (config.credentialsIssuedCounter === 0) {
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
        if (config.credentialsIssuedCounter === 0) {
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
        statusCredentialInfo,
        credentialsIssuedCounter
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

      // examine info for all status purposes
      const statusPurposes = Object.keys(statusCredentialInfo) as StatusPurpose[];
      let credsIssuedCounter = 0;
      for (const statusPurpose of statusPurposes) {
        const {
          latestStatusCredentialId,
          latestCredentialsIssuedCounter,
          statusCredentialsCounter
        } = statusCredentialInfo[statusPurpose];

        // ensure that status is consistent
        const statusCredentials = await this.getAllStatusCredentialsByPurpose(statusPurpose, options);
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
          const statusPurpose = statusCredentialSubjectObject.statusPurpose as StatusPurpose;
          const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;
          hasLatestStatusCredentialId = hasLatestStatusCredentialId || (statusCredential.id?.endsWith(latestStatusCredentialId) ?? false);
          const hasValidStatusCredentialType = statusCredential.type.includes(STATUS_CREDENTIAL_TYPE);
          const hasValidStatusCredentialSubId = statusCredentialSubjectObject.id?.startsWith(statusCredentialUrl) ?? false;
          const hasValidStatusCredentialSubType = statusCredentialSubjectObject.type === STATUS_CREDENTIAL_SUBJECT_TYPE;
          const hasValidStatusCredentialSubStatusPurpose = Object.values(statusPurposes).includes(statusPurpose);
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

        // accumulate credential issuance counter from all status purposes
        credsIssuedCounter += (statusCredentialsCounter - 1) *
                               CREDENTIAL_STATUS_LIST_SIZE +
                               latestCredentialsIssuedCounter;
      }

      // retrieve credential IDs from event log
      const credentialIds = await this.getAllUserCredentialIds(options);
      const credentialIdsCounter = credentialIds.length;
      const hasValidIssuedCounterCredentialToConfig = credentialIdsCounter === credentialsIssuedCounter;
      const hasValidIssuedCounterConfigToReality = credentialsIssuedCounter === credsIssuedCounter;

      // check if credential issuance counter matches between
      // credential table and config table
      if (!hasValidIssuedCounterCredentialToConfig) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'There is a mismatch between the credentials tracked ' +
              `in the credential table (${credentialIdsCounter}) ` +
              'and the credentials tracked ' +
              `in the config table (${credentialsIssuedCounter}).`
          })
        };
      }

      // check if credential issuance counter matches between
      // config table and reality
      if (!hasValidIssuedCounterConfigToReality) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'There is a mismatch between the credentials tracked ' +
              `in the config table (${credentialsIssuedCounter}) ` +
              'and the credentials tracked ' +
              `in reality (${credsIssuedCounter}).`
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

  // creates user credential record
  async createUserCredentialRecord(userCredentialRecord: UserCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.userCredentialTableName, userCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create user credential: ${error.message}`
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

  // updates user credential record
  async updateUserCredentialRecord(userCredentialRecord: UserCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      const { id } = userCredentialRecord;
      await this.updateRecord(this.userCredentialTableName, 'id', id, userCredentialRecord, options);
    } catch (error: any) {
      if (error instanceof WriteConflictError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to update user credential: ${error.message}`
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
  async getStatusCredential(statusCredentialId: string, options?: DatabaseConnectionOptions): Promise<VerifiableCredential> {
    const { credential } = await this.getStatusCredentialRecordById(statusCredentialId, options);
    return credential;
  }

  // retrieves user credential record by ID
  async getUserCredentialRecordById(userCredentialId: string, options?: DatabaseConnectionOptions): Promise<UserCredentialRecord | null> {
    let record;
    try {
      record = await this.getRecordById(this.userCredentialTableName, userCredentialId, options);
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to get user credential with ID "${userCredentialId}": ${error.message}`
      });
    }
    return record as UserCredentialRecord | null;
  }

  // retrieves config record by ID
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

  // retrieves all database records
  abstract getAllRecords<T>(tableName: string, options?: DatabaseConnectionOptions): Promise<T[]>;

  // retrieves all user credential records
  async getAllUserCredentialRecords(options?: DatabaseConnectionOptions): Promise<UserCredentialRecord[]> {
    return this.getAllRecords(this.userCredentialTableName, options);
  }

  // retrieves all database records by field
  abstract getAllRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: DatabaseConnectionOptions): Promise<T[]>;

  // retrieves all status credential records by purpose
  async getAllStatusCredentialRecordsByPurpose(purpose: StatusPurpose, options?: DatabaseConnectionOptions): Promise<StatusCredentialRecord[]> {
    return this.getAllRecordsByField(this.statusCredentialTableName, 'purpose', purpose, options);
  }

  // retrieves all status credentials by purpose
  async getAllStatusCredentialsByPurpose(purpose: StatusPurpose, options?: DatabaseConnectionOptions): Promise<VerifiableCredential[]> {
    let statusCredentials = [];
    try {
      const statusCredentialRecords = await this.getAllStatusCredentialRecordsByPurpose(purpose, options);
      statusCredentials = statusCredentialRecords
        .filter(r => r.purpose === purpose)
        .map(r => r.credential);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get all status credentials by purpose "${purpose}": ${error.message}`
      });
    }
    return statusCredentials;
  }

  // retrieves all user credential IDs
  async getAllUserCredentialIds(options?: DatabaseConnectionOptions): Promise<string[]> {
    let credentialIds = [];
    try {
      const credentialRecords = await this.getAllUserCredentialRecords(options);
      credentialIds = credentialRecords.map(e => e.id);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get all credential IDs: ${error.message}`
      });
    }
    return credentialIds;
  }
}

// composes BitstringStatusListCredential
export async function composeStatusCredential({
  issuerDid,
  credentialId,
  statusList,
  statusPurpose
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
