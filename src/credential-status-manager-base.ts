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
  MAX_CREDENTIAL_ID_LENGTH,
  getCredentialSubjectObject,
  getDateString,
  getSigningMaterial,
  isValidCredentialId,
  signCredential,
  validateCredential
} from './helpers.js';

// Number of credentials tracked in a list
const CREDENTIAL_STATUS_LIST_SIZE = 100000;

// Length of status credential ID
const STATUS_CREDENTIAL_ID_LENGTH = 20;

// Character set of status credential ID
const STATUS_CREDENTIAL_ID_CHAR_SET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

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
  statusCredentialInfo: StatusCredentialInfo;
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
  databasePassword?: string;
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

  /**
   * Constructs instance of BaseCredentialStatusManager
   * 
   * @param {BaseCredentialStatusManagerOptions} [options] - Credential status attachment options.
   */
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

  /**
   * Ensures valid configuration of credential status manager
   * 
   * @returns {void}
   */
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

  /**
   * Retrieves database name
   * 
   * @returns {string[]} Returns database name.
   */
  getDatabaseName(): string {
    return this.databaseName;
  }

  /**
   * Retrieves database table names
   * 
   * @returns {string[]} Returns database table names.
   */
  getDatabaseTableNames(): string[] {
    return [
      this.statusCredentialTableName,
      this.userCredentialTableName,
      this.eventTableName,
      this.credentialEventTableName,
      this.configTableName
    ];
  }

  /**
   * Generates new status credential ID
   * Note: We assume this method will never generate an ID that
   * has previously been generated for a status credential in this system
   * 
   * @returns {string} Returns new status credential ID.
   */
  generateStatusCredentialId(): string {
    let statusCredentialId = '';
    const charSetLength = STATUS_CREDENTIAL_ID_CHAR_SET.length;
    for (let i = 0; i < STATUS_CREDENTIAL_ID_LENGTH; i++) {
      statusCredentialId += STATUS_CREDENTIAL_ID_CHAR_SET.charAt(Math.floor(Math.random() * charSetLength));
    }
    return statusCredentialId;
  }

  /**
   * Generates new user credential ID
   * Note: We assume this method will never generate an ID that
   * has previously been generated for a user credential in this system
   * 
   * @returns {string} Returns new user credential ID.
   */
  generateUserCredentialId(): string {
    return `urn:uuid:${uuid()}`;
  }

  /**
   * Composes credentialStatus field of credential
   * 
   * @param {CredentialStatusInfo} [credentialStatusInfo] - Credential status info.
   *
   * @returns {any} Returns credentialStatus field of credential.
   */
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

  /**
   * Attaches status to credential
   * 
   * @param {AttachCredentialStatusOptions} [options] - Credential status attachment options.
   *
   * @returns {Promise<AttachCredentialStatusResult>} Resolves to metadata associated with attached credential status.
   */
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
    } else {
      if (!isValidCredentialId(credentialCopy.id)) {
        throw new BadRequestError({
          message: 'The credential ID must be a URL, UUID, or DID ' +
            `that is no more than ${MAX_CREDENTIAL_ID_LENGTH} characters in length.`
        });
      }
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
      let credentialRecord;
      try {
        credentialRecord = await this.getUserCredentialRecordById(credentialCopy.id, options);
      } catch (error) {}

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
          credentialsIssuedCounter,
          statusCredentialInfo,
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
      credentialsIssuedCounter,
      statusCredentialInfo,
      ...configRecordRest
    };
  }

  /**
   * Allocates status for credential
   *
   * @param {AllocateStatusOptions} [options={}] - The options to use.
   * 
   * @param {VerifiableCredential} [options.credential] - The credential for which to allocate status.
   * @param {StatusPurpose[]} [options.statusPurposes] - The statuses to allocate for the credential.
   *
   * @throws {BadRequestError} If credential is in JWT format.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to new credential with status.
   */
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
      const { issuerDid } = await getSigningMaterial({
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

  /**
   * Allocates revocation status for credential
   * 
   * @param {VerifiableCredential} [credential] - The credential for which to allocate revocation status.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to new credential with revocation status.
   */
  async allocateRevocationStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: [StatusPurpose.Revocation] });
  }

  /**
   * Allocates suspension status for credential
   * 
   * @param {VerifiableCredential} [credential] - The credential for which to allocate suspension status.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to new credential with suspension status.
   */
  async allocateSuspensionStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: [StatusPurpose.Suspension] });
  }

  /**
   * Allocates all supported statuses for credential
   * 
   * @param {VerifiableCredential} [credential] - The credential for which to allocate all supported statuses.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to new credential with all supported statuses.
   */
  async allocateSupportedStatuses(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.allocateStatus({ credential, statusPurposes: SUPPORTED_STATUS_PURPOSES });
  }

  /**
   * Determines if credential status info should be updated
   *
   * @param {ShouldUpdateCredentialStatusInfoOptions} [options] - Credential status update determination options.
   *
   * @returns {boolean} Returns whether credential status info should be updated.
   */
  shouldUpdateCredentialStatusInfo({
    statusInfo, statusPurpose, invalidate
  }: ShouldUpdateCredentialStatusInfoOptions): boolean {
    // prevent activation of credentials that have been revoked
    const revoked = !statusInfo[StatusPurpose.Revocation].valid;
    if (revoked && !(statusPurpose === StatusPurpose.Revocation && invalidate)) {
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

  /**
   * Updates status for credential
   *
   * @param {UpdateStatusOptions} [options={}] - The options to use.
   * 
   * @param {string} [options.credentialId] - The ID of the credential for which to update status.
   * @param {StatusPurpose} [options.statusPurpose] - The status to update for the credential.
   * @param {boolean} [options.invalidate] - Whether to invalidate the status of the credential for the given purpose.
   *
   * @throws {BadRequestError} If the credential is not being tracked for the given purpose
   *   or if the status credential is in JWT format.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to updated status credential.
   */
  async updateStatus({
    credentialId,
    statusPurpose,
    invalidate
  }: UpdateStatusOptions): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: DatabaseConnectionOptions) => {
      // retrieve record for credential with given ID
      const credentialRecordBefore = await this.getUserCredentialRecordById(credentialId, options);

      // retrieve relevant credential info
      const { statusInfo, ...credentialRecordBeforeRest } = credentialRecordBefore;

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
      const { issuerDid } = await getSigningMaterial({
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
      const credentialRecordAfter: UserCredentialRecord = {
        statusInfo: {
          ...statusInfo,
          [statusPurpose]: {
            ...statusInfo[statusPurpose],
            valid: !valid
          }
        },
        ...credentialRecordBeforeRest
      };
      await this.updateUserCredentialRecord(credentialRecordAfter, options);

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

  /**
   * Revokes credential
   * 
   * @param {string} [credentialId] - The ID of the credential to revoke.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to updated status credential.
   */
  async revokeCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({
      credentialId,
      statusPurpose: StatusPurpose.Revocation,
      invalidate: true
    });
  }

  /**
   * Suspends credential
   * 
   * @param {string} [credentialId] - The ID of the credential to suspend.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to updated status credential.
   */
  async suspendCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({
      credentialId,
      statusPurpose: StatusPurpose.Suspension,
      invalidate: true
    });
  }

  /**
   * Lifts suspension from credential
   * 
   * @param {string} [credentialId] - The ID of the credential for which to lift suspension.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to updated status credential.
   */
  async unsuspendCredential(credentialId: string): Promise<VerifiableCredential> {
    return this.updateStatus({
      credentialId,
      statusPurpose: StatusPurpose.Suspension,
      invalidate: false
    });
  }

  /**
   * Retrieves status of credential with given ID
   *
   * @param {string} [credentialId] - The ID of the credential for which to retrieve status.
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<CredentialStatusInfo>} Resolves to credential status info.
   */
  async getStatus(credentialId: string, options?: DatabaseConnectionOptions): Promise<CredentialStatusInfo> {
    // retrieve user credential record
    const record = await this.getUserCredentialRecordById(credentialId, options);
    return record.statusInfo;
  }

  /**
   * Retrieves database URL
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<string>} Resolves to database URL.
   */
  abstract getDatabaseUrl(options?: DatabaseConnectionOptions): Promise<string>;

  /**
   * Executes function as transaction
   * 
   * @param {Function} [func] - Function to execute as transaction.
   *   This function accepts database connection options.
   *
   * @returns {Promise<any>} Resolves to the return value and performs the side effects of func.
   */
  abstract executeTransaction(func: (options?: DatabaseConnectionOptions) => Promise<any>): Promise<any>;

  /**
   * Determines if caller has authority to manage status based on authorization credentials
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether caller has the authority
   *   to manage status, based on database connection options.
   */
  abstract hasAuthority(options?: DatabaseConnectionOptions): Promise<boolean>;

  /**
   * Creates database
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  abstract createDatabase(options?: DatabaseConnectionOptions): Promise<void>;

  /**
   * Creates database
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  abstract createDatabaseTable(tableName: string, options?: DatabaseConnectionOptions): Promise<void>;

  /**
   * Creates database tables
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Creates database resources
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Initializes database resources
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Determines if database exists
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether database exists.
   */
  abstract databaseExists(options?: DatabaseConnectionOptions): Promise<boolean>;

  /**
   * Determines if database table exists
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether database table exists.
   */
  abstract databaseTableExists(tableName: string, options?: DatabaseConnectionOptions): Promise<boolean>;

  /**
   * Determines if database tables exist
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether database tables exist.
   */
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

  /**
   * Determines if database table is empty
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether database table is empty.
   */
  abstract databaseTableEmpty(tableName: string, options?: DatabaseConnectionOptions): Promise<boolean>;

  /**
   * Determines if database tables are empty
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether database tables are empty.
   */
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

  /**
   * Retrieves database state
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<GetDatabaseStateResult>} Resolves to database state.
   */
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
      // Note: This is the number of credentials that would be issued if
      // every credential is assigned to every status purpose, but it is
      // possible to assign a credential to fewer purposes than the total
      // number of supported purposes in a given deployment
      let maxCredentialsIssuedCounter = 0;
      for (const statusPurpose of statusPurposes) {
        // retrieve info for latest status credential
        const {
          latestStatusCredentialId,
          latestCredentialsIssuedCounter,
          statusCredentialsCounter
        } = statusCredentialInfo[statusPurpose];
        const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestStatusCredentialId}`;

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

        // ensure that all status credentials for this purpose are valid
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

        // ensure that the latest status credential for this purpose is being tracked in the config
        if (!hasLatestStatusCredentialId) {
          return {
            valid: false,
            error: new InvalidDatabaseStateError({
              message: `Latest status credential for the ${statusPurpose} purpose ` +
                `("${latestStatusCredentialId}") is not being tracked in the config.`
            })
          };
        }

        // accumulate credential issuance counter from all status purposes
        maxCredentialsIssuedCounter += (statusCredentialsCounter - 1) *
                                       CREDENTIAL_STATUS_LIST_SIZE +
                                       latestCredentialsIssuedCounter;
      }

      // retrieve credential IDs from event log
      const credentialIds = await this.getAllUserCredentialIds(options);
      const credentialIdsCounter = credentialIds.length;
      const hasValidIssuedCounterCredentialToConfig = credentialIdsCounter === credentialsIssuedCounter;
      const hasValidIssuedCounterConfigToMax = credentialsIssuedCounter <= maxCredentialsIssuedCounter;

      // ensure alignment between the number of records in the credential table
      // and the number of credentials tracked in the config table
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

      // ensure that the number of credentials does not exceed the max
      // number of credentials that can be issued in this deployment
      if (!hasValidIssuedCounterConfigToMax) {
        return {
          valid: false,
          error: new InvalidDatabaseStateError({
            message: 'The number of credentials tracked ' +
              `in the config (${credentialsIssuedCounter}) ` +
              'exceeds the max number of credentials that could have ' +
              `been issued in this deployment (${maxCredentialsIssuedCounter}).`
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

  /**
   * Creates single database record
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {T} [record] - Database record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  abstract createRecord<T>(tableName: string, record: T, options?: DatabaseConnectionOptions): Promise<void>;

  /**
   * Creates status credential record
   * 
   * @param {StatusCredentialRecord} [statusCredentialRecord] - Status credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  async createStatusCredentialRecord(statusCredentialRecord: StatusCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.statusCredentialTableName, statusCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create status credential: ${error.message}`
      });
    }
  }

  /**
   * Creates user credential record
   * 
   * @param {UserCredentialRecord} [userCredentialRecord] - User credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  async createUserCredentialRecord(userCredentialRecord: UserCredentialRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.userCredentialTableName, userCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create user credential: ${error.message}`
      });
    }
  }

  /**
   * Creates config record
   * 
   * @param {ConfigRecord} [configRecord] - Config record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  async createConfigRecord(configRecord: ConfigRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.configTableName, configRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create config: ${error.message}`
      });
    }
  }

  /**
   * Creates event record
   * 
   * @param {EventRecord} [eventRecord] - Event record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  async createEventRecord(eventRecord: EventRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.eventTableName, eventRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event: ${error.message}`
      });
    }
  }

  /**
   * Creates credential event record
   * 
   * @param {CredentialEventRecord} [credentialEventRecord] - Credential event record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  async createCredentialEventRecord(credentialEventRecord: CredentialEventRecord, options?: DatabaseConnectionOptions): Promise<void> {
    try {
      await this.createRecord(this.credentialEventTableName, credentialEventRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event for credential: ${error.message}`
      });
    }
  }

  /**
   * Updates single database record
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {string} [recordIdKey] - Name of record ID key.
   * @param {string} [recordIdValue] - Value associated with recordIdKey.
   * @param {T} [record] - Database record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  abstract updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: DatabaseConnectionOptions): Promise<void>;

  /**
   * Updates status credential record
   * 
   * @param {StatusCredentialRecord} [statusCredentialRecord] - Status credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Updates user credential record
   * 
   * @param {UserCredentialRecord} [userCredentialRecord] - User credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Updates config record
   * 
   * @param {ConfigRecord} [configRecord] - Config record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Updates credential event record
   * 
   * @param {CredentialEventRecord} [credentialEventRecord] - Credential event record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
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

  /**
   * Retrieves any database record in table
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<T | null>} Resolves to database record in table, if any exist.
   */
  abstract getAnyRecord<T>(tableName: string, options?: DatabaseConnectionOptions): Promise<T | null>;

  /**
   * Retrieves config record ID
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<string>} Resolves to config record ID.
   */
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

  /**
   * Retrieves single database record by field
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {string} [fieldKey] - Name of field key.
   * @param {string} [fieldValue] - Value associated with fieldKey.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<T | null>} Resolves to matching database record in table, if any exist.
   */
  abstract getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: DatabaseConnectionOptions): Promise<T | null>;

  /**
   * Retrieves single database record by id
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {string} [id] - ID of database record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<T | null>} Resolves to matching database record in table, if any exist.
   */
  async getRecordById<T>(tableName: string, id: string, options?: DatabaseConnectionOptions): Promise<T | null> {
    return this.getRecordByField(tableName, 'id', id, options);
  }

  /**
   * Retrieves status credential record by ID
   * 
   * @param {string} [statusCredentialId] - ID of status credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<StatusCredentialRecord>} Resolves to status credential record.
   */
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

  /**
   * Retrieves status credential by ID
   * 
   * @param {string} [statusCredentialId] - ID of status credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to status credential.
   */
  async getStatusCredential(statusCredentialId: string, options?: DatabaseConnectionOptions): Promise<VerifiableCredential> {
    const { credential } = await this.getStatusCredentialRecordById(statusCredentialId, options);
    return credential;
  }

  /**
   * Retrieves user credential record by ID
   * 
   * @param {string} [userCredentialId] - ID of user credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<UserCredentialRecord>} Resolves to user credential record.
   */
  async getUserCredentialRecordById(userCredentialId: string, options?: DatabaseConnectionOptions): Promise<UserCredentialRecord> {
    let record;
    try {
      record = await this.getRecordById(this.userCredentialTableName, userCredentialId, options);
      if (!record) {
        throw new NotFoundError({
          message: `Unable to find credential with ID "${userCredentialId}".`
        });
      }
    } catch (error: any) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw new InternalServerError({
        message: `Unable to get info for credential with ID "${userCredentialId}": ${error.message}`
      });
    }
    return record as UserCredentialRecord;
  }

  /**
   * Alias for getUserCredentialRecordById
   * 
   * @param {string} [userCredentialId] - ID of user credential record.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<UserCredentialRecord>} Resolves to user credential record.
   */
  async getCredentialInfo(userCredentialId: string, options?: DatabaseConnectionOptions): Promise<UserCredentialRecord> {
    return this.getUserCredentialRecordById(userCredentialId, options);
  }

  /**
   * Retrieves config record
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<ConfigRecord>} Resolves to config record.
   */
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

  /**
   * Retrieves all database records
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<T[]>} Resolves to all records in database table.
   */
  abstract getAllRecords<T>(tableName: string, options?: DatabaseConnectionOptions): Promise<T[]>;

  /**
   * Retrieves all user credential records
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<UserCredentialRecord[]>} Resolves to all records in database table.
   */
  async getAllUserCredentialRecords(options?: DatabaseConnectionOptions): Promise<UserCredentialRecord[]> {
    return this.getAllRecords(this.userCredentialTableName, options);
  }

  /**
   * Retrieves all database records by field
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {string} [fieldKey] - Name of field key.
   * @param {string} [fieldValue] - Value associated with fieldKey.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<T[]>} Resolves to all matching records.
   */
  abstract getAllRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: DatabaseConnectionOptions): Promise<T[]>;

  /**
   * Retrieves all status credential records by purpose
   * 
   * @param {StatusPurpose} [purpose] - Status purpose.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<StatusCredentialRecord[]>} Resolves to all matching status credential records.
   */
  async getAllStatusCredentialRecordsByPurpose(purpose: StatusPurpose, options?: DatabaseConnectionOptions): Promise<StatusCredentialRecord[]> {
    return this.getAllRecordsByField(this.statusCredentialTableName, 'purpose', purpose, options);
  }

  /**
   * Retrieves all status credentials by purpose
   * 
   * @param {StatusPurpose} [purpose] - Status purpose.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<VerifiableCredential[]>} Resolves to all matching status credentials.
   */
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

  /**
   * Retrieves all user credential IDs
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<string[]>} Resolves to all user credential IDs.
   */
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

/**
 * Composes BitstringStatusListCredential
 * 
 * @param {ComposeStatusCredentialOptions} [options] - Status credential composition options.
 *
 * @returns {Promise<VerifiableCredential>} Resolves to status credential.
 */
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
