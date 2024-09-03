/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { createCredential, createList, decodeList } from '@digitalbazaar/vc-bitstring-status-list';
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
import { IndexAllocator } from './index-allocator.js';

// Theoretical number of credentials that CAN be tracked in a list
const MAX_CREDENTIAL_STATUS_LIST_SIZE = 100500;

// Buffer between theoretical and safe credential status list size
const CREDENTIAL_STATUS_LIST_SIZE_BUFFER = 500;

// Safe number of credentials that WILL be tracked in a list to avoid contention
const SAFE_CREDENTIAL_STATUS_LIST_SIZE = MAX_CREDENTIAL_STATUS_LIST_SIZE - CREDENTIAL_STATUS_LIST_SIZE_BUFFER;

// Length of status credential ID
const STATUS_CREDENTIAL_ID_LENGTH = 20;

// Character set of status credential ID
const STATUS_CREDENTIAL_ID_CHAR_SET = '012ABCDEFGHIJKLMnopqrstuvwxyz3456abcdefghijklmNOPQRSTUVWXYZ789';

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
type CredentialStatusInfo =
  Record<StatusPurpose, {
    statusCredentialId: string;
    statusListIndex: number;
    valid: boolean;
  }>;

// Type definition for status credential info
type StatusCredentialInfo =
  Record<StatusPurpose, {
    latestId: string;
    latestOrder: number;
  }>;

// Type definition for status credential record
export interface StatusCredentialRecord {
  id: string;
  order: number;
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

// Type definition for credential status config record
export interface ConfigRecord {
  id: string;
  statusCredentialSiteOrigin: string;
  statusCredentialInfo: StatusCredentialInfo;
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
  indexAllocators: Record<string, IndexAllocator>;
  statusCredentialRecordsByPurpose: Record<StatusPurpose, StatusCredentialRecord>;
}

// Type definition for attachCredentialStatus method output
interface AttachCredentialStatusResult {
  credential: any;
  credentialStatusInfo: CredentialStatusInfo;
  newUserCredential: boolean;
}

// Type definition for input and output of
// initializeTransactionData and refreshTransactionData methods
interface TransactionData {
  config: ConfigRecord;
  statusPurposes: StatusPurpose[];
  indexAllocators: Record<string, IndexAllocator>;
  statusCredentialRecordsByPurpose: Record<StatusPurpose, StatusCredentialRecord>;
  newStatusCredentialByPurpose: Record<StatusPurpose, boolean>;
}

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
   * @param {AttachCredentialStatusOptions} [attachCredentialStatusOptions] - Credential status attachment options.
   *
   * @param {ConfigRecord} [attachCredentialStatusOptions.credential] - The credential to attach status to.
   * @param {StatusPurpose[]} [attachCredentialStatusOptions.statusPurposes] - The statuses of interest.
   * @param {Record<string, IndexAllocator>} [attachCredentialStatusOptions.indexAllocators] - The index allocators for a status credential.
   * @param {Record<StatusPurpose, StatusCredentialRecord>} [attachCredentialStatusOptions.statusCredentialRecordsByPurpose] - The status credential records by purpose.
   *
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<AttachCredentialStatusResult>} Resolves to metadata associated with attached credential status.
   */
  async attachCredentialStatus(
    attachCredentialStatusOptions: AttachCredentialStatusOptions,
    options?: DatabaseConnectionOptions
  ): Promise<AttachCredentialStatusResult> {
    // destructure method input
    const {
      credential,
      statusPurposes,
      indexAllocators,
      statusCredentialRecordsByPurpose
    } = attachCredentialStatusOptions;

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

    // only search for credential if it was passed with an ID
    if (credentialContainsId) {
      // retrieve record for credential with given ID
      // (don't fail if credential is not found, as this is common)
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

        return {
          credential: {
            ...credentialCopy,
            credentialStatus
          },
          newUserCredential: false,
          credentialStatusInfo: statusInfo
        };
      }
    }

    // compose credentialStatus field of credential
    const statusInfo = {} as CredentialStatusInfo;
    for (const statusPurpose of statusPurposes) {
      const statusCredentialRecord = statusCredentialRecordsByPurpose[statusPurpose];
      const statusCredentialId = statusCredentialRecord.id;

      // update credential status info
      statusInfo[statusPurpose] = {
        statusCredentialId,
        statusListIndex: indexAllocators[statusCredentialId].getAvailableIndex(),
        valid: true
      };
    }
    const credentialStatus = this.composeCredentialStatus(statusInfo);

    return {
      credential: {
        ...credentialCopy,
        credentialStatus
      },
      newUserCredential: true,
      credentialStatusInfo: statusInfo
    };
  }

  /**
   * Initializes transaction data
   *
   * @param {TransactionData} [initializeTransactionDataOptions] - Transaction data initialization options.
   *
   * @param {StatusPurpose[]} [initializeTransactionDataOptions.statusPurposes] - The statuses of interest.
   *
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<TransactionData>} Resolves to transaction data.
   */
  async initializeTransactionData({ statusPurposes }: { statusPurposes: StatusPurpose[] }, options?: DatabaseConnectionOptions): Promise<TransactionData> {
    // retrieve signing material and other useful metadata
    const {
      didMethod,
      didSeed,
      didWebUrl,
      signStatusCredential,
      statusCredentialSiteOrigin
    } = this;
    const { issuerDid } = await getSigningMaterial({
      didMethod,
      didSeed,
      didWebUrl
    });
    const config = await this.getConfigRecord(options);
    const indexAllocators = {} as Record<string, IndexAllocator>;
    const statusCredentialRecordsByPurpose = {} as Record<StatusPurpose, StatusCredentialRecord>;
    const newStatusCredentialByPurpose = {} as Record<StatusPurpose, boolean>;
    for (const purpose of statusPurposes) {
      let statusCredentialId = config.statusCredentialInfo[purpose].latestId;
      const allocatedIndices = await this.getAllocatedIndicesByStatusCredentialId(statusCredentialId, purpose, options);
      if (allocatedIndices.length === SAFE_CREDENTIAL_STATUS_LIST_SIZE) {
        // create new status credential if latest one has reached its max capacity
        statusCredentialId = this.generateStatusCredentialId();
        const statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
        let statusCredential = await composeStatusCredential({
          issuerDid,
          credentialId: statusCredentialUrl,
          statusPurpose: purpose
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
        indexAllocators[statusCredentialId] = new IndexAllocator(
          [],
          MAX_CREDENTIAL_STATUS_LIST_SIZE,
          CREDENTIAL_STATUS_LIST_SIZE_BUFFER
        );
        newStatusCredentialByPurpose[purpose] = true;
        config.statusCredentialInfo[purpose].latestId = statusCredentialId;
        statusCredentialRecordsByPurpose[purpose] = {
          id: statusCredentialId,
          order: config.statusCredentialInfo[purpose].latestOrder + 1,
          purpose,
          credential: statusCredential
        };
      } else {
        // utilize latest status credential if it has not reached its max capacity
        indexAllocators[statusCredentialId] = new IndexAllocator(
          allocatedIndices,
          MAX_CREDENTIAL_STATUS_LIST_SIZE,
          CREDENTIAL_STATUS_LIST_SIZE_BUFFER
        );
        newStatusCredentialByPurpose[purpose] = false;
        statusCredentialRecordsByPurpose[purpose] = await this.getStatusCredentialRecordById(statusCredentialId, options);
      }
    }
    return {
      config,
      statusPurposes,
      indexAllocators,
      statusCredentialRecordsByPurpose,
      newStatusCredentialByPurpose
    };
  }

  /**
   * Refreshes transaction data
   *
   * @param {TransactionData} [transactionData] - Transaction data.
   *
   * @param {ConfigRecord} [transactionData.config] - The config record.
   * @param {StatusPurpose[]} [transactionData.statusPurposes] - The statuses of interest.
   * @param {Record<string, IndexAllocator>} [transactionData.indexAllocators] - The index allocators for a status credential.
   * @param {Record<StatusPurpose, StatusCredentialRecord>} [transactionData.statusCredentialRecordsByPurpose] - The status credential records by purpose.
   * @param {Record<StatusPurpose, boolean>} [transactionData.newStatusCredentialByPurpose] - Whether a new status credential record should be created for each purpose.
   *
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<TransactionData>} Resolves to transaction data.
   */
  async refreshTransactionData(transactionData: TransactionData, options?: DatabaseConnectionOptions): Promise<TransactionData> {
    // retrieve old transaction data
    const {
      config: oldConfig,
      statusPurposes,
      indexAllocators: oldIndexAllocators,
      statusCredentialRecordsByPurpose: oldStatusCredentialRecordsByPurpose,
      newStatusCredentialByPurpose: oldNewStatusCredentialByPurpose
    } = transactionData;

    // retrieve signing material and other useful metadata
    const {
      didMethod,
      didSeed,
      didWebUrl,
      signStatusCredential,
      statusCredentialSiteOrigin
    } = this;
    const { issuerDid } = await getSigningMaterial({
      didMethod,
      didSeed,
      didWebUrl
    });
    const config = await this.getConfigRecord(options);
    const indexAllocators = {} as Record<string, IndexAllocator>;
    const statusCredentialRecordsByPurpose = {} as Record<StatusPurpose, StatusCredentialRecord>;
    const newStatusCredentialByPurpose = {} as Record<StatusPurpose, boolean>;
    for (const purpose of statusPurposes) {
      let statusCredentialId = config.statusCredentialInfo[purpose].latestId;
      let statusCredentialOrder = config.statusCredentialInfo[purpose].latestOrder;
      // NOTE: one of the two operands of this condition should suffice
      if (
        oldConfig.statusCredentialInfo[purpose].latestId !== statusCredentialId ||
        oldConfig.statusCredentialInfo[purpose].latestOrder !== statusCredentialOrder
      ) {
        // retrieve data associated with latest status credential
        const allocatedIndices = await this.getAllocatedIndicesByStatusCredentialId(statusCredentialId, purpose, options);
        indexAllocators[statusCredentialId] = new IndexAllocator(
          allocatedIndices,
          MAX_CREDENTIAL_STATUS_LIST_SIZE,
          CREDENTIAL_STATUS_LIST_SIZE_BUFFER
        );
        newStatusCredentialByPurpose[purpose] = false;
        statusCredentialRecordsByPurpose[purpose] = await this.getStatusCredentialRecordById(statusCredentialId, options);
      } else if (oldIndexAllocators[statusCredentialId].getAvailableIndexCounter() <= CREDENTIAL_STATUS_LIST_SIZE_BUFFER) {
        // create new status credential if latest one has reached its max capacity
        statusCredentialId = this.generateStatusCredentialId();
        const statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
        let statusCredential = await composeStatusCredential({
          issuerDid,
          credentialId: statusCredentialUrl,
          statusPurpose: purpose
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
        indexAllocators[statusCredentialId] = new IndexAllocator(
          [],
          MAX_CREDENTIAL_STATUS_LIST_SIZE,
          CREDENTIAL_STATUS_LIST_SIZE_BUFFER
        );
        newStatusCredentialByPurpose[purpose] = true;
        config.statusCredentialInfo[purpose].latestId = statusCredentialId;
        statusCredentialOrder += 1;
        config.statusCredentialInfo[purpose].latestOrder = statusCredentialOrder;
        statusCredentialRecordsByPurpose[purpose] = {
          id: statusCredentialId,
          order: statusCredentialOrder,
          purpose,
          credential: statusCredential
        };
      } else {
        // utilize the same data, since status credential has not changed
        indexAllocators[statusCredentialId] = oldIndexAllocators[statusCredentialId];
        newStatusCredentialByPurpose[purpose] = oldNewStatusCredentialByPurpose[purpose];
        statusCredentialRecordsByPurpose[purpose] = oldStatusCredentialRecordsByPurpose[purpose];
      }
    }
    return {
      config,
      statusPurposes,
      indexAllocators,
      statusCredentialRecordsByPurpose,
      newStatusCredentialByPurpose
    };
  }

  /**
   * Allocates status for credential
   *
   * @param {AllocateStatusOptions} [allocateStatusOptions] - Credential status allocation options.
   * 
   * @param {VerifiableCredential} [allocateStatusOptions.credential] - The credential for which to allocate status.
   * @param {StatusPurpose[]} [allocateStatusOptions.statusPurposes] - The statuses to allocate for the credential.
   *
   * @throws {BadRequestError} If credential is in JWT format.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to new credential with status.
   */
  async allocateStatus(allocateStatusOptions: AllocateStatusOptions): Promise<VerifiableCredential> {
    // destructure method input
    const {
      credential,
      statusPurposes
    } = allocateStatusOptions;

    // track whether transaction data has been initialized
    let transactionDataInitialized = false;

    // declare transaction data
    let config: ConfigRecord;
    let indexAllocators: Record<string, IndexAllocator>;
    let statusCredentialRecordsByPurpose: Record<StatusPurpose, StatusCredentialRecord>;
    let newStatusCredentialByPurpose: Record<StatusPurpose, boolean>;

    return this.executeTransaction(async (options?: DatabaseConnectionOptions) => {
      // report error for compact JWT credentials
      if (typeof credential === 'string') {
        throw new BadRequestError({
          message: 'This library does not support compact JWT credentials.'
        });
      }

      // initialize transaction data if necessary
      if (!transactionDataInitialized) {
        // retrieve all allocated indices for latest status credential to guide random index guessing
        ({
          config,
          indexAllocators,
          statusCredentialRecordsByPurpose,
          newStatusCredentialByPurpose
        } = await this.initializeTransactionData({ statusPurposes }, options));
        transactionDataInitialized = true;
      }

      // attach status to credential
      let credentialWithStatus;
      let newUserCredential;
      let credentialStatusInfo;
      try {
        ({
          credential: credentialWithStatus,
          newUserCredential,
          credentialStatusInfo
        } = await this.attachCredentialStatus({ credential, statusPurposes, indexAllocators, statusCredentialRecordsByPurpose }, options));
      } catch (error) {
        // refresh transaction data if the status list
        // reaches its maximum safe capacity
        ({
          config,
          indexAllocators,
          statusCredentialRecordsByPurpose,
          newStatusCredentialByPurpose
        } = await this.refreshTransactionData({
          config,
          statusPurposes,
          indexAllocators,
          statusCredentialRecordsByPurpose,
          newStatusCredentialByPurpose
        }, options));
        // this triggers a retry of the transaction
        throw error;
      }

      // retrieve signing material and other useful metadata
      const {
        didMethod,
        didSeed,
        didWebUrl,
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
      for (const [statusPurpose, newStatusCred] of Object.entries(newStatusCredentialByPurpose)) {
        if (newStatusCred) {
          const statusCredentialRecord = statusCredentialRecordsByPurpose[statusPurpose as StatusPurpose];
          try {
            // create status credential record
            await this.createStatusCredentialRecord(statusCredentialRecord, options);
          } catch (error) {
            // refresh transaction data if there is a write conflict
            // while saving the status credential record
            ({
              config,
              indexAllocators,
              statusCredentialRecordsByPurpose,
              newStatusCredentialByPurpose
            } = await this.refreshTransactionData({
              config,
              statusPurposes,
              indexAllocators,
              statusCredentialRecordsByPurpose,
              newStatusCredentialByPurpose
            }, options));
            // this triggers a retry of the transaction
            throw error;
          }
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
      try {
        // create user credential record
        await this.createUserCredentialRecord(credentialRecord, options);
      } catch (error) {
        // refresh transaction data if there is a write conflict
        // while saving the user credential record
        ({
          config,
          indexAllocators,
          statusCredentialRecordsByPurpose,
          newStatusCredentialByPurpose
        } = await this.refreshTransactionData({
          config,
          statusPurposes,
          indexAllocators,
          statusCredentialRecordsByPurpose,
          newStatusCredentialByPurpose
        }, options));
        // this triggers a retry of the transaction
        throw error;
      }

      // create a new event and credential event record for each purpose
      for (const statusPurpose of statusPurposes) {
        // create new event record
        const event: EventRecord = {
          id: uuid(),
          timestamp: getDateString(),
          credentialId,
          statusPurpose,
          valid: true
        };
        await this.createEventRecord(event, options);
      }

      // Only update config record when a new status credential is created
      if (Object.values(newStatusCredentialByPurpose).some(n => n)) {
        await this.updateConfigRecord(config);
      }

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
   * @param {UpdateStatusOptions} [updateStatusOptions] - Credential status update options.
   * 
   * @param {string} [updateStatusOptions.credentialId] - The ID of the credential for which to update status.
   * @param {StatusPurpose} [updateStatusOptions.statusPurpose] - The status to update for the credential.
   * @param {boolean} [updateStatusOptions.invalidate] - Whether to invalidate the status of the credential for the given purpose.
   *
   * @throws {BadRequestError} If the credential is not being tracked for the given purpose
   *   or if the status credential is in JWT format.
   *
   * @returns {Promise<VerifiableCredential>} Resolves to updated status credential.
   */
  async updateStatus(updateStatusOptions: UpdateStatusOptions): Promise<VerifiableCredential> {
    // destructure method input
    const {
      credentialId,
      statusPurpose,
      invalidate
    } = updateStatusOptions;
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
      const statusCredentialRecord = await this.getStatusCredentialRecordById(statusCredentialId, options);
      const statusCredentialBefore = statusCredentialRecord.credential;

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
        signStatusCredential,
        statusCredentialSiteOrigin
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
      const statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
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
        order: statusCredentialRecord.order,
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
      const newEventRecord: EventRecord = {
        id: uuid(),
        timestamp: getDateString(),
        credentialId,
        statusPurpose,
        valid: !invalidate
      };
      await this.createEventRecord(newEventRecord, options);

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
   * Creates database table
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
    // create index for UserCredential to prevent
    // parallel transactions from using the same
    // combination of statusListCredential and statusListIndex
    try {
      for (const statusPurpose of SUPPORTED_STATUS_PURPOSES) {
        await this.createUniqueDatabaseTableIndex(
          this.userCredentialTableName, [
            `statusInfo.${statusPurpose}.statusCredentialId`,
            `statusInfo.${statusPurpose}.statusListIndex`
          ],
          options
        );
      }
      await this.createUniqueDatabaseTableIndex(
        this.statusCredentialTableName,
        ['order', 'purpose'],
        options
      );
    } catch (error: any) {
      throw new InternalServerError({
        message: 'Unable to create unique database table index for ' +
          `"${this.userCredentialTableName}": ${error.message}`
      });
    }
  }

  /**
   * Creates unique database table index
   * 
   * @param {string} [tableName] - Name of database table.
   * @param {string} [fields] - Array of field names to index.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<void>}
   */
  abstract createUniqueDatabaseTableIndex(tableName: string, fields: string[], options?: DatabaseConnectionOptions): Promise<void>;

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
      didWebUrl,
      statusCredentialSiteOrigin
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
        latestId: statusCredentialId,
        latestOrder: 1
      };

      // compose status credential
      const statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
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
        order: 1,
        purpose: statusPurpose,
        credential: statusCredential
      }, options);
    }

    // create status config record
    const configRecord: ConfigRecord = {
      id: uuid(),
      statusCredentialSiteOrigin,
      statusCredentialInfo
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
    const anyCredentialIssued = await this.checkAnyCredentialsIssued(options);
    for (const tableName of tableNames) {
      // these tables are only required after credentials have been issued
      if (
        tableName === this.userCredentialTableName ||
        tableName === this.eventTableName
      ) {
        if (!anyCredentialIssued) {
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
    const anyCredentialIssued = await this.checkAnyCredentialsIssued(options);
    for (const tableName of tableNames) {
      // these tables are only required after credentials have been issued
      if (
        tableName === this.userCredentialTableName ||
        tableName === this.eventTableName
      ) {
        if (!anyCredentialIssued) {
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
        statusCredentialInfo
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
      for (const statusPurpose of statusPurposes) {
        // retrieve info for latest status credential
        const { latestId } = statusCredentialInfo[statusPurpose];
        const statusCredentialUrl = `${this.statusCredentialSiteOrigin}/${latestId}`;

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
          hasLatestStatusCredentialId = hasLatestStatusCredentialId || (statusCredential.id?.endsWith(latestId) ?? false);
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
                `("${latestId}") is not being tracked in the config.`
            })
          };
        }
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
      if (error instanceof WriteConflictError) {
        throw error;
      }
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
      if (error instanceof WriteConflictError) {
        throw error;
      }
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
   * Checks whether any credentials have been issued
   * 
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<boolean>} Resolves to whether any credential has been issued.
   */
  async checkAnyCredentialsIssued(options?: DatabaseConnectionOptions): Promise<boolean> {
    let record;
    try {
      record = await this.getAnyRecord(this.userCredentialTableName, options);
      return !!record;
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get credential record: ${error.message}`
      });
    }
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
   * Retrieves allocated indices for a status credential
   * 
   * @param {string} [statusCredentialId] - ID of status credential record.
   * @param {string} [statusPurpose] - Status purpose.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<number[]>} Resolves to allocated indices for status credential.
   */
  async getAllUserCredentialIndicesByStatusCredentialId(statusCredentialId: string, statusPurpose: string, options?: DatabaseConnectionOptions): Promise<number[]> {
    return this.getAllRecordsByField(this.userCredentialTableName, `statusInfo.${statusPurpose}.statusCredentialId`, statusCredentialId, options);
  }

  /**
   * Alias for getAllUserCredentialIndicesByStatusCredentialId
   * 
   * @param {string} [statusCredentialId] - ID of status credential record.
   * @param {string} [statusPurpose] - Status purpose.
   * @param {DatabaseConnectionOptions} [options={}] - Database connection options.
   *
   * @returns {Promise<number[]>} Resolves to allocated indices for status credential.
   */
  async getAllocatedIndicesByStatusCredentialId(statusCredentialId: string, statusPurpose: string, options?: DatabaseConnectionOptions): Promise<number[]> {
    return this.getAllUserCredentialIndicesByStatusCredentialId(statusCredentialId, statusPurpose, options);
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
    statusList = await createList({ length: MAX_CREDENTIAL_STATUS_LIST_SIZE });
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
