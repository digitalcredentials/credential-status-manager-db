/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import { CONTEXT_URL_V1 } from '@digitalbazaar/vc-status-list-context';
import { VerifiableCredential } from '@digitalcredentials/vc-data-model';
import { createCredential, createList, decodeList } from '@digitalcredentials/vc-status-list';
import { v4 as uuid } from 'uuid';
import { BadRequestError, NotFoundError } from './errors.js';
import {
  DidMethod,
  deriveStatusCredentialId,
  getDateString,
  getSigningMaterial,
  signCredential
} from './helpers.js';

// Number of credentials tracked in a list
const CREDENTIAL_STATUS_LIST_SIZE = 100000;

// Credential status type
const CREDENTIAL_STATUS_TYPE = 'StatusList2021Entry';

// Credential status manager database service
export enum CredentialStatusManagerService {
  MongoDb = 'mongodb'
}

// States of credential resulting from caller actions and tracked in the event log
export enum CredentialState {
  Active = 'active',
  Revoked = 'revoked'
}

// Type definition for event
interface Event {
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
export interface Config {
  id: string;
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
export interface CredentialEvent {
  credentialId: string;
  eventId: string;
}

// Type definition for composeStatusCredential function input
interface ComposeStatusCredentialOptions {
  issuerDid: string;
  credentialId: string;
  statusList?: any;
  statusPurpose?: string;
}

// Type definition for embedCredentialStatus method input
interface EmbedCredentialStatusOptions {
  credential: any;
  statusPurpose?: string;
}

// Type definition for embedCredentialStatus method output
type EmbedCredentialStatusResult = Config & {
  credential: any;
  newStatusCredential: boolean;
};

// Type definition for updateStatus method input
interface UpdateStatusOptions {
  credentialId: string;
  credentialStatus: CredentialState;
}

// Type definition for BaseCredentialStatusManager constructor method input
export interface BaseCredentialStatusManagerOptions {
  statusCredentialTableName: string;
  configTableName: string;
  eventTableName: string;
  credentialEventTableName: string;
  databaseName: string;
  databaseUrl?: string;
  databaseUsername: string;
  databasePassword: string;
  databaseHost?: string;
  databasePort?: string;
  didMethod: DidMethod;
  didSeed: string;
  didWebUrl?: string;
  signUserCredential?: boolean;
  signStatusCredential?: boolean;
}

// Minimal set of options required for configuring BaseCredentialStatusManager
export const BASE_MANAGER_REQUIRED_OPTIONS: Array<keyof BaseCredentialStatusManagerOptions> = [
  'statusCredentialTableName',
  'configTableName',
  'eventTableName',
  'credentialEventTableName',
  'databaseName',
  'databaseUsername',
  'databasePassword',
  'didMethod',
  'didSeed'
];

// Base class for database clients
export abstract class BaseCredentialStatusManager {
  protected readonly statusCredentialTableName: string;
  protected readonly configTableName: string;
  protected readonly eventTableName: string;
  protected readonly credentialEventTableName: string;
  protected readonly databaseName: string;
  protected readonly databaseUrl?: string;
  protected databaseUsername: string;
  protected databasePassword: string;
  protected readonly databaseHost?: string;
  protected readonly databasePort?: string;
  protected readonly didMethod: DidMethod;
  protected readonly didSeed: string;
  protected readonly didWebUrl?: string;
  protected readonly signUserCredential: boolean;
  protected readonly signStatusCredential: boolean;

  constructor(options: BaseCredentialStatusManagerOptions) {
    const {
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
    } = options;
    this.statusCredentialTableName = statusCredentialTableName;
    this.configTableName = configTableName;
    this.eventTableName = eventTableName;
    this.credentialEventTableName = credentialEventTableName;
    this.databaseName = databaseName;
    this.databaseUrl = databaseUrl;
    this.databaseUsername = databaseUsername;
    this.databasePassword = databasePassword;
    this.databaseHost = databaseHost;
    this.databasePort = databasePort;
    this.didMethod = didMethod;
    this.didSeed = didSeed;
    this.didWebUrl = didWebUrl;
    this.signUserCredential = signUserCredential ?? false;
    this.signStatusCredential = signStatusCredential ?? false;
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
  generateStatusCredentialId(): string {
    return Math.random().toString(36).substring(2, 12).toUpperCase();
  }

  // embeds status into credential
  async embedCredentialStatus({ credential, statusPurpose = 'revocation' }: EmbedCredentialStatusOptions): Promise<EmbedCredentialStatusResult> {
    // ensure that credential has ID
    if (!credential.id) {
      // Note: This assumes that uuid will never generate an ID that
      // conflicts with an ID that has already been tracked in the event log
      credential.id = uuid();
    }

    // ensure that credential contains the proper status credential context
    if (!credential['@context'].includes(CONTEXT_URL_V1)) {
      credential['@context'].push(CONTEXT_URL_V1);
    }

    // retrieve config data
    const configId = await this.getConfigId();
    let {
      latestStatusCredentialId,
      latestCredentialsIssuedCounter,
      allCredentialsIssuedCounter
    } = await this.getConfig(configId);

    // retrieve latest relevant event for credential with given ID
    const event = await this.getLatestEventForCredential(credential.id);

    // do not allocate new entry if ID is already being tracked
    if (event) {
      // retrieve relevant event data
      const { statusCredentialId, credentialStatusIndex } = event;

      // attach credential status
      const statusCredentialUrlBase = this.getStatusCredentialUrlBase();
      const statusCredentialUrl = `${statusCredentialUrlBase}/${statusCredentialId}`;
      const credentialStatusId = `${statusCredentialUrl}#${credentialStatusIndex}`;
      const credentialStatus = {
        id: credentialStatusId,
        type: CREDENTIAL_STATUS_TYPE,
        statusPurpose,
        statusListIndex: credentialStatusIndex.toString(),
        statusListCredential: statusCredentialUrl
      };

      return {
        id: configId,
        credential: {
          ...credential,
          credentialStatus
        },
        newStatusCredential: false,
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
      allCredentialsIssuedCounter++;
    }
    latestCredentialsIssuedCounter++;

    // attach credential status
    const statusCredentialUrlBase = this.getStatusCredentialUrlBase();
    const statusCredentialUrl = `${statusCredentialUrlBase}/${latestStatusCredentialId}`;
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
      id: configId,
      credential: {
        ...credential,
        credentialStatus
      },
      newStatusCredential,
      latestStatusCredentialId,
      latestCredentialsIssuedCounter,
      allCredentialsIssuedCounter
    };
  }

  // allocates status for credential in race-prone manner
  async allocateStatus(credential: VerifiableCredential): Promise<VerifiableCredential | void> {
    return this.executeAsTransaction(async (options?: any) => {
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
        latestStatusCredentialId,
        ...embedCredentialStatusResultRest
      } = await this.embedCredentialStatus({ credential });

      // retrieve signing material
      const {
        didMethod,
        didSeed,
        didWebUrl,
        signUserCredential,
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

      // create new status credential only if the last one has reached capacity
      if (newStatusCredential) {
        // create status credential
        const statusCredentialUrlBase = this.getStatusCredentialUrlBase();
        const statusCredentialUrl = `${statusCredentialUrlBase}/${latestStatusCredentialId}`;
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
        await this.createStatusCredential({
          id: latestStatusCredentialId,
          credential: statusCredential
        }, options);
      }

      // sign credential if necessary
      if (signUserCredential) {
        credentialWithStatus = await signCredential({
          credential: credentialWithStatus,
          didMethod,
          didSeed,
          didWebUrl
        });
      }

      // extract relevant data from credential status
      const {
        statusListCredential: statusCredentialUrl,
        statusListIndex
      } = credentialWithStatus.credentialStatus;

      // retrieve status credential ID from status credential URL
      const statusCredentialId = deriveStatusCredentialId(statusCredentialUrl);

      // create new event
      const eventId = uuid();
      const event: Event = {
        id: eventId,
        timestamp: getDateString(),
        credentialId: credential.id as string,
        credentialIssuer: issuerDid,
        credentialSubject: credential.credentialSubject?.id,
        credentialState: CredentialState.Active,
        verificationMethod,
        statusCredentialId,
        credentialStatusIndex: parseInt(statusListIndex)
      };
      await this.createEvent(event, options);
      await this.createCredentialEvent({
        credentialId: credential.id as string,
        eventId
      }, options);

      // persist updates to config data
      await this.updateConfig({
        latestStatusCredentialId,
        ...embedCredentialStatusResultRest
      }, options);

      return credentialWithStatus;
    });
  }

  // updates status of credential in race-prone manner
  async updateStatus({
    credentialId,
    credentialStatus
  }: UpdateStatusOptions): Promise<VerifiableCredential | void> {
    return this.executeAsTransaction(async (options?: any) => {
      // retrieve latest relevant event for credential with given ID
      const oldEvent = await this.getLatestEventForCredential(credentialId);

      // unable to find credential with given ID
      if (!oldEvent) {
        throw new NotFoundError({
          message: `Unable to find credential with ID "${credentialId}".`
        });
      }

      // retrieve relevant event data
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
      const statusCredentialBefore = await this.getStatusCredential(statusCredentialId);

      // report error for compact JWT credentials
      if (typeof statusCredentialBefore === 'string') {
        throw new BadRequestError({
          message: 'This library does not support compact JWT credentials.'
        });
      }

      // update status credential
      const statusCredentialListEncodedBefore = statusCredentialBefore.credentialSubject.encodedList;
      const statusCredentialListDecoded = await decodeList({
        encodedList: statusCredentialListEncodedBefore
      });
      switch (credentialStatus) {
        case CredentialState.Active:
          statusCredentialListDecoded.setStatus(credentialStatusIndex, false); // active credential is represented as 0 bit
          break;
        case CredentialState.Revoked:
          statusCredentialListDecoded.setStatus(credentialStatusIndex, true); // revoked credential is represented as 1 bit
          break;
        default:
          throw new BadRequestError({
            message:
              '"credentialStatus" must be one of the following values: ' +
              `${Object.values(CredentialState).map(s => `"${s}"`).join(', ')}.`
          });
      }
      const statusCredentialUrlBase = this.getStatusCredentialUrlBase();
      const statusCredentialUrl = `${statusCredentialUrlBase}/${statusCredentialId}`;
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

      // persist status credential
      await this.updateStatusCredential({
        id: statusCredentialId,
        credential: statusCredential
      }, options);

      // create new event
      const eventId = uuid();
      const newEvent: Event = {
        id: eventId,
        timestamp: getDateString(),
        credentialId,
        credentialIssuer: issuerDid,
        credentialSubject,
        credentialState: credentialStatus,
        verificationMethod,
        statusCredentialId,
        credentialStatusIndex
      };
      await this.createEvent(newEvent, options);
      await this.updateCredentialEvent({
        credentialId,
        eventId
      }, options);

      return statusCredential;
    });
  }

  // checks status of credential with given ID
  async checkStatus(credentialId: string): Promise<Event> {
    // retrieve latest relevant event for credential with given ID
    const event = await this.getLatestEventForCredential(credentialId);

    // unable to find credential with given ID
    if (!event) {
      throw new NotFoundError({
        message: `Unable to find credential with ID "${credentialId}".`
      });
    }

    return event;
  }

  // retrieves credential status URL
  abstract getStatusCredentialUrlBase(): string;

  // deploys website to host credential status management resources
  async deployCredentialStatusWebsite(): Promise<void> {};

  // checks if caller has authority to manage status based on authorization credentials
  abstract hasAuthority(databaseUsername: string, databasePassword: string): Promise<boolean>;

  // checks if database exists
  abstract databaseExists(): Promise<boolean>;

  // checks if database table exists
  abstract databaseTableExists(tableName: string): Promise<boolean>;

  // checks if database tables exist
  async databaseTablesExist(): Promise<boolean> {
    const databaseTableNames = this.getDatabaseTableNames();
    return databaseTableNames.every(async (tableName) => {
      return this.databaseTableExists(tableName);
    });
  }

  // checks if database table is empty
  abstract databaseTableEmpty(tableName: string): Promise<boolean>;

  // checks if database tables are empty
  async databaseTablesEmpty(): Promise<boolean> {
    const databaseTableNames = this.getDatabaseTableNames();
    return databaseTableNames.every(async (tableName) => {
      return this.databaseTableEmpty(tableName);
    });
  }

  // checks if database tables are properly configured
  async databaseTablesProperlyConfigured(): Promise<boolean> {
    try {
      // retrieve config data
      const configId = await this.getConfigId();
      const {
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        allCredentialsIssuedCounter
      } = await this.getConfig(configId);
      const statusCredentialUrlBase = this.getStatusCredentialUrlBase();
      const statusCredentialUrl = `${statusCredentialUrlBase}/${latestStatusCredentialId}`;
      const statusCredentials = await this.getAllStatusCredentials();

      // ensure status data is consistent
      let hasLatestStatusCredentialId = false;
      for (const statusData of statusCredentials) {
        // report error for compact JWT credentials
        if (typeof statusData === 'string') {
          return false;
        }

        // retrieve credential from status credential record
        const { credential } = statusData;

        // ensure status credential is well formed
        hasLatestStatusCredentialId = hasLatestStatusCredentialId || (credential.id?.endsWith(latestStatusCredentialId) ?? false);
        const hasProperStatusCredentialType = credential.type.includes('StatusList2021Credential');
        const hasProperStatusCredentialSubId = credential.credentialSubject.id?.startsWith(statusCredentialUrl) ?? false;
        const hasProperStatusCredentialSubType = credential.credentialSubject.type === 'StatusList2021';
        const hasProperStatusCredentialSubStatusPurpose = credential.credentialSubject.statusPurpose === 'revocation';
        const hasProperStatusFormat = hasProperStatusCredentialType &&
                                      hasProperStatusCredentialSubId &&
                                      hasProperStatusCredentialSubType &&
                                      hasProperStatusCredentialSubStatusPurpose;
        if (!hasProperStatusFormat) {
          return false;
        }
      }
      // ensure that latest status credential is being tracked in the config
      if (!hasLatestStatusCredentialId) {
        return false;
      }

      // ensure that all status credentials are being tracked in the config
      if (statusCredentials.length !== allCredentialsIssuedCounter) {
        return false;
      }

      // retrieve credential IDs from event log
      const credentialIds = await this.getAllCredentialIds();
      const hasProperEvents = credentialIds.length ===
                              (statusCredentials.length - 1) *
                              CREDENTIAL_STATUS_LIST_SIZE +
                              latestCredentialsIssuedCounter;

      // ensure that all checks pass
      return hasProperEvents;
    } catch (error) {
      return false;
    }
  }

  // executes function as transaction
  abstract executeAsTransaction<T>(func: <T>(options?: any) => Promise<T | void>): Promise<T | void>;

  // creates single database record
  abstract createRecord<T>(tableName: string, record: T, options?: any): Promise<void>;

  // creates status credential
  async createStatusCredential(statusCredentialRecord: StatusCredentialRecord, options?: any): Promise<void> {
    return this.createRecord(this.statusCredentialTableName, statusCredentialRecord, options);
  }

  // creates config
  async createConfig(config: Config, options?: any): Promise<void> {
    return this.createRecord(this.configTableName, config, options);
  }

  // creates event
  async createEvent(event: Event, options?: any): Promise<void> {
    return this.createRecord(this.eventTableName, event, options);
  }

  // creates credential event
  async createCredentialEvent(credentialEvent: CredentialEvent, options?: any): Promise<void> {
    return this.createRecord(this.credentialEventTableName, credentialEvent, options);
  }

  // updates single database record
  abstract updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: any): Promise<void>;

  // updates status credential
  async updateStatusCredential(statusCredentialRecord: StatusCredentialRecord, options?: any): Promise<void> {
    const { id } = statusCredentialRecord;
    return this.updateRecord(this.statusCredentialTableName, 'id', id, statusCredentialRecord, options);
  }

  // updates config
  async updateConfig(config: Config, options?: any): Promise<void> {
    const { id } = config;
    return this.updateRecord(this.configTableName, 'id', id, config, options);
  }

  // updates credential event
  async updateCredentialEvent(credentialEvent: CredentialEvent, options?: any): Promise<void> {
    const { credentialId } = credentialEvent;
    return this.updateRecord(this.credentialEventTableName, 'credentialId', credentialId, credentialEvent, options);
  }

  // retrieves any database record
  abstract getAnyRecord<T>(tableName: string): Promise<T | null>;

  // retrieves config ID
  async getConfigId(): Promise<string> {
    const record = await this.getAnyRecord(this.configTableName);
    if (!record) {
      throw new NotFoundError({
        message: 'Unable to find config.'
      });
    }
    return (record as Config).id;
  }

  // retrieves single database record by field
  abstract getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T | null>;

  // retrieves multiple database records by field
  abstract getRecordsByField<T>(tableName: string, fieldKey: string, fieldValue: string): Promise<T[]>;

  // retrieves single database record by id
  async getRecordById<T>(tableName: string, id: string): Promise<T | null> {
    return this.getRecordByField(tableName, 'id', id);
  }

  // retrieves status credential record by ID
  async getStatusCredentialRecordById(statusCredentialId: string): Promise<StatusCredentialRecord> {
    const record = await this.getRecordById(this.statusCredentialTableName, statusCredentialId);
    if (!record) {
      throw new NotFoundError({
        message: `Unable to find status credential with ID "${statusCredentialId}".`
      });
    }
    return record as StatusCredentialRecord;
  }

  // retrieves status credential by ID
  async getStatusCredential(statusCredentialId: string): Promise<VerifiableCredential> {
    const { credential } = await this.getStatusCredentialRecordById(statusCredentialId);
    return credential as VerifiableCredential;
  }

  // retrieves config by ID
  async getConfig(configId: string): Promise<Config> {
    const record = await this.getRecordById(this.configTableName, configId);
    if (!record) {
      throw new NotFoundError({
        message: `Unable to find config with ID "${configId}".`
      });
    }
    return record as Config;
  }

  // retrieves latest event featuring credential with given ID
  async getLatestEventForCredential(credentialId: string): Promise<Event> {
    const credentialEventRecord = await this.getRecordByField<CredentialEvent>(this.credentialEventTableName, 'credentialId', credentialId);
    if (!credentialEventRecord) {
      throw new NotFoundError({
        message: `Unable to find event for credential with ID "${credentialId}".`
      });
    }
    const { eventId } = credentialEventRecord;
    const eventRecord = await this.getRecordById(this.eventTableName, eventId);
    if (!eventRecord) {
      throw new NotFoundError({
        message: `Unable to find event with ID "${eventId}".`
      });
    }
    return eventRecord as Event;
  }

  // retrieves all records in table
  abstract getAllRecords<T>(tableName: string): Promise<T[]>;

  // retrieves all status credential records
  async getAllStatusCredentialRecords(): Promise<StatusCredentialRecord[]> {
    return this.getAllRecords(this.statusCredentialTableName);
  }

  // retrieves all credential event records
  async getAllCredentialEventRecords(): Promise<Event[]> {
    return this.getAllRecords(this.credentialEventTableName);
  }

  // retrieves all credential IDs
  async getAllCredentialIds(): Promise<string[]> {
    const credentialEventRecords = await this.getAllCredentialEventRecords();
    return credentialEventRecords.map(e => e.credentialId);
  }

  // retrieves all status credentials
  async getAllStatusCredentials(): Promise<VerifiableCredential[]> {
    const statusCredentialRecords = await this.getAllStatusCredentialRecords();
    return statusCredentialRecords.map(r => r.credential);
  }
}

// composes StatusList2021Credential
export async function composeStatusCredential({
  issuerDid,
  credentialId,
  statusList,
  statusPurpose = 'revocation'
}: ComposeStatusCredentialOptions): Promise<any> {
  // determine whether or not to create a new status credential
  if (!statusList) {
    statusList = await createList({ length: CREDENTIAL_STATUS_LIST_SIZE });
  }

  // create status credential
  const issuanceDate = getDateString();
  let credential = await createCredential({
    id: credentialId,
    list: statusList,
    statusPurpose
  });
  credential = {
    ...credential,
    issuer: issuerDid,
    issuanceDate
  };

  return credential;
}
