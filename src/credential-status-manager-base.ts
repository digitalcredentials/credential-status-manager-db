/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import { CONTEXT_URL_V1 } from '@digitalbazaar/vc-status-list-context';
import { VerifiableCredential } from '@digitalcredentials/vc-data-model';
import { createCredential, createList, decodeList } from '@digitalcredentials/vc-status-list';
import { v4 as uuid } from 'uuid';
import { BadRequestError, InternalServerError, NotFoundError } from './errors.js';
import {
  DidMethod,
  deriveStatusCredentialId,
  getDateString,
  getSigningMaterial,
  signCredential
} from './helpers.js';
import { AwsRegion, AwsStatusCredentialSiteDeployer } from './status-credential-site-deployer-aws.js';
import { BaseStatusCredentialSiteDeployer, BaseStatusCredentialSiteDeployerOptions } from './status-credential-site-deployer-base.js';

// Number of credentials tracked in a list
const CREDENTIAL_STATUS_LIST_SIZE = 100000;

// Credential status type
const CREDENTIAL_STATUS_TYPE = 'StatusList2021Entry';

// Database hosting service
export enum DatabaseService {
  MongoDB = 'mongodb'
  // MySQL = 'mysql' // TODO - implement this
}

// Site hosting service
export enum SiteService {
  AWS = 'aws'
  // DigitalOcean = 'digitalocean', // TODO - implement this
  // Heroku = 'heroku', // TODO - implement this
  // Netlify = 'netlify', // TODO - implement this
  // Vercel = 'vercel' // TODO - implement this
}

// States of credential resulting from caller actions and tracked in the event log
export enum CredentialState {
  Active = 'active',
  Revoked = 'revoked'
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
  statusPurpose?: string;
}

// Type definition for embedCredentialStatus method input
interface EmbedCredentialStatusOptions {
  credential: any;
  statusPurpose?: string;
}

// Type definition for embedCredentialStatus method output
type EmbedCredentialStatusResult = ConfigRecord & {
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
  siteUrl?: string;
  statusCredentialTableName?: string;
  configTableName?: string;
  eventTableName?: string;
  credentialEventTableName?: string;
  databaseName?: string;
  databaseUrl?: string;
  databaseHost?: string;
  databasePort?: string;
  databaseUsername: string;
  databasePassword: string;
  didMethod: DidMethod;
  didSeed: string;
  didWebUrl?: string;
  signUserCredential?: boolean;
  signStatusCredential?: boolean;
  awsRegion?: AwsRegion;
  awsElasticBeanstalkAppName?: string;
  awsElasticBeanstalkEnvName?: string;
  awsS3BucketName?: string;
}

// Minimal set of options required for configuring BaseCredentialStatusManager
export const BASE_MANAGER_REQUIRED_OPTIONS: Array<keyof BaseCredentialStatusManagerOptions> = [
  'databaseUsername',
  'databasePassword',
  'didMethod',
  'didSeed'
];

// Base class for database clients
export abstract class BaseCredentialStatusManager {
  protected siteUrl?: string;
  protected readonly statusCredentialTableName: string;
  protected readonly configTableName: string;
  protected readonly eventTableName: string;
  protected readonly credentialEventTableName: string;
  protected databaseService!: DatabaseService;
  protected readonly databaseName: string;
  protected readonly databaseUrl?: string;
  protected readonly databaseHost?: string;
  protected readonly databasePort?: string;
  protected databaseUsername: string;
  protected databasePassword: string;
  protected readonly didMethod: DidMethod;
  protected readonly didSeed: string;
  protected readonly didWebUrl?: string;
  protected readonly signUserCredential: boolean;
  protected readonly signStatusCredential: boolean;
  protected readonly awsRegion?: AwsRegion;
  protected readonly awsElasticBeanstalkAppName?: string;
  protected readonly awsElasticBeanstalkEnvName?: string;
  protected readonly awsS3BucketName?: string;

  constructor(options: BaseCredentialStatusManagerOptions) {
    const {
      siteUrl,
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
      signUserCredential,
      signStatusCredential,
      awsRegion,
      awsElasticBeanstalkAppName,
      awsElasticBeanstalkEnvName,
      awsS3BucketName
    } = options;
    this.siteUrl = siteUrl;
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
    this.signUserCredential = signUserCredential ?? false;
    this.signStatusCredential = signStatusCredential ?? false;
    this.awsRegion = awsRegion!;
    this.awsElasticBeanstalkAppName = awsElasticBeanstalkAppName!;
    this.awsElasticBeanstalkEnvName = awsElasticBeanstalkEnvName!;
    this.awsS3BucketName = awsS3BucketName!;
    this.validateConfiguration(options);
  }

  // ensures valid configuration of credential status manager
  validateConfiguration(options: BaseCredentialStatusManagerOptions): void {
    const missingOptions = [] as
      Array<keyof BaseCredentialStatusManagerOptions>;

    const isProperlyConfigured = BASE_MANAGER_REQUIRED_OPTIONS.every(
      (option: keyof BaseCredentialStatusManagerOptions) => {
        if (!options[option]) {
          missingOptions.push(option as any);
        }
        return !!options[option];
      }
    );

    if (!isProperlyConfigured) {
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

  // embeds status into credential
  async embedCredentialStatus({ credential, statusPurpose = 'revocation' }: EmbedCredentialStatusOptions, options?: any): Promise<EmbedCredentialStatusResult> {
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
    let {
      id,
      latestStatusCredentialId,
      latestCredentialsIssuedCounter,
      allCredentialsIssuedCounter
    } = await this.getConfigRecord(options);

    // retrieve latest relevant event for credential with given ID
    const event = await this.getLatestEventRecordForCredential(credential.id, options);

    // do not allocate new entry if ID is already being tracked
    if (event) {
      // retrieve relevant event data
      const { statusCredentialId, credentialStatusIndex } = event;

      // attach credential status
      const statusCredentialUrl = `${this.siteUrl}/${statusCredentialId}`;
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
      latestStatusCredentialId = generateStatusCredentialId();
      allCredentialsIssuedCounter++;
    }
    latestCredentialsIssuedCounter++;

    // attach credential status
    const statusCredentialUrl = `${this.siteUrl}/${latestStatusCredentialId}`;
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
  async allocateStatus(credential: VerifiableCredential): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: any) => {
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
      } = await this.embedCredentialStatus({ credential }, options);

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
        const statusCredentialUrl = `${this.siteUrl}/${latestStatusCredentialId}`;
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
      const event: EventRecord = {
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
  }: UpdateStatusOptions): Promise<VerifiableCredential> {
    return this.executeTransaction(async (options?: any) => {
      // retrieve latest relevant event for credential with given ID
      const oldEvent = await this.getLatestEventRecordForCredential(credentialId, options);

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
      const statusCredentialBefore = await this.getStatusCredential(statusCredentialId, options);

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
      const statusCredentialUrl = `${this.siteUrl}/${statusCredentialId}`;
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
      const newEvent: EventRecord = {
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
  async checkStatus(credentialId: string, options?: any): Promise<EventRecord> {
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

  // deploys website to host status credential
  async deployStatusCredentialWebsite(service: SiteService): Promise<void> {
    let siteDeployer: BaseStatusCredentialSiteDeployer;
    const baseOptions: BaseStatusCredentialSiteDeployerOptions = {
      DB_SERVICE: this.databaseService,
      DB_NAME: this.databaseName,
      DB_URL: await this.getDatabaseUrl(),
      DB_STATUS_CRED_TABLE_NAME: this.statusCredentialTableName
    };
    switch (service) {
      case SiteService.AWS:
        siteDeployer = new AwsStatusCredentialSiteDeployer({
          ...baseOptions,
          awsRegion: this.awsRegion!,
          awsElasticBeanstalkAppName: this.awsElasticBeanstalkAppName!,
          awsElasticBeanstalkEnvName: this.awsElasticBeanstalkEnvName!,
          awsS3BucketName: this.awsS3BucketName!
        });
        break;
      default:
        throw new BadRequestError({
          message:
            '"service" must be one of the following values: ' +
            `${Object.values(SiteService).map(s => `"${s}"`).join(', ')}.`
        });
    }
    this.siteUrl = await siteDeployer.run();
  };

  // retrieves database URL
  abstract getDatabaseUrl(): Promise<string>;

  // executes function as transaction
  abstract executeTransaction(func: (options?: any) => Promise<any>): Promise<any>;

  // checks if caller has authority to manage status based on authorization credentials
  abstract hasAuthority(databaseUsername: string, databasePassword: string, options?: any): Promise<boolean>;

  // creates database
  abstract createDatabase(options?: any): Promise<void>;

  // creates database table
  abstract createDatabaseTable(tableName: string, options?: any): Promise<void>;

  // creates database tables
  async createDatabaseTables(options?: any): Promise<void> {
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
  async createDatabaseResources(options?: any): Promise<void> {
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
  async initializeDatabaseResources(options?: any): Promise<void> {
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

    // create and persist status config
    const statusCredentialId = generateStatusCredentialId();
    const config: ConfigRecord = {
      id: uuid(),
      latestStatusCredentialId: statusCredentialId,
      latestCredentialsIssuedCounter: 0,
      allCredentialsIssuedCounter: 0
    };
    await this.createConfig(config, options);

    // create status credential
    const statusCredentialUrl = `${this.siteUrl}/${statusCredentialId}`;
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

    // create and persist status data
    await this.createStatusCredential({
      id: statusCredentialId,
      credential: statusCredential
    }, options);
  }

  // checks if database exists
  abstract databaseExists(options?: any): Promise<boolean>;

  // checks if database table exists
  abstract databaseTableExists(tableName: string, options?: any): Promise<boolean>;

  // checks if database tables exist
  async databaseTablesExist(options?: any): Promise<boolean> {
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
  abstract databaseTableEmpty(tableName: string, options?: any): Promise<boolean>;

  // checks if database tables are empty
  async databaseTablesEmpty(options?: any): Promise<boolean> {
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

  // checks if database tables are properly configured
  async databaseTablesProperlyConfigured(options?: any): Promise<boolean> {
    try {
      // retrieve config data
      const {
        latestStatusCredentialId,
        latestCredentialsIssuedCounter,
        allCredentialsIssuedCounter
      } = await this.getConfigRecord(options);
      const statusCredentialUrl = `${this.siteUrl}/${latestStatusCredentialId}`;
      const statusCredentials = await this.getAllStatusCredentials(options);

      // ensure status data is consistent
      let hasLatestStatusCredentialId = false;
      for (const credential of statusCredentials) {
        // report error for compact JWT credentials
        if (typeof credential === 'string') {
          return false;
        }

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

      // retrieve credential IDs from event log
      const credentialIds = await this.getAllCredentialIds(options);
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

  // creates single database record
  abstract createRecord<T>(tableName: string, record: T, options?: any): Promise<void>;

  // creates status credential
  async createStatusCredential(statusCredentialRecord: StatusCredentialRecord, options?: any): Promise<void> {
    try {
      await this.createRecord(this.statusCredentialTableName, statusCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create status credential: ${error.message}`
      });
    }
  }

  // creates config
  async createConfig(config: ConfigRecord, options?: any): Promise<void> {
    try {
      await this.createRecord(this.configTableName, config, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create config: ${error.message}`
      });
    }
  }

  // creates event
  async createEvent(event: EventRecord, options?: any): Promise<void> {
    try {
      await this.createRecord(this.eventTableName, event, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event: ${error.message}`
      });
    }
  }

  // creates credential event
  async createCredentialEvent(credentialEvent: CredentialEventRecord, options?: any): Promise<void> {
    try {
      await this.createRecord(this.credentialEventTableName, credentialEvent, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to create event for credential: ${error.message}`
      });
    }
  }

  // updates single database record
  abstract updateRecord<T>(tableName: string, recordIdKey: string, recordIdValue: string, record: T, options?: any): Promise<void>;

  // updates status credential
  async updateStatusCredential(statusCredentialRecord: StatusCredentialRecord, options?: any): Promise<void> {
    try {
      const { id } = statusCredentialRecord;
      await this.updateRecord(this.statusCredentialTableName, 'id', id, statusCredentialRecord, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to update status credential: ${error.message}`
      });
    }
  }

  // updates config
  async updateConfig(config: ConfigRecord, options?: any): Promise<void> {
    try {
      const { id } = config;
      await this.updateRecord(this.configTableName, 'id', id, config, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to update config: ${error.message}`
      });
    }
  }

  // updates credential event
  async updateCredentialEvent(credentialEvent: CredentialEventRecord, options?: any): Promise<void> {
    try {
      const { credentialId } = credentialEvent;
      await this.updateRecord(this.credentialEventTableName, 'credentialId', credentialId, credentialEvent, options);
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to update event for credential: ${error.message}`
      });
    }
  }

  // retrieves any database record
  abstract getAnyRecord<T>(tableName: string, options?: any): Promise<T | null>;

  // retrieves config ID
  async getConfigId(options?: any): Promise<string> {
    let record;
    try {
      record = await this.getAnyRecord(this.configTableName, options);
      if (!record) {
        throw new NotFoundError({
          message: 'Unable to find config.'
        });
      }
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get config ID: ${error.message}`
      });
    }
    return (record as ConfigRecord).id;
  }

  // retrieves single database record by field
  abstract getRecordByField<T>(tableName: string, fieldKey: string, fieldValue: string, options?: any): Promise<T | null>;

  // retrieves single database record by id
  async getRecordById<T>(tableName: string, id: string, options?: any): Promise<T | null> {
    return this.getRecordByField(tableName, 'id', id, options);
  }

  // retrieves status credential record by ID
  async getStatusCredentialRecordById(statusCredentialId: string, options?: any): Promise<StatusCredentialRecord> {
    let record;
    try {
      record = await this.getRecordById(this.statusCredentialTableName, statusCredentialId, options);
      if (!record) {
        throw new NotFoundError({
          message: `Unable to find status credential with ID "${statusCredentialId}".`
        });
      }
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get status credential with ID "${statusCredentialId}": ${error.message}`
      });
    }
    return record as StatusCredentialRecord;
  }

  // retrieves status credential by ID
  async getStatusCredential(statusCredentialId: string, options?: any): Promise<VerifiableCredential> {
    const { credential } = await this.getStatusCredentialRecordById(statusCredentialId, options);
    return credential as VerifiableCredential;
  }

  // retrieves config by ID
  async getConfigRecord(options?: any): Promise<ConfigRecord> {
    const configId = await this.getConfigId(options);
    let record;
    try {
      record = await this.getRecordById(this.configTableName, configId, options);
      if (!record) {
        throw new NotFoundError({
          message: `Unable to find config with ID "${configId}".`
        });
      }
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get config with ID "${configId}": ${error.message}`
      });
    }
    return record as ConfigRecord;
  }

  // retrieves latest event featuring credential with given ID
  async getLatestEventRecordForCredential(credentialId: string, options?: any): Promise<EventRecord> {
    let eventRecord;
    try {
      const credentialEventRecord = await this.getRecordByField<CredentialEventRecord>(this.credentialEventTableName, 'credentialId', credentialId, options);
      if (!credentialEventRecord) {
        throw new NotFoundError({
          message: `Unable to find event for credential with ID "${credentialId}".`
        });
      }
      const { eventId } = credentialEventRecord;
      eventRecord = await this.getRecordById(this.eventTableName, eventId, options);
      if (!eventRecord) {
        throw new NotFoundError({
          message: `Unable to find event with ID "${eventId}".`
        });
      }
    } catch (error: any) {
      throw new InternalServerError({
        message: `Unable to get latest event for credential with ID "${credentialId}": ${error.message}`
      });
    }
    return eventRecord as EventRecord;
  }

  // retrieves all records in table
  abstract getAllRecords<T>(tableName: string, options?: any): Promise<T[]>;

  // retrieves all status credential records
  async getAllStatusCredentialRecords(options?: any): Promise<StatusCredentialRecord[]> {
    return this.getAllRecords(this.statusCredentialTableName, options);
  }

  // retrieves all credential event records
  async getAllCredentialEventRecords(options?: any): Promise<EventRecord[]> {
    return this.getAllRecords(this.credentialEventTableName, options);
  }

  // retrieves all credential IDs
  async getAllCredentialIds(options?: any): Promise<string[]> {
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
  async getAllStatusCredentials(options?: any): Promise<VerifiableCredential[]> {
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

// composes StatusList2021Credential
export async function composeStatusCredential({
  issuerDid,
  credentialId,
  statusList,
  statusPurpose = 'revocation'
}: ComposeStatusCredentialOptions): Promise<VerifiableCredential> {
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

// generates new status credential ID
// Note: We assume this function will never generate an ID that
// has never been generated for a status credential in this system
function generateStatusCredentialId(): string {
  return Math.random().toString(36).substring(2, 12).toUpperCase();
}
