/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import 'mocha';
import { expect } from 'chai';
import { createSandbox } from 'sinon';
import * as MongoDb from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { createStatusManager } from '../src/index.js';
import {
  BaseCredentialStatusManager,
  BaseCredentialStatusManagerOptions,
  DatabaseService
} from '../src/credential-status-manager-base.js';
import * as MongoDbStatus from '../src/credential-status-manager-mongodb.js';
import {
  checkLocalCredentialStatus,
  checkRemoteCredentialStatus,
  checkStatusCredential,
  checkUserCredentialInfo,
  databasePassword,
  databaseUsername,
  didMethod,
  didSeed,
  statusCredentialSiteOrigin,
  unsignedCredential1,
  unsignedCredential2,
  unsignedCredential3
} from './helpers.js';

const sandbox = createSandbox();

class MockMongoDbCredentialStatusManager extends MongoDbStatus.MongoDbCredentialStatusManager {
  server?: MongoMemoryServer;

  constructor(options: BaseCredentialStatusManagerOptions) {
    super(options);
  }

  // retrieve database client
  async getDatabaseClient(options?: MongoDbStatus.MongoDbConnectionOptions) {
    if (!this.server) {
      this.server = await MongoMemoryServer.create();
    }
    const databaseUrl = this.server.getUri();
    const client = new MongoDb.MongoClient(databaseUrl);
    return client;
  }

  // executes function as transaction
  async executeTransaction(func: (options?: MongoDbStatus.MongoDbConnectionOptions) => Promise<any>): Promise<any> {
    const result = await func();
    return result;
  }

  // start database instance
  async startDatabase(): Promise<void> {
    if (this.server?.state !== 'running') {
      await this.server?.start();
    }
  }

  // stop database instance
  async stopDatabase(): Promise<boolean> {
    let stopResult = false;
    if (this.server?.state !== 'stopped') {
      stopResult = (await this.server?.stop())!;
    }
    return stopResult;
  }
}

describe('MongoDB Credential Status Manager', () => {
  const databaseService = 'mongodb' as DatabaseService;
  let statusManager: MongoDbStatus.MongoDbCredentialStatusManager;
  sandbox.stub(MongoDbStatus, 'MongoDbCredentialStatusManager').value(MockMongoDbCredentialStatusManager);

  beforeEach(async () => {
    statusManager = await createStatusManager({
      databaseService,
      databaseUrl: 'OverriddenByGetDatabaseClient',
      databaseUsername,
      databasePassword,
      statusCredentialSiteOrigin,
      didMethod,
      didSeed,
      signStatusCredential: true,
      signUserCredential: true
    }) as MongoDbStatus.MongoDbCredentialStatusManager;
    await (statusManager as MockMongoDbCredentialStatusManager).startDatabase();
  });

  afterEach(async () => {
    await (statusManager as MockMongoDbCredentialStatusManager).stopDatabase();
  });

  it('tests output of createStatusManager', async () => {
    expect(statusManager).to.be.instanceof(BaseCredentialStatusManager);
    expect(statusManager).to.be.instanceof(MongoDbStatus.MongoDbCredentialStatusManager);
  });

  it('tests allocateRevocationStatus', async () => {
    // allocate and check status for first credential
    const credentialWithStatus1 = await statusManager.allocateRevocationStatus(unsignedCredential1) as any;
    checkLocalCredentialStatus(credentialWithStatus1, 1);

    // allocate and check status for second credential
    const credentialWithStatus2 = await statusManager.allocateRevocationStatus(unsignedCredential2) as any;
    checkLocalCredentialStatus(credentialWithStatus2, 2);

    // allocate and check status for third credential
    const credentialWithStatus3 = await statusManager.allocateRevocationStatus(unsignedCredential3) as any;
    checkLocalCredentialStatus(credentialWithStatus3, 3);

    // attempt to allocate and check status for existing credential
    const credentialWithStatus2Copy = await statusManager.allocateRevocationStatus(unsignedCredential2) as any;
    checkLocalCredentialStatus(credentialWithStatus2Copy, 2);

    // check if database has valid configuration
    const databaseState = await statusManager.getDatabaseState();
    expect(databaseState.valid).to.be.true;
  });

  it('tests allocateRevocationStatus and getCredentialInfo', async () => {
    // allocate status for credential
    const credentialWithStatus = await statusManager.allocateRevocationStatus(unsignedCredential1) as any;

    // check user credential info
    const credentialRecord = await statusManager.getCredentialInfo(credentialWithStatus.id);
    checkUserCredentialInfo(credentialWithStatus.id, credentialRecord, 1, true);

    // check if database has valid configuration
    const databaseState = await statusManager.getDatabaseState();
    expect(databaseState.valid).to.be.true;
  });

  it('tests updateStatus and getStatus', async () => {
    // allocate status for credential
    const credentialWithStatus = await statusManager.allocateRevocationStatus(unsignedCredential1) as any;

    // update status of credential
    const statusCredential = await statusManager.revokeCredential(credentialWithStatus.id) as any;

    // check status credential
    checkStatusCredential(statusCredential);

    // check status of credential
    const statusInfo = await statusManager.getStatus(credentialWithStatus.id);
    checkRemoteCredentialStatus(statusInfo, 1, false);

    // check if database has valid configuration
    const databaseState = await statusManager.getDatabaseState();
    expect(databaseState.valid).to.be.true;
  });
});
