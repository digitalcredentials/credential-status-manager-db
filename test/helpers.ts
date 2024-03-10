/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { expect } from 'chai';
import {
  DatabaseService
} from '../src/credential-status-manager-base.js';
import { DidMethod } from '../src/helpers.js';

const credentialId1 = 'https://credentials.example.edu/3732';
const credentialId2 = 'https://credentials.example.edu/6274';
const credentialId3 = 'https://credentials.example.edu/0285';
const credentialSubject = 'did:example:abcdef';
const issuerKey = 'z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC';
const issuerDid = `did:key:${issuerKey}`;
const verificationMethod = `${issuerDid}#${issuerKey}`;

const unsignedCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2'
  ],
  type: [
    'VerifiableCredential'
  ],
  issuer: issuerDid,
  validFrom: '2020-03-10T04:24:12.164Z',
  credentialSubject: {
    id: credentialSubject
  }
};

export const unsignedCredential1 = {
  ...unsignedCredential,
  id: credentialId1
};

export const unsignedCredential2 = {
  ...unsignedCredential,
  id: credentialId2
};

export const unsignedCredential3 = {
  ...unsignedCredential,
  id: credentialId3
};

export const databaseUsername = 'testuser';
export const databasePassword = 'testpass';
export const statusCredentialSiteOrigin = 'https://credentials.example.edu/status';
export const didMethod = 'key' as DidMethod;
export const didSeed = 'DsnrHBHFQP0ab59dQELh3uEwy7i5ArcOTwxkwRO2hM87CBRGWBEChPO7AjmwkAZ2';
export const statusCredentialId = 'V27UAUYPNR';

export function checkLocalCredentialStatus(
  credentialWithStatus: any,
  credentialStatusIndex: number,
  databaseService: DatabaseService
) {
  let statusCredentialUrl;
  switch (databaseService) {
    case DatabaseService.MongoDB:
      statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
      break;
  }
  expect(credentialWithStatus).to.have.property('credentialStatus');
  expect(credentialWithStatus.credentialStatus).to.have.property('id');
  expect(credentialWithStatus.credentialStatus).to.have.property('type');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusPurpose');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusListIndex');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusListCredential');
  expect(credentialWithStatus.credentialStatus.type).to.equal('BitstringStatusListEntry');
  expect(credentialWithStatus.credentialStatus.statusPurpose).to.equal('revocation');
  expect(credentialWithStatus.credentialStatus.statusListIndex).to.equal(credentialStatusIndex.toString());
  expect(credentialWithStatus.credentialStatus.id.startsWith(statusCredentialUrl)).to.be.true;
  expect(credentialWithStatus.credentialStatus.statusListCredential.startsWith(statusCredentialUrl)).to.be.true;
}

export function checkRemoteCredentialStatus(
  credentialStatus: any,
  credentialId: string,
  credentialStatusIndex: number
) {
  expect(credentialStatus).to.have.property('timestamp');
  expect(credentialStatus).to.have.property('credentialId');
  expect(credentialStatus).to.have.property('credentialIssuer');
  expect(credentialStatus).to.have.property('credentialSubject');
  expect(credentialStatus).to.have.property('credentialState');
  expect(credentialStatus).to.have.property('verificationMethod');
  expect(credentialStatus).to.have.property('statusCredentialId');
  expect(credentialStatus).to.have.property('credentialStatusIndex');
  expect(credentialStatus.credentialId).to.equal(credentialId);
  expect(credentialStatus.credentialIssuer).to.equal(issuerDid);
  expect(credentialStatus.credentialSubject).to.equal(credentialSubject);
  expect(credentialStatus.credentialState).to.equal('revoked');
  expect(credentialStatus.verificationMethod).to.equal(verificationMethod);
  expect(credentialStatus.statusCredentialId).to.equal(statusCredentialId);
  expect(credentialStatus.credentialStatusIndex).to.equal(credentialStatusIndex);
}

export function checkStatusCredential(
  statusCredential: any,
  databaseService: DatabaseService
) {
  let statusCredentialUrl;
  switch (databaseService) {
    case DatabaseService.MongoDB:
      statusCredentialUrl = `${statusCredentialSiteOrigin}/${statusCredentialId}`;
      break;
  }
  expect(statusCredential).to.have.property('id');
  expect(statusCredential).to.have.property('type');
  expect(statusCredential).to.have.property('credentialSubject');
  expect(statusCredential.credentialSubject).to.have.property('id');
  expect(statusCredential.credentialSubject).to.have.property('type');
  expect(statusCredential.credentialSubject).to.have.property('encodedList');
  expect(statusCredential.credentialSubject).to.have.property('statusPurpose');
  expect(statusCredential.id).to.equal(statusCredentialUrl);
  expect(statusCredential.type).to.include('BitstringStatusListCredential');
  expect(statusCredential.credentialSubject.id.startsWith(statusCredentialUrl)).to.be.true;
  expect(statusCredential.credentialSubject.type).to.equal('BitstringStatusList');
  expect(statusCredential.credentialSubject.statusPurpose).to.equal('revocation');
}
