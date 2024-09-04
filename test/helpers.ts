/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { expect } from 'chai';
import { DidMethod } from '../src/helpers.js';

const credentialId1 = 'https://credentials.example.edu/3732';
const credentialId2 = 'https://credentials.example.edu/6274';
const credentialId3 = 'https://credentials.example.edu/0285';
const credentialSubject = 'did:example:abcdef';
const issuerKey = 'z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC';
const issuerDid = `did:key:${issuerKey}`;

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

export function checkLocalCredentialStatus(credentialWithStatus: any) {
  expect(credentialWithStatus).to.have.property('credentialStatus');
  expect(credentialWithStatus.credentialStatus).to.have.property('id');
  expect(credentialWithStatus.credentialStatus).to.have.property('type');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusPurpose');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusListIndex');
  expect(credentialWithStatus.credentialStatus).to.have.property('statusListCredential');
  expect(credentialWithStatus.credentialStatus.type).to.equal('BitstringStatusListEntry');
  expect(credentialWithStatus.credentialStatus.statusPurpose).to.equal('revocation');
  expect(credentialWithStatus.credentialStatus.id.startsWith(statusCredentialSiteOrigin)).to.be.true;
  expect(credentialWithStatus.credentialStatus.statusListCredential.startsWith(statusCredentialSiteOrigin)).to.be.true;
}

export function checkRemoteCredentialStatus(
  statusInfo: any,
  valid: boolean
) {
  expect(statusInfo).to.have.property('revocation');
  expect(statusInfo.revocation).to.have.property('statusCredentialId');
  expect(statusInfo.revocation).to.have.property('statusListIndex');
  expect(statusInfo.revocation).to.have.property('valid');
  expect(statusInfo.revocation.valid).to.equal(valid);
}

export function checkStatusCredential(
  statusCredential: any
) {
  expect(statusCredential).to.have.property('id');
  expect(statusCredential).to.have.property('type');
  expect(statusCredential).to.have.property('credentialSubject');
  expect(statusCredential.credentialSubject).to.have.property('id');
  expect(statusCredential.credentialSubject).to.have.property('type');
  expect(statusCredential.credentialSubject).to.have.property('encodedList');
  expect(statusCredential.credentialSubject).to.have.property('statusPurpose');
  expect(statusCredential.id.startsWith(statusCredentialSiteOrigin)).to.be.true;
  expect(statusCredential.type).to.include('BitstringStatusListCredential');
  expect(statusCredential.credentialSubject.id.startsWith(statusCredentialSiteOrigin)).to.be.true;
  expect(statusCredential.credentialSubject.type).to.equal('BitstringStatusList');
  expect(statusCredential.credentialSubject.statusPurpose).to.equal('revocation');
}

export function checkUserCredentialInfo(
  credentialId: string,
  credentialRecord: any,
  valid: boolean
) {
  expect(credentialRecord).to.have.property('id');
  expect(credentialRecord).to.have.property('issuer');
  expect(credentialRecord).to.have.property('subject');
  expect(credentialRecord).to.have.property('statusInfo');
  expect(credentialRecord.id).to.equal(credentialId);
  expect(credentialRecord.issuer).to.equal(issuerDid);
  expect(credentialRecord.subject).to.equal(credentialSubject);
  checkRemoteCredentialStatus(credentialRecord.statusInfo, valid);
}
