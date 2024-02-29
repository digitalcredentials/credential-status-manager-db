# credential-status-manager-db

[![Build status](https://img.shields.io/github/actions/workflow/status/digitalcredentials/credential-status-manager-db/main.yml?branch=main)](https://github.com/digitalcredentials/credential-status-manager-db/actions?query=workflow%3A%22Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/@digitalcredentials/credential-status-manager-db.svg)](https://npm.im/@digitalcredentials/credential-status-manager-db)

> A Typescript library for managing the status of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model) in a database using [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021)

## Table of Contents

- [Background](#background)
- [Install](#install)
  - [NPM](#npm)
  - [Development](#development)
- [Usage](#usage)
  - [Create credential status manager](#create-credential-status-manager)
  - [Allocate status for credential](#allocate-status-for-credential)
  - [Update status of credential](#update-status-of-credential)
  - [Check status of credential](#check-status-of-credential)
- [Schemas](schemas)
  - [`StatusCredential`](#statuscredential)
  - [`Config`](#config)
  - [`Event`](#event)
  - [`CredentialEvent`](#credentialevent)
- [Dependencies](#dependencies)
  - [Generate DID seeds](#generate-did-seeds)
- [Contribute](#contribute)
- [License](#license)

## Background

Credentials are dynamic artifacts with a lifecycle that goes well beyond issuance. This lifecycle is liable to span revocation, suspension, and expiry, among other common states. Many proposals have been put forth to capture these statuses in Verifiable Credentials. One of the most mature specifications for this is [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021). This library provides an implementation of this specification that leverages database services like MongoDB and MySQL for storage and authentication.

## Install

- Node.js 20+ is recommended.

### NPM

To install via NPM:

```
npm install @digitalcredentials/credential-status-manager-db
```

### Development

To install locally (for development):

```
git clone https://github.com/digitalcredentials/credential-status-manager-db.git
cd credential-status-manager-db
npm install
```

## Usage

### Create credential status manager

The `createStatusManager` function is the only exported pure function of this library. It is an asynchronous function that accepts configuration options and returns a credential status manager that aligns with these options. Here are all the possible configuration options:

| Key | Description | Type | Required |
| --- | --- | --- | --- |
| `databaseService` | name of the database service that will host the credential status resources | `mongodb` | yes |
| `statusCredentialSiteOrigin` | base URL of status credentials managed by a given deployment | string | yes |
| `databaseUrl` | URL of the database instance used to manage credential status data | string | yes (if `databaseHost`, `databasePort`, `databaseUsername`, and `databasePassword` are not set) |
| `databaseHost` | host of the database instance used to manage credential status data | string | yes (if `databaseUrl` is not set) |
| `databasePort` | port of the database instance used to manage credential status data | string | yes (if `databaseUrl` is not set) |
| `databaseUsername` | username of user with read/write privileges on the database instance used to manage credential status data | string | yes (if `databaseUrl` is not set) |
| `databasePassword` | password associated with `databaseUsername` | string | yes (if `databaseUrl` is not set) |
| `databaseName` | name of the database instance used to manage credential status data | string | no (default: `credentialStatus`) |
| `statusCredentialTableName` | name of the database table used to manage status credentials | string | no (default: `StatusCredential`; [schema](#statuscredential)) |
| `configTableName` | name of the database table used to manage application configuration | string | no (default: `Config`; [schema](#config)) |
| `eventTableName` | name of the database table used to manage credential status events | string | no (default: `Event`; [schema](#event)) |
| `credentialEventTableName` | name of the database table used to manage the latest status event for a given credential | string | no (default: `CredentialEvent`; [schema](#credentialevent)) |
| `autoDeployDatabase` | whether or not to automatically create the database (`databaseName`) and the initial tables (`statusCredentialTableName` and `configTableName`) | string | no (default: `true`) |
| `didMethod` | name of the DID method used for signing | `key` \| `web` | yes |
| `didSeed` | seed used to deterministically generate DID | string | yes |
| `didWebUrl` | URL for `did:web` | string | yes (if `didMethod` = `web`) |
| `signStatusCredential` | whether or not to sign status credentials | boolean | no (default: `true`) |
| `signUserCredential` | whether or not to sign user credentials | boolean | no (default: `false`) |

Here is a sample call to `createStatusManager`:

```ts
import { createStatusManager } from '@digitalcredentials/credential-status-manager-db';

const statusManager = await createStatusManager({
  databaseService: 'mongodb',
  statusCredentialSiteOrigin: 'https://credentials.example.edu/status',
  databaseUrl: 'mongodb+srv://testuser:testpass@domain.mongodb.net?retryWrites=false',
  databaseUsername: 'testuser',
  databasePassword: 'testpass',
  didMethod: 'key',
  didSeed: 'DsnrHBHFQP0ab59dQELh3uEwy7i5ArcOTwxkwRO2hM87CBRGWBEChPO7AjmwkAZ2' // Please create your own DID seed (see Dependencies section for detailed instructions)
});
```

### Allocate status for credential

`allocateStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts a credential as input, records its status in a previously configured database instance, and returns the credential with status metadata attached.

Here is a sample call to `allocateStatus`:

```ts
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  id: 'https://credentials.example.edu/3732',
  type: [
    'VerifiableCredential'
  ],
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  issuanceDate: '2020-03-10T04:24:12.164Z',
  credentialSubject: {
    id: 'did:example:abcdef'
  }
};
const credentialWithStatus = await statusManager.allocateStatus(credential);
console.log(credentialWithStatus);
/*
{
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://w3id.org/vc/status-list/2021/v1'
  ],
  id: 'https://credentials.example.edu/3732',
  type: [ 'VerifiableCredential' ],
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  issuanceDate: '2020-03-10T04:24:12.164Z',
  credentialSubject: { id: 'did:example:abcdef' },
  credentialStatus: {
    id: 'https://credentials.example.edu/status/V27UAUYPNR#1',
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: '1',
    statusListCredential: 'https://credentials.example.edu/status/V27UAUYPNR'
  }
}
*/
```

**Note:** If the caller invokes `allocateStatus` multiple times with the same credential ID against the same instance of a credential status manager, the library will not allocate a new entry. It will just return a credential with the same status info as it did in the previous invocation.

### Update status of credential

`updateStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts a credential ID and desired credential status as input (options: `active` | `revoked`), records its new status in a previously configured database instance, and returns the status credential.

Here is a sample call to `updateStatus`:

```ts
const statusCredential = await statusManager.updateStatus({
  credentialId: credentialWithStatus.id,
  credentialStatus: 'revoked'
});
console.log(statusCredential);
/*
{
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/vc/status-list/2021/v1'
  ],
  id: 'https://credentials.example.edu/status/V27UAUYPNR',
  type: [ 'VerifiableCredential', 'StatusList2021Credential' ],
  credentialSubject: {
    id: 'https://credentials.example.edu/status/V27UAUYPNR#list',
    type: 'StatusList2021',
    encodedList: 'H4sIAAAAAAAAA-3BMQ0AAAACIGf_0LbwAhoAAAAAAAAAAAAAAIC_AfqBUGnUMAAA',
    statusPurpose: 'revocation'
  },
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  issuanceDate: '2023-03-15T19:21:54.093Z'
}
*/
```

### Check status of credential

`checkStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts a credential ID as input and returns status information for the credential.

Here is a sample call to `checkStatus`:

```ts
const credentialStatus = await statusManager.checkStatus(credentialWithStatus.id);
console.log(credentialStatus);
/*
{
  id: 'b3153335-5814-47c1-9ee2-eb173d055d13',
  timestamp: '2023-03-15T19:39:06.023Z',
  credentialId: 'https://credentials.example.edu/3732',
  credentialIssuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  credentialSubject: 'did:example:abcdef',
  credentialState: 'revoked',
  verificationMethod: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC#z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  statusCredentialId: 'V27UAUYPNR',
  credentialStatusIndex: 1
}
*/
```

## Schemas

There is a lot of data that is managed by this service. In this section, we will outline the schemas for each database table maintained by a given deployment.

### `StatusCredential`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the database record | string |
| `credential` | Status List 2021 verifiable credential | object ([BitstringStatusListCredential](https://www.w3.org/TR/vc-bitstring-status-list#bitstringstatuslistcredential)) |

### `Config`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the database record | string |
| `statusCredentialSiteOrigin` | base URL of status credentials managed by a given deployment | string |
| `latestStatusCredentialId` | ID of the latest status credential to be created in a given deployment | string |
| `latestCredentialsIssuedCounter` | number of credentials to be issued against the latest status credential to be created in a given deployment | number |
| `allCredentialsIssuedCounter` | total number of credentials to be issued in a given deployment | number |

### `Event`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the database record | string |
| `timestamp` | ISO timestamp of the moment that the event was recorded | string |
| `credentialId` | ID of the credential associated with the event | string |
| `credentialIssuer` | ID of the issuer of the credential associated with the event | string |
| `credentialSubject` | ID of the subject of the credential associated with the event | string |
| `credentialState` | state of the credential associated with the event | `active` \| `revoked` |
| `verificationMethod` | reference of the public key used to sign the credential associated with the event | string |
| `statusCredentialId` | ID of the status credential associated with the event | string |
| `credentialStatusIndex` | position allocated on the status credential for the credential associated with the event | number |

### `CredentialEvent`

| Key | Description | Type |
| --- | --- | --- |
| `credentialId` | ID of a previously issued credential | string |
| `eventId` | ID of the latest status event for credential with ID `credentialId` | string |

## Dependencies

### Generate DID seeds

In order to generate a DID seed, you will need to use software that is capable of creating it in a format that corresponds to a valid DID document. Here is sample code that does this:

```ts
import { generateSecretKeySeed } from '@digitalcredentials/bnid';

// Set `didSeed` key to this value
const secretKeySeed = await generateSecretKeySeed();
```

If `didMethod` = `web`, you must also generate a DID document and host it at `didWebUrl`/.well-known/did.json. Here is sample code that does this:

```ts
import { decodeSecretKeySeed } from '@digitalcredentials/bnid';
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalcredentials/x25519-key-agreement-key-2020';
import * as DidWeb from '@interop/did-web-resolver';
import { CryptoLD } from '@digitalcredentials/crypto-ld';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2020);
const didWebDriver = DidWeb.driver({ cryptoLd });

const decodedSeed = decodeSecretKeySeed({secretKeySeed});

// Host this document at `didWebUrl`/.well-known/did.json
const didWebUrl = 'https://example.edu';
const didDocument = didWebDriver.generate({ url: didWebUrl, seed: decodedSeed });
```

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2024 Digital Credentials Consortium.
