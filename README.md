# credential-status-manager-db

[![Build status](https://img.shields.io/github/actions/workflow/status/digitalcredentials/credential-status-manager-db/main.yml?branch=main)](https://github.com/digitalcredentials/credential-status-manager-db/actions?query=workflow%3A%22Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/@digitalcredentials/credential-status-manager-db.svg)](https://npm.im/@digitalcredentials/credential-status-manager-db)

> A Typescript library for managing the status of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0) in a database using [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list)

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
  - [`UserCredential`](#usercredential)
  - [`Config`](#config)
  - [`Event`](#event)
- [Dependencies](#dependencies)
  - [Generate DID seeds](#generate-did-seeds)
- [Contribute](#contribute)
- [License](#license)

## Background

Credentials are dynamic artifacts with a lifecycle that goes well beyond issuance. This lifecycle is liable to span revocation, suspension, and expiry, among other common states. Many proposals have been put forth to capture these statuses in Verifiable Credentials. One of the most mature specifications for this is [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list). This library provides an implementation of this specification that leverages database services like MongoDB and MySQL for storage and authentication.

## Install

- Node.js 20+ is recommended.

### NPM

To install via NPM:

```bash
npm install @digitalcredentials/credential-status-manager-db
```

### Development

To install locally (for development):

```bash
git clone https://github.com/digitalcredentials/credential-status-manager-db.git
cd credential-status-manager-db
npm install
```

## Usage

### Create credential status manager

The `createStatusManager` function is the only exported pure function of this library. It is an asynchronous function that accepts configuration options and returns a credential status manager that aligns with these options. Here are all the possible configuration options:

| Key | Description | Type | Required |
| --- | --- | --- | --- |
| `databaseService` | name of the database service used to manage credential status data | `mongodb` | yes |
| `statusCredentialSiteOrigin` | base URL of status credentials managed by a given deployment | string | yes |
| `databaseUrl` | URL of the database instance used to manage credential status data | string | yes (if `databaseHost`, `databasePort`, `databaseUsername`, and `databasePassword` are not set) |
| `databaseHost` | host of the database instance used to manage credential status data | string | yes (if `databaseUrl` is not set) |
| `databasePort` | port of the database instance used to manage credential status data | number | yes (if `databaseUrl` is not set) |
| `databaseUsername` | username of user with read/write privileges on the database instance used to manage credential status data | string | yes (if `databaseUrl` is not set) |
| `databasePassword` | password associated with `databaseUsername` | string | yes (if `databaseUrl` is not set) |
| `databaseName` | name of the database instance used to manage credential status data | string | no (default: `credentialStatus`) |
| `statusCredentialTableName` | name of the database table used to manage status credentials ([schema](#statuscredential)) | string | no (default: `StatusCredential`) |
| `userCredentialTableName` | name of the database table used to manage user credentials ([schema](#usercredential)) | string | no (default: `UserCredential`) |
| `configTableName` | name of the database table used to manage application configuration ([schema](#config)) | string | no (default: `Config`) |
| `eventTableName` | name of the database table used to manage credential status events ([schema](#event)) | string | no (default: `Event`) |
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

`allocateStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts a credential and an array of status purposes as input (options: `revocation` | `suspension`), records its status in a previously configured database instance, and returns the credential with status metadata attached.

Here is a sample call to `allocateStatus`:

```ts
const credential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  id: 'https://credentials.example.edu/3732',
  type: [
    'VerifiableCredential'
  ],
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  validFrom: '2020-03-10T04:24:12.164Z',
  credentialSubject: {
    id: 'did:example:abcdef'
  }
};
const credentialWithStatus = await statusManager.allocateStatus({
  credential,
  statusPurposes: ['revocation', 'suspension']
});
console.log(credentialWithStatus);
/*
{
  '@context': [
    'https://www.w3.org/ns/credentials/v2'
  ],
  id: 'https://credentials.example.edu/3732',
  type: [ 'VerifiableCredential' ],
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  validFrom: '2020-03-10T04:24:12.164Z',
  credentialSubject: { id: 'did:example:abcdef' },
  credentialStatus: [
    {
      id: 'https://credentials.example.edu/status/Uz42qSDSXTcoLH7kZ6ST#6',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '6',
      statusListCredential: 'https://credentials.example.edu/status/Uz42qSDSXTcoLH7kZ6ST'
    },
    {
      id: 'https://credentials.example.edu/status/9kGimd8POqM88l32F9aT#3',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'suspension',
      statusListIndex: '3',
      statusListCredential: 'https://credentials.example.edu/status/9kGimd8POqM88l32F9aT'
    }
  ]
}
*/
```

**Note:** You can also call `allocateRevocationStatus(credential)` to achieve the same effect as `allocateStatus({ credential, statusPurposes: ['revocation'] })`, `allocateSuspensionStatus(credential)` to achieve the same effect as `allocateStatus({ credential, statusPurposes: ['suspension'] })`, and `allocateSupportedStatuses(credential)` to achieve the same effect as `allocateStatus({ credential, statusPurposes: ['revocation', 'suspension'] })`.

Additionally, if the caller invokes `allocateStatus` multiple times with the same credential ID against the same instance of a credential status manager, the library will not allocate a new entry. It will just return a credential with the same status info as it did in the previous invocation.

### Update status of credential

`updateStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts as input a credential ID, a status purpose (options: `revocation` | `suspension`), and whether to invalidate the status; records its new status in a previously configured database instance; and returns the status credential.

Here is a sample call to `updateStatus`:

```ts
const statusCredential = await statusManager.updateStatus({
  credentialId: credentialWithStatus.id,
  statusPurpose: 'revocation',
  invalidate: true
});
console.log(statusCredential);
/*
{
  '@context': [
    'https://www.w3.org/ns/credentials/v2'
  ],
  id: 'https://credentials.example.edu/status/Uz42qSDSXTcoLH7kZ6ST',
  type: [ 'VerifiableCredential', 'BitstringStatusListCredential' ],
  credentialSubject: {
    id: 'https://credentials.example.edu/status/Uz42qSDSXTcoLH7kZ6ST#list',
    type: 'BitstringStatusList',
    encodedList: 'H4sIAAAAAAAAA-3BMQ0AAAACIGf_0LbwAhoAAAAAAAAAAAAAAIC_AfqBUGnUMAAA',
    statusPurpose: 'revocation'
  },
  issuer: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC',
  validFrom: '2024-03-10T00:00:00.000Z'
}
*/
```

**Note:** You can also call `revokeCredential(credentialId)` to achieve the same effect as `updateStatus({ credentialId, statusPurpose: 'revocation', invalidate: true })` and `suspendCredential(credentialId)` to achieve the same effect as `updateStatus({ credentialId, statusPurpose: 'suspension', invalidate: true })`. Also note that `unsuspendCredential(credentialId)` will lift a suspension from a credential, while there is no equivalent reversal logic for revocation, since it is not allowed.

### Check status of credential

`getStatus` is an instance method that is called on a credential status manager initialized by `createStatusManager`. It is an asynchronous method that accepts a credential ID as input and returns status information for the credential.

Here is a sample call to `getStatus`:

```ts
const credentialStatus = await statusManager.getStatus(credentialWithStatus.id);
console.log(credentialStatus);
/*
{
  revocation: {
    statusCredentialId: 'Uz42qSDSXTcoLH7kZ6ST',
    statusListIndex: 6,
    valid: true
  },
  suspension: {
    statusCredentialId: '9kGimd8POqM88l32F9aT',
    statusListIndex: 3,
    valid: false
  }
}
*/
```

## Schemas

There is a lot of data that is managed by this service. In this section, we will outline the schemas for each database table maintained by a given deployment.

### `StatusCredential`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the status credential database record | string |
| `order` | the order in which this status credential was created relative to other status credentials | number |
| `purpose` | name of the purpose of this status credential | `revocation` \| `suspension` (see `statusPurpose` [here](https://www.w3.org/TR/vc-bitstring-status-list#bitstringstatuslistcredential)) |
| `credential` | Bitstring Status List Verifiable Credential | object ([BitstringStatusListCredential](https://www.w3.org/TR/vc-bitstring-status-list#bitstringstatuslistcredential)) |

### `UserCredential`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the user credential database record | string |
| `issuer` | ID of the issuer of the credential | string |
| `subject` | ID of the subject of the credential | string |
| `statusInfo` | mapping from status purpose to status info | object |
| `statusInfo[PURPOSE].statusCredentialId` | ID of the status credential associated with the credential for a given purpose | string |
| `statusInfo[PURPOSE].statusListIndex` | position allocated on the status credential for the credential for a given purpose | number |
| `statusInfo[PURPOSE].valid` | validity of the credential according to the status credential tracking its status for a given purpose | boolean |

### `Config`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the config database record | string |
| `statusCredentialSiteOrigin` | base URL of status credentials managed by a given deployment | string |
| `statusCredentialInfo` | mapping from status purpose to status credential info | object |
| `statusCredentialInfo[PURPOSE].latestId` | ID of the latest status credential to be created for a given purpose in a given deployment | string |
| `statusCredentialInfo[PURPOSE].latestOrder` | latestOrder of the latest status credential to be created for a given purpose in a given deployment (total number of status credentials) | number |

### `Event`

| Key | Description | Type |
| --- | --- | --- |
| `id` | ID of the event database record | string |
| `timestamp` | ISO timestamp of the moment that the event was recorded | string |
| `credentialId` | ID of the credential associated with the event | string |
| `statusPurpose` | name of the purpose of the credential status whose modification is being tracked by the event | `revocation` \| `suspension` (see `statusPurpose` [here](https://www.w3.org/TR/vc-bitstring-status-list#bitstringstatuslistcredential)) |
| `valid` | validity of the credential that is being applied by the event | boolean |

## Dependencies

### Generate DID seeds

In order to generate a DID seed, you will need to use software that is capable of creating it in a format that corresponds to a valid DID document. Here is sample code that does this:

```ts
import { generateSecretKeySeed } from 'bnid';

// Set `didSeed` key to this value
const secretKeySeed = await generateSecretKeySeed();
```

If `didMethod` = `web`, you must also generate a DID document and host it at `didWebUrl`/.well-known/did.json. Here is sample code that does this:

```ts
import { decodeSecretKeySeed } from 'bnid';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import * as DidWeb from '@interop/did-web-resolver';
import { CryptoLD } from 'crypto-ld';

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
