/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import * as uuid from 'uuid';
import * as vcBitstringStatusListContext from '@digitalbazaar/vc-bitstring-status-list-context';
import { decodeSecretKeySeed } from 'bnid';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { securityLoader } from '@digitalcredentials/security-document-loader';
import { issue as sign } from '@digitalbazaar/vc';
import { VerifiableCredential } from '@digitalcredentials/vc-data-model';
import * as DidKey from '@digitalbazaar/did-method-key';
import * as DidWeb from '@interop/did-web-resolver';
import { CryptoLD } from 'crypto-ld';
import { BadRequestError, InvalidDidSeedError } from './errors.js';

// Crypto library for linked data
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2020);

// DID drivers
const didWebDriver = DidWeb.driver({ cryptoLd });
const didKeyDriver = DidKey.driver();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from
});

// Document loader
const documentLoader = securityLoader().build();

// Max length for credential IDs
export const MAX_CREDENTIAL_ID_LENGTH = 64;

const vc1ContextId = 'https://www.w3.org/2018/credentials/v1'
const vc2ContextId = 'https://www.w3.org/ns/credentials/v2'
// DID method used to sign credentials
export enum DidMethod {
  Key = 'key',
  Web = 'web'
}

// Type definition for signCredential method input
interface SignCredentialOptions {
  credential: any;
  didMethod: DidMethod;
  didSeed: string;
  didWebUrl?: string;
}

// Type definition for getSigningKeys method input
interface GetSigningKeysOptions {
  didMethod: DidMethod;
  didSeed: string;
  didWebUrl?: string;
}

// Type definition for getSigningKeys method output
interface GetSigningKeysResult {
  didDocument: any;
  issuerDid: string;
  keyPairs: Map<string, any>;
  verificationMethod: string;
  signingKey: any;
}

// validates credential
export function validateCredential(credential: VerifiableCredential): void {
  if (typeof credential === 'string') {
    throw new BadRequestError({
      message: 'This library does not support compact JWT credentials.'
    });
  }

  if (!Array.isArray(credential['@context']) || credential['@context'].length === 0) {
    throw new BadRequestError({
      message: 'This library does not support credentials with ' +
        'a "@context" value that is not a non-empty array.'
    });
  }

  switch (credential['@context'][0]) {
    case vc1ContextId:
      // ensure that credential contains valid status credential context in VC 1.1
      if (!credential['@context'].includes(vcBitstringStatusListContext.CONTEXT_URL)) {
        credential['@context'].push(vcBitstringStatusListContext.CONTEXT_URL);
      }
      break;
    case vc2ContextId:
      // no additional contexts need to be added in VC 2.0
      break;
    default:
      throw new BadRequestError({
        message: 'This library does not support credentials ' +
          'that do not conform to VC 1.1 or VC 2.0. ' +
          'Note: The first value in the "@context" array must be ' +
          `${vc1ContextId} or ${vc2ContextId}.`
      });
  }
}

// retrieves credential subject entry
export function getCredentialSubjectObject(credential: VerifiableCredential): any {
  // report error for compact JWT credentials
  if (typeof credential === 'string') {
    throw new BadRequestError({
      message: 'This library does not support compact JWT credentials.'
    });
  }
  if (Array.isArray(credential.credentialSubject)) {
    return credential.credentialSubject[0];
  }
  return credential.credentialSubject;
}

// signs credential
export async function signCredential({
  credential,
  didMethod,
  didSeed,
  didWebUrl
}: SignCredentialOptions): Promise<VerifiableCredential> {
  const {
    signingKey
  } = await getSigningMaterial({
    didMethod,
    didSeed,
    didWebUrl
  });

  const date = getDateString();
  const suite = new Ed25519Signature2020({ key:signingKey, date });
  return sign({
    credential,
    documentLoader,
    suite
  });
}

// retrieves signing material
export async function getSigningMaterial({
  didMethod,
  didSeed,
  didWebUrl
}: GetSigningKeysOptions)
  : Promise<GetSigningKeysResult> {
  let didDocument;
  let keyPairs;
  let methodFor;
  let signingKey;
  let verificationMethod;
  const didSeedBytes = decodeSeed(didSeed);
  if (didMethod === DidMethod.Key) {
    const verificationKeyPair = await Ed25519VerificationKey2020.generate({
      seed: didSeedBytes
    });
    ({ didDocument, keyPairs, methodFor } = await didKeyDriver.fromKeyPair({
      verificationKeyPair
    }));

    const assertionMethod = methodFor({ purpose: 'assertionMethod' })
    signingKey = await Ed25519VerificationKey2020.from({
      type: assertionMethod.type,
      controller: assertionMethod.controller,
      id: assertionMethod.id,
      publicKeyMultibase: assertionMethod.publicKeyMultibase,
      privateKeyMultibase: verificationKeyPair.privateKeyMultibase
    })
    verificationMethod = extractId(didDocument.assertionMethod[0]);
  } else if (didMethod === DidMethod.Web) {
    ({ didDocument, keyPairs } = await didWebDriver.generate({
      seed: didSeedBytes,
      url: didWebUrl
    }));
    verificationMethod = extractId(didDocument.assertionMethod[0]);
    signingKey = keyPairs.get(verificationMethod);
  } else {
    throw new BadRequestError({
      message:
        '"didMethod" must be one of the following values: ' +
        `${Object.values(DidMethod).map(m => `"${m}"`).join(', ')}.`
    });
  }

  const issuerDid = didDocument.id;
  

  return {
    didDocument,
    issuerDid,
    keyPairs,
    verificationMethod,
    signingKey
  };
}

// decodes DID seed
function decodeSeed(didSeed: string): Uint8Array {
  let didSeedBytes;
  if (didSeed.startsWith('z')) {
    // This is a multibase-encoded seed
    didSeedBytes = decodeSecretKeySeed({ secretKeySeed: didSeed });
  } else if (didSeed.length >= 32) {
    didSeedBytes = (new TextEncoder()).encode(didSeed).slice(0, 32);
  } else {
    throw new InvalidDidSeedError();
  }
  return didSeedBytes;
}

// extracts ID from object or string
function extractId(objectOrString: any): string {
  if (typeof objectOrString === 'string') {
    return objectOrString;
  }
  return objectOrString.id;
}

// determines if credential ID is valid
export function isValidCredentialId(credentialId: string): boolean {
  const isValidFormat = URL.canParse(credentialId) || uuid.validate(credentialId);
  const isValidLength = credentialId.length <= MAX_CREDENTIAL_ID_LENGTH;
  return isValidFormat && isValidLength;
}

// retrieves current timestamp
export function getDateString(): string {
  return (new Date()).toISOString();
}
