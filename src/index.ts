#!/usr/bin/env node
import * as ed25519 from '@transmute/did-key-ed25519';
import * as vc from '@transmute/vc.js';
import crypto from 'crypto';

// @ts-ignore
import { Ed25519Signature2018 } from '@transmute/ed25519-signature-2018';
import { documentLoaderFactory } from '@transmute/jsonld-document-loader';

import DidContext from './did-v1.json';


export const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1';

import W3ID_SEC_V1 from './sec-v1.json';
import W3ID_SEC_V2 from './sec-v2.json';

const W3ID_SEC_URL_V1 = 'https://w3id.org/security/v1';
const W3ID_SEC_URL_V2 = 'https://w3id.org/security/v2';

import W3C_VC_DATA_MODEL_V1 from './vc-v1.json';
import W3C_VC_DATA_MODEL_EXAMPLES_V1 from './vc-example-v1.json';
import JWS_V1 from './jws2020.json';

const W3C_VC_DATA_MODEL_URL_V1 = 'https://www.w3.org/2018/credentials/v1';
const W3C_VC_DATA_MODEL_EXAMPLES_URL_V1 =
  'https://www.w3.org/2018/credentials/examples/v1';
const JWS_URL_V1 = 'https://w3id.org/security/jws/v1';

async function generateDidKeyPair(): Promise<ed25519.Ed25519KeyPair> {

  return ed25519.Ed25519KeyPair.generate({
    secureRandom: () => {
      return crypto.randomBytes(32);
    },
  });

}

function createPresentation(holder: string) : any {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/jws/v1"
    ],
    "type": [
      "VerifiablePresentation"
    ],
    "holder": holder
  };
}

export async function generateDid(): Promise<string> {
  const keyPair = await generateDidKeyPair();
  return keyPair.controller;
}

function generateDidKeySuite(keyPair: ed25519.Ed25519KeyPair): any {
  const suite = new Ed25519Signature2018({
   // verificationMethod: keyPair.id,
    key: keyPair,
  });
  return suite;
}

export async function generateAndProveDid(challenge: string): Promise<any> {
  console.log('start');
  const keyPair = await generateDidKeyPair();
  console.log('keyPair', keyPair);
  const suite = generateDidKeySuite(keyPair);
  console.log('suite', suite);

  const documentLoader = documentLoaderFactory.pluginFactory
    .build()
    .addContext({ [DID_CONTEXT_URL]: DidContext })
    .addContext({ [W3ID_SEC_URL_V1]: W3ID_SEC_V1 })
    .addContext({ [W3ID_SEC_URL_V2]: W3ID_SEC_V2 })
    .addContext({ [JWS_URL_V1]: JWS_V1 })
    .addContext({ [W3C_VC_DATA_MODEL_URL_V1]: W3C_VC_DATA_MODEL_V1 })
    .addContext({
      [W3C_VC_DATA_MODEL_EXAMPLES_URL_V1]: W3C_VC_DATA_MODEL_EXAMPLES_V1,
    })
    .buildDocumentLoader();
  console.log('documentLoader', documentLoader);

  console.log('controller: ' + keyPair.controller);

  const presentation = createPresentation(keyPair.controller);
  console.log('presentation', JSON.stringify(presentation, null, 2));
  //presentation['@context'].push('https://w3id.org/did/v1');
  const signedPresentation = await vc.ld.signPresentation({
    presentation: presentation,
    documentLoader: documentLoader,
    suite,
    challenge: challenge,
  });
  console.log('signedPres', signedPresentation);
  return signedPresentation;
}


(async () => {
  var text = await generateAndProveDid('3443wrerwrew');
  console.log(text);
})().catch(e => {
  console.error(e);
  // Deal with the fact the chain failed
});