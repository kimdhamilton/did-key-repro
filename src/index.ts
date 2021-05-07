#!/usr/bin/env node

import crypto from 'crypto';

const didKeyDriver = require('@digitalbazaar/did-method-key').driver();


const didContext = require('did-context');
const ed25519 = require('ed25519-signature-2020-context');
const DccContextV1Url = "https://w3id.org/dcc/v1";
const x25519Ctx = require('x25519-key-agreement-2020-context');

import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';

const vc = require('@digitalbazaar/vc');
import { generateSecureRandom } from 'react-native-securerandom';
import { contexts as ldContexts, documentLoaderFactory } from '@transmute/jsonld-document-loader';




export function getCustomLoader(): any {
  const customLoaderProto = documentLoaderFactory.pluginFactory
    .build({
      contexts: {
        ...ldContexts.W3C_Verifiable_Credentials,
        ...ldContexts.W3ID_Security_Vocabulary,
        ...ldContexts.W3C_Decentralized_Identifiers
      },
    })
    .addContext({ [ed25519.constants.CONTEXT_URL]: ed25519.contexts.get(ed25519.constants.CONTEXT_URL) })
    .addContext({ [didContext.constants.DID_CONTEXT_URL]: didContext.contexts.get(didContext.constants.DID_CONTEXT_URL) })
    .addContext({ [x25519Ctx.constants.CONTEXT_URL]: x25519Ctx.contexts.get(x25519Ctx.constants.CONTEXT_URL) });
  return customLoaderProto.buildDocumentLoader();

}
async function generateKey(): Promise<any> {
 // const BYTES_LENGTH = 32;
 // const randomBytes = await generateSecureRandom(BYTES_LENGTH);
  //const {
  //  didDocument, keyPairs
  //} = await didKeyDriver.generate(randomBytes);

  const {
    didDocument, keyPairs
  } = await didKeyDriver.generate();

  const pkey = keyPairs.entries().next().value[1];
  console.log(JSON.stringify(pkey));

  return pkey;
}

function createPresentation(holder: string): any {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "type": [
      "VerifiablePresentation"
    ],
    "id": "123",
    "holder": holder
  };
}


export async function generateAndProveDid(challenge: string): Promise<any> {

  const signingKey = await generateKey();
  const signatureSuite = new Ed25519Signature2020({
    key: signingKey,
    date: '2020-03-10T04:24:12.164Z' // TODO: now
  });
  const customLoader = getCustomLoader();

  const presentation = createPresentation(signingKey.controller);
  let result = await vc.signPresentation({
    presentation: presentation,
    documentLoader: customLoader,
    suite: signatureSuite,
    challenge: challenge
  });
  return result;

}

(async () => {
  var text = await generateAndProveDid('3443wrerwrew');
  console.log(text);
})().catch(e => {
  console.error(e);
  // Deal with the fact the chain failed
});