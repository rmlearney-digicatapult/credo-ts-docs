import { exampleStorage } from './example-storage.js'

const storage = await exampleStorage()

// start-section-1
import { Agent, DidDocument, DidDocumentService, Kms } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { type WebVhDidCreateOptions, type WebVhDidUpdateOptions, WebVhModule } from '@credo-ts/webvh'
import express from 'express'

const webVhModules = {
  webvh: new WebVhModule(),
}
// end-section-1

const agent = new Agent({
  dependencies: agentDependencies,
  modules: {
    ...webVhModules,
    ...storage,
  },
})
await agent.initialize()

// start-section-2
// The update key signs the DID log. The assertion key signs credentials and AnonCreds objects.
const updateKey = await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
const assertionKey = await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
const updateMultikey = Kms.PublicJwk.fromPublicJwk(updateKey.publicJwk).fingerprint
const assertionMultikey = Kms.PublicJwk.fromPublicJwk(assertionKey.publicJwk).fingerprint

const { didState } = await agent.dids.create<WebVhDidCreateOptions>({
  method: 'webvh',
  // Credo replaces {DID} with the new DID
  didDocument: DidDocument.fromJSON({
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: '{DID}',
    verificationMethod: [
      { id: '{DID}#assertion-key', type: 'Multikey', controller: '{DID}', publicKeyMultibase: assertionMultikey },
    ],
    authentication: ['{DID}#assertion-key'],
    assertionMethod: ['{DID}#assertion-key'],
  }),
  options: {
    address: 'issuer.example.com',
    updateKeys: [updateMultikey],
    updateKeyKmsKeyIds: { [updateMultikey]: { keyId: updateKey.keyId, kmsBackend: updateKey.backend } },
    keys: [
      { didDocumentRelativeKeyId: '#assertion-key', kmsKeyId: assertionKey.keyId, kmsBackend: assertionKey.backend },
    ],
    alsoKnownAsWeb: true,
  },
})

if (didState.state !== 'finished') {
  throw new Error(`Creating the did failed: ${didState.state === 'failed' ? didState.reason : didState.state}`)
}
const did = didState.did
// end-section-2

// start-section-3
const app = express()

app.get('/.well-known/did.jsonl', async (_request, response) => {
  const { log } = await agent.modules.webvh.getPublicationData(did)
  // One log entry per line
  response.type('text/jsonl').send(log.map((entry) => JSON.stringify(entry)).join('\n'))
})

app.get('/.well-known/did-witness.json', async (_request, response) => {
  const { witnessProofs } = await agent.modules.webvh.getPublicationData(did)
  response.json(witnessProofs)
})

app.get('/.well-known/did.json', async (_request, response) => {
  const { webDoc } = await agent.modules.webvh.getPublicationData(did)
  if (!webDoc) {
    response.sendStatus(404)
    return
  }
  response.json(webDoc)
})
// end-section-3

const server = app.listen(4085)

// start-section-4
// Your own DID resolves from its DidRecord, whether it's published or not
const local = await agent.dids.resolve(did)

// Fetch and verify the published log instead
const published = await agent.dids.resolve(did, {
  useCache: false,
  persistInCache: false,
  useLocalCreatedDidRecord: false,
})

// A query always resolves the published log
const firstVersion = await agent.dids.resolve(`${did}?versionNumber=1`)
// end-section-4

console.log(local.didDocument?.id, published.didResolutionMetadata.error, firstVersion.didResolutionMetadata.error)

// start-section-5
const didDocument = await agent.dids.resolveDidDocument(did)
didDocument.service = [
  new DidDocumentService({
    id: `${did}#website`,
    type: 'LinkedDomains',
    serviceEndpoint: 'https://issuer.example.com',
  }),
]

const updateResult = await agent.dids.update<WebVhDidUpdateOptions>({ did, didDocument })
if (updateResult.didState.state !== 'finished') throw new Error('Updating the did failed')
// end-section-5

// start-section-6
const nextUpdateKey = await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
const nextUpdateMultikey = Kms.PublicJwk.fromPublicJwk(nextUpdateKey.publicJwk).fingerprint

const rotateResult = await agent.dids.update<WebVhDidUpdateOptions>({
  did,
  didDocument: await agent.dids.resolveDidDocument(did),
  options: {
    updateKeys: [nextUpdateMultikey],
    updateKeyKmsKeyIds: { [nextUpdateMultikey]: { keyId: nextUpdateKey.keyId, kmsBackend: nextUpdateKey.backend } },
  },
})
if (rotateResult.didState.state !== 'finished') throw new Error('Rotating the update key failed')
// end-section-6

// start-section-7
const deactivateResult = await agent.dids.deactivate({ did })
if (deactivateResult.didState.state !== 'finished') throw new Error('Deactivating the did failed')
// end-section-7

const publishedLog = await fetch('http://localhost:4085/.well-known/did.jsonl').then((response) => response.text())
const publishedWebDoc = await fetch('http://localhost:4085/.well-known/did.json')
console.log(did, publishedLog.split('\n').length, publishedWebDoc.status)

server.close()
await agent.shutdown()
