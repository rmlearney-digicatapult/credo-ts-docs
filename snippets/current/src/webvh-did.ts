import { mkdtemp, readdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { exampleStorage } from './example-storage.js'

const storage = await exampleStorage()

// start-section-1
import { Agent, DidDocumentBuilder, DidDocumentService, getMultikey, Kms } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { type WebVhDidCreateOptions, type WebVhDidUpdateOptions, WebVhModule } from '@credo-ts/webvh'

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
const updateKey = Kms.PublicJwk.fromKmsKey(await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } }))
const assertionKey = Kms.PublicJwk.fromKmsKey(await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } }))

// Credo replaces {DID} with the new DID
const didDocument = new DidDocumentBuilder('{DID}')
  .addContext('https://w3id.org/security/multikey/v1')
  .addVerificationMethod(
    getMultikey({ did: '{DID}', publicJwk: assertionKey, verificationMethodId: '{DID}#assertion-key' })
  )
  .addAuthentication('{DID}#assertion-key')
  .addAssertionMethod('{DID}#assertion-key')
  .build()

const { didState } = await agent.dids.create<WebVhDidCreateOptions>({
  method: 'webvh',
  didDocument,
  options: {
    address: 'issuer.example.com',
    updateKeys: [updateKey.fingerprint],
    updateKeyKmsKeyIds: { [updateKey.fingerprint]: { keyId: updateKey.keyId, kmsBackend: updateKey.kmsBackend } },
    keys: [
      { didDocumentRelativeKeyId: '#assertion-key', kmsKeyId: assertionKey.keyId, kmsBackend: assertionKey.kmsBackend },
    ],
    alsoKnownAsWeb: true,
  },
})

if (didState.state !== 'finished') {
  throw new Error(`Creating the did failed: ${didState.state === 'failed' ? didState.reason : didState.state}`)
}
const did = didState.did
// end-section-2

const wellKnownDirectory = await mkdtemp(`${tmpdir()}/webvh-`)

// start-section-3
import { mkdir, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'

// Copies the files to the directory that your web server serves as https://issuer.example.com/.well-known/
async function publishDid(did: string, directory: string) {
  const { log, witnessProofs, webDoc } = await agent.modules.webvh.getPublicationData(did)
  await mkdir(directory, { recursive: true })
  // The approvals before the log, so resolvers don't find a log entry without its approvals
  await writeFile(path.join(directory, 'did-witness.json'), JSON.stringify(witnessProofs))
  // One log entry per line
  await writeFile(path.join(directory, 'did.jsonl'), log.map((entry) => JSON.stringify(entry)).join('\n'))
  if (webDoc) await writeFile(path.join(directory, 'did.json'), JSON.stringify(webDoc))
  else await rm(path.join(directory, 'did.json'), { force: true })
}

await publishDid(did, wellKnownDirectory)
// end-section-3

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
const updatedDidDocument = await agent.dids.resolveDidDocument(did)
updatedDidDocument.service = [
  new DidDocumentService({
    id: `${did}#website`,
    type: 'LinkedDomains',
    serviceEndpoint: 'https://issuer.example.com',
  }),
]

const updateResult = await agent.dids.update<WebVhDidUpdateOptions>({ did, didDocument: updatedDidDocument })
if (updateResult.didState.state !== 'finished') throw new Error('Updating the did failed')
// end-section-5

// start-section-6
const nextUpdateKey = Kms.PublicJwk.fromKmsKey(await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } }))

const rotateResult = await agent.dids.update<WebVhDidUpdateOptions>({
  did,
  didDocument: await agent.dids.resolveDidDocument(did),
  options: {
    updateKeys: [nextUpdateKey.fingerprint],
    updateKeyKmsKeyIds: {
      [nextUpdateKey.fingerprint]: { keyId: nextUpdateKey.keyId, kmsBackend: nextUpdateKey.kmsBackend },
    },
  },
})
if (rotateResult.didState.state !== 'finished') throw new Error('Rotating the update key failed')
// end-section-6

// start-section-7
const deactivateResult = await agent.dids.deactivate({ did })
if (deactivateResult.didState.state !== 'finished') throw new Error('Deactivating the did failed')
// end-section-7

// Publish again after every change. After deactivation, there's no did.json.
await publishDid(did, wellKnownDirectory)
console.log(did, await readdir(wellKnownDirectory))

await agent.shutdown()
