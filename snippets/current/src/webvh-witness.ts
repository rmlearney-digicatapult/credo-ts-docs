import { exampleStorage } from './example-storage.js'

const controllerStorage = await exampleStorage()
const witnessStorage = await exampleStorage()

import { Agent, DidDocumentBuilder, Kms } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import {
  type WebVhDidCreateOptions,
  type WebVhDidLog,
  type WebVhDidUpdateOptions,
  WebVhModule,
  type WebVhWitnessSigningOptions,
} from '@credo-ts/webvh'

// Stand in for the application's own web server, which serves https://issuer.example.com/.well-known/
const webServerFiles = new Map<string, string>()
async function uploadToWebServer(fileName: string, content: string) {
  webServerFiles.set(fileName, content)
}
const webServerFetch: typeof fetch = async (input) => {
  const url = input instanceof Request ? input.url : input.toString()
  const content = webServerFiles.get(url.split('/').pop() ?? '')
  return content === undefined ? new Response(null, { status: 404 }) : new Response(content)
}

const controller = new Agent({
  dependencies: agentDependencies,
  modules: { webvh: new WebVhModule(), ...controllerStorage },
})
await controller.initialize()

const witness = new Agent({
  dependencies: { ...agentDependencies, fetch: webServerFetch },
  modules: { webvh: new WebVhModule(), ...witnessStorage },
})
await witness.initialize()

// start-section-1
// On the witness agent: the witness shares this did:key with the controller
const witnessKey = Kms.PublicJwk.fromKmsKey(await witness.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } }))
const witnessDid = `did:key:${witnessKey.fingerprint}`
// end-section-1

const updateKey = Kms.PublicJwk.fromKmsKey(await controller.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } }))

// start-section-2
// On the controller agent
const didDocument = new DidDocumentBuilder('{DID}').build()

const { didState } = await controller.dids.create<WebVhDidCreateOptions>({
  method: 'webvh',
  didDocument,
  options: {
    address: 'issuer.example.com',
    updateKeys: [updateKey.fingerprint],
    updateKeyKmsKeyIds: { [updateKey.fingerprint]: { keyId: updateKey.keyId, kmsBackend: updateKey.kmsBackend } },
    keys: [],
    // Every new log entry needs an approval from one of these witnesses
    witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
  },
})
if (didState.state !== 'finished') throw new Error('Creating the did failed')
const did = didState.did
// end-section-2

// start-section-3
// On the controller agent
const { log } = await controller.modules.webvh.getPublicationData(did)
const requirement = await controller.modules.webvh.getWitnessRequirement(did)
// Send log to requirement.witnesses, for example over DIDComm or HTTPS. requirement.threshold of them must approve.
// Without a requirement, the new entry needs no approvals: publish it straight away.
// end-section-3

// start-section-4
// On the witness agent. Your own copies of the published log and approvals of the DID, empty before its first entry.
let publishedLog: WebVhDidLog = []
let publishedWitnessProofs: WebVhWitnessSigningOptions['witnessProofs'] = []

const approval = await witness.modules.webvh.signWitnessProof({
  trustedLog: publishedLog,
  candidateLog: log,
  witnessProofs: publishedWitnessProofs,
  kmsKeyId: witnessKey.keyId,
  kmsBackend: witnessKey.kmsBackend,
})
// Return approval to the controller
// end-section-4

// start-section-5
// On the controller agent, as approvals arrive: add them to the approvals of the earlier entries
const { witnessProofs } = await controller.modules.webvh.getPublicationData(did)
const approvals = [...witnessProofs, approval]

const verification = await controller.modules.webvh.verifyWitnessProofs({ log, witnessProofs: approvals })
// verified stays false until enough witnesses approve: wait for more approvals
if (verification.verified) {
  await controller.modules.webvh.storeWitnessProofs(did, approvals)
}
// end-section-5

// start-section-6
// On the controller, once the approvals are stored. Your application uploads the files: the approvals first, then the log.
const approved = await controller.modules.webvh.getPublicationData(did)
await uploadToWebServer('did-witness.json', JSON.stringify(approved.witnessProofs))
await uploadToWebServer('did.jsonl', approved.log.map((entry) => JSON.stringify(entry)).join('\n'))
// end-section-6

// start-section-7
// On the witness agent, once the controller has published: resolving fetches and verifies the published files
const published = await witness.dids.resolve(did, { useCache: false, persistInCache: false })
// Each versionId covers the entries before it, so at the version you approved, the published log is the log you approved
if (published.didDocumentMetadata.versionId === approval.versionId) {
  publishedLog = log
  publishedWitnessProofs = await witness.modules.webvh.fetchWitnessProofs(did)
}
// end-section-7

// Every later change goes through the same steps
const updateResult = await controller.dids.update<WebVhDidUpdateOptions>({
  did,
  didDocument: await controller.dids.resolveDidDocument(did),
})
if (updateResult.didState.state !== 'finished') throw new Error('Updating the did failed')

const next = await controller.modules.webvh.getPublicationData(did)
const nextApproval = await witness.modules.webvh.signWitnessProof({
  trustedLog: publishedLog,
  candidateLog: next.log,
  witnessProofs: publishedWitnessProofs,
  kmsKeyId: witnessKey.keyId,
  kmsBackend: witnessKey.kmsBackend,
})
const nextVerification = await controller.modules.webvh.verifyWitnessProofs({
  log: next.log,
  witnessProofs: [...next.witnessProofs, nextApproval],
})
console.log(did, requirement?.threshold, nextVerification.verified)

await controller.shutdown()
await witness.shutdown()
