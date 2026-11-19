import { exampleStorage } from './example-storage.js'

const controllerStorage = await exampleStorage()
const witnessStorage = await exampleStorage()

import { Agent, DidDocument, Kms } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { type WebVhDidCreateOptions, type WebVhDidLog, type WebVhDidUpdateOptions, WebVhModule } from '@credo-ts/webvh'

const controller = new Agent({
  dependencies: agentDependencies,
  modules: { webvh: new WebVhModule(), ...controllerStorage },
})
await controller.initialize()

const witness = new Agent({
  dependencies: agentDependencies,
  modules: { webvh: new WebVhModule(), ...witnessStorage },
})
await witness.initialize()

// start-section-1
// On the witness agent: the witness shares this did:key with the controller
const witnessKey = await witness.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
const witnessDid = `did:key:${Kms.PublicJwk.fromPublicJwk(witnessKey.publicJwk).fingerprint}`
// end-section-1

const updateKey = await controller.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
const updateMultikey = Kms.PublicJwk.fromPublicJwk(updateKey.publicJwk).fingerprint

// start-section-2
// On the controller agent
const { didState } = await controller.dids.create<WebVhDidCreateOptions>({
  method: 'webvh',
  didDocument: DidDocument.fromJSON({ '@context': ['https://www.w3.org/ns/did/v1'], id: '{DID}' }),
  options: {
    address: 'issuer.example.com',
    updateKeys: [updateMultikey],
    updateKeyKmsKeyIds: { [updateMultikey]: { keyId: updateKey.keyId, kmsBackend: updateKey.backend } },
    keys: [],
    // Every new log entry needs an approval from one of these witnesses
    witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
  },
})
if (didState.state !== 'finished') throw new Error('Creating the did failed')
const did = didState.did

// Send the log and the current proofs to each witness, for example over DIDComm or HTTPS
const { log, witnessProofs } = await controller.modules.webvh.getPublicationData(did)
// end-section-2

// start-section-3
// On the witness agent. Keep the log this witness approved last; it's empty before the first entry of a DID.
let trustedLog: WebVhDidLog = []

const proofEntry = await witness.modules.webvh.signWitnessProof({
  trustedLog,
  candidateLog: log,
  witnessProofs,
  kmsKeyId: witnessKey.keyId,
  kmsBackend: witnessKey.backend,
})
trustedLog = log
// Return proofEntry to the controller
// end-section-3

// start-section-4
// On the controller agent, once enough witnesses have replied
const collectedProofs = [...witnessProofs, proofEntry]

const verification = await controller.modules.webvh.verifyWitnessProofs({ log, witnessProofs: collectedProofs })
if (!verification.verified) throw new Error('The new log entry is missing witness approvals')

// Replaces the stored proofs. Publish did.jsonl and did-witness.json after this.
await controller.modules.webvh.storeWitnessProofs(did, collectedProofs)
// end-section-4

// The next update goes through the same steps, with the log the witness approved as its trusted log
const updateResult = await controller.dids.update<WebVhDidUpdateOptions>({
  did,
  didDocument: await controller.dids.resolveDidDocument(did),
})
if (updateResult.didState.state !== 'finished') throw new Error('Updating the did failed')

const next = await controller.modules.webvh.getPublicationData(did)
const nextProofEntry = await witness.modules.webvh.signWitnessProof({
  trustedLog,
  candidateLog: next.log,
  witnessProofs: next.witnessProofs,
  kmsKeyId: witnessKey.keyId,
  kmsBackend: witnessKey.backend,
})
await controller.modules.webvh.storeWitnessProofs(did, [...next.witnessProofs, nextProofEntry])

const nextVerification = await controller.modules.webvh.verifyWitnessProofs({
  log: next.log,
  witnessProofs: [...next.witnessProofs, nextProofEntry],
})
console.log(did, nextVerification.verified)

await controller.shutdown()
await witness.shutdown()
