import type {
  RouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  RouterAbEcdsaDerivationActivationRefreshResponseV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from './routerAbEcdsaDerivation';
import type { CorrelationId } from './canonicalPrimitives';
import type { EcdsaServerGeneration } from './ecdsaCapabilityActivation';

const signerAEnvelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'> = {
  recipient_role: 'signer_a',
  header_digest: { bytes: new Array<number>(32).fill(1) },
  aad_digest: { bytes: new Array<number>(32).fill(2) },
  ciphertext: { bytes: [3] },
};

const wrongSignerAEnvelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'> = {
  // @ts-expect-error Signer A envelopes cannot target Signer B.
  recipient_role: 'signer_b',
  header_digest: { bytes: new Array<number>(32).fill(1) },
  aad_digest: { bytes: new Array<number>(32).fill(2) },
  ciphertext: { bytes: [3] },
};

declare const refreshRequest: RouterAbEcdsaDerivationActivationRefreshRequestV1;
declare const activationCorrelationId: CorrelationId;
declare const expectedServerGeneration: EcdsaServerGeneration;
declare const activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;

const exactRefreshRequest: RouterAbEcdsaDerivationActivationRefreshRequestV1 = refreshRequest;

// @ts-expect-error Refresh requests require both role-specific opaque envelopes.
const missingDeriverBEnvelope: RouterAbEcdsaDerivationActivationRefreshRequestV1 = {
  context: exactRefreshRequest.context,
  lifecycle: exactRefreshRequest.lifecycle,
  public_identity: exactRefreshRequest.public_identity,
  signer_set: exactRefreshRequest.signer_set,
  router_id: exactRefreshRequest.router_id,
  client_id: exactRefreshRequest.client_id,
  signing_worker_ephemeral_public_key: exactRefreshRequest.signing_worker_ephemeral_public_key,
  refresh_authorization_digest_b64u: exactRefreshRequest.refresh_authorization_digest_b64u,
  refresh_nonce: exactRefreshRequest.refresh_nonce,
  previous_activation_epoch: exactRefreshRequest.previous_activation_epoch,
  next_activation_epoch: exactRefreshRequest.next_activation_epoch,
  expires_at_ms: exactRefreshRequest.expires_at_ms,
  deriver_a_refresh_envelope: signerAEnvelope,
};

void wrongSignerAEnvelope;
void missingDeriverBEnvelope;

const exactCommitRequest = {
  activation_correlation_id: activationCorrelationId,
  expected_server_generation: expectedServerGeneration,
  refresh_request: refreshRequest,
} satisfies RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
void exactCommitRequest;

const missingExpectedGeneration = {
  activation_correlation_id: activationCorrelationId,
  refresh_request: refreshRequest,
  // @ts-expect-error Refresh commits require the current exact server generation.
} satisfies RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
void missingExpectedGeneration;

const committedResponse = {
  result: 'activation_committed',
  signing_worker_activation: activationReceipt,
} satisfies RouterAbEcdsaDerivationActivationRefreshResponseV1;
void committedResponse;

const invalidCommittedResponse = {
  result: 'activation_committed',
  signing_worker_activation: activationReceipt,
  // @ts-expect-error Committed readback does not contain a forwarded proof response.
  response: {},
} satisfies RouterAbEcdsaDerivationActivationRefreshResponseV1;
void invalidCommittedResponse;
