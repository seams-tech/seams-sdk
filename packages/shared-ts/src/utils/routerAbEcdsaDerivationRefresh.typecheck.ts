import type {
  RouterAbEcdsaDerivationActivationRefreshRequestV1,
  RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1,
} from './routerAbEcdsaDerivation';

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
