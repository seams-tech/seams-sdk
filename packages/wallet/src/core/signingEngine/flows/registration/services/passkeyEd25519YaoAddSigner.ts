import type {
  AddSignerIntentGrant,
  AddSignerIntentV1,
  AddSignerSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import {
  computeAddSignerNearEd25519SigningKeyId,
  registrationNearEd25519BranchKey,
} from '@shared/utils/registrationIntent';
import {
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  deriveSigningRootId,
  normalizeRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoHttpTransportConfigV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';

type Ed25519AddSignerSelection = Extract<AddSignerSelection, { mode: 'ed25519' }>;

export type VerifiedPasskeyEd25519AddSignerIntentV1 = {
  kind: 'verified_passkey_ed25519_add_signer_intent_v1';
  intent: Omit<AddSignerIntentV1, 'signerSelection'> & {
    signerSelection: Ed25519AddSignerSelection;
  };
  addSignerIntentDigestB64u: string;
  addSignerIntentGrant: AddSignerIntentGrant;
  addSignerCeremonyId: string;
};

export type VerifiedPasskeyEd25519AddSignerAuthorityV1 = {
  kind: 'verified_passkey_ed25519_add_signer_authority_v1';
  walletId: WalletId;
  addSignerIntentDigestB64u: string;
  credentialIdB64u: string;
};

export type VerifiedPasskeyEd25519YaoAddSignerPreparationInputV1 = {
  kind: 'verified_passkey_ed25519_yao_add_signer_input_v1';
  verifiedIntent: VerifiedPasskeyEd25519AddSignerIntentV1;
  verifiedAuthority: VerifiedPasskeyEd25519AddSignerAuthorityV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  httpTransport: {
    kind: 'passkey_ed25519_yao_http_transport_v1';
    routerOrigin: string;
    fetch: typeof fetch;
  };
};

export type PreparedPasskeyEd25519YaoAddSignerV1 = {
  kind: 'prepared_passkey_ed25519_yao_add_signer_v1';
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  transportConfig: RouterAbEd25519YaoHttpTransportConfigV1;
};

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireMatchingString(left: string, right: string, label: string): void {
  if (left !== right) throw new Error(`${label} does not match the verified add-signer intent`);
}

function requireMatchingParticipantIds(
  intended: readonly number[],
  admitted: readonly [number, number],
): void {
  if (intended.length !== 2 || intended[0] !== admitted[0] || intended[1] !== admitted[1]) {
    throw new Error('Yao participant IDs do not match the verified add-signer intent');
  }
}

function transportConfig(
  input: VerifiedPasskeyEd25519YaoAddSignerPreparationInputV1,
): RouterAbEd25519YaoHttpTransportConfigV1 {
  const bearerToken = requireNonEmptyString(
    input.verifiedIntent.addSignerIntentGrant,
    'add-signer intent grant',
  );
  return {
    routerOrigin: requireNonEmptyString(input.httpTransport.routerOrigin, 'Yao Router origin'),
    authorization: { kind: 'bearer', value: `Bearer ${bearerToken}` },
    fetch: input.httpTransport.fetch,
  };
}

export async function prepareVerifiedPasskeyEd25519YaoAddSignerV1(
  input: VerifiedPasskeyEd25519YaoAddSignerPreparationInputV1,
): Promise<PreparedPasskeyEd25519YaoAddSignerV1> {
  const intent = input.verifiedIntent.intent;
  const selection = intent.signerSelection.ed25519;
  requireMatchingString(
    String(intent.walletId),
    String(input.verifiedAuthority.walletId),
    'Passkey authority wallet ID',
  );
  requireMatchingString(
    input.verifiedIntent.addSignerIntentDigestB64u,
    input.verifiedAuthority.addSignerIntentDigestB64u,
    'Passkey authority intent digest',
  );
  requireNonEmptyString(input.verifiedAuthority.credentialIdB64u, 'passkey credential ID');

  const runtimePolicyScope = normalizeRuntimePolicyScope(intent.runtimePolicyScope);
  const signingRootId = deriveSigningRootId(runtimePolicyScope);
  const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    input.admissionRequest,
  );
  if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
  const admission = parsedAdmission.value;
  const ceremonyId = requireNonEmptyString(
    input.verifiedIntent.addSignerCeremonyId,
    'add-signer ceremony ID',
  );

  requireMatchingString(admission.scope.lifecycle_id, ceremonyId, 'Yao lifecycle ID');
  requireMatchingString(
    admission.scope.threshold_session_id,
    ceremonyId,
    'Yao Threshold Session ID',
  );
  requireMatchingString(admission.scope.account_id, String(intent.walletId), 'Yao account ID');
  requireMatchingString(
    admission.scope.signer_set_id,
    String(registrationNearEd25519BranchKey(selection.signerSlot)),
    'Yao signer-set ID',
  );
  requireMatchingString(
    admission.scope.root_share_epoch,
    runtimePolicyScope.signingRootVersion,
    'Yao root-share epoch',
  );
  requireMatchingString(
    admission.application_binding.wallet_id,
    String(intent.walletId),
    'Yao application wallet ID',
  );
  requireMatchingString(
    admission.application_binding.signing_root_id,
    signingRootId,
    'Yao signing-root ID',
  );
  if (admission.application_binding.key_creation_signer_slot !== selection.signerSlot) {
    throw new Error('Yao signer slot does not match the verified add-signer intent');
  }
  requireMatchingParticipantIds(selection.participantIds, admission.participant_ids);
  const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
    kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
    walletId: intent.walletId,
    signingRootId,
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    signerSlot: selection.signerSlot,
    participantIds: selection.participantIds,
    keyPurpose: selection.keyPurpose,
    keyVersion: selection.keyVersion,
    derivationVersion: selection.derivationVersion,
  });
  requireMatchingString(
    admission.application_binding.near_ed25519_signing_key_id,
    String(nearEd25519SigningKeyId),
    'Yao NEAR signing-key ID',
  );

  return {
    kind: 'prepared_passkey_ed25519_yao_add_signer_v1',
    request: admission,
    transportConfig: transportConfig(input),
  };
}

export async function admitVerifiedPasskeyEd25519YaoAddSignerV1(
  input: VerifiedPasskeyEd25519YaoAddSignerPreparationInputV1,
): Promise<{
  readonly request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly receipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
  readonly transportConfig: RouterAbEd25519YaoHttpTransportConfigV1;
}> {
  const prepared = await prepareVerifiedPasskeyEd25519YaoAddSignerV1(input);
  const transport = new RouterAbEd25519YaoHttpActivationTransportV1(prepared.transportConfig);
  const response = await transport.send({
    kind: 'admit',
    path: ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
    body: prepared.request,
  });
  if (!response.ok) throw new Error(response.message);
  const receipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(response.value);
  if (!receipt.ok) throw new Error(receipt.message);
  return {
    request: prepared.request,
    receipt: receipt.value,
    transportConfig: prepared.transportConfig,
  };
}
