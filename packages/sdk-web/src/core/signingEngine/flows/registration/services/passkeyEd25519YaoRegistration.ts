import type {
  PasskeyRegistrationAuthMethodInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationNearEd25519SignerRequest,
  WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  registerProductEd25519YaoV1,
  type ProductEd25519YaoRegistrationResultV1,
} from './ed25519YaoRegistration';
import {
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoHttpTransportConfigV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';

export type PasskeyRegistrationIntentV1 = Omit<RegistrationIntentV1, 'authMethod'> & {
  authMethod: PasskeyRegistrationAuthMethodInput;
};

export type VerifiedPasskeyRegistrationIntentV1 = {
  kind: 'verified_passkey_registration_intent_v1';
  intent: PasskeyRegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationCeremonyId: string;
};

export type VerifiedPasskeyRegistrationAuthorityV1 = {
  kind: 'verified_passkey_registration_authority_v1';
  walletId: WalletId;
  registrationIntentDigestB64u: string;
  credentialIdB64u: string;
  ownedPasskeyPrfFirst: Uint8Array;
};

export type PasskeyEd25519YaoHttpTransportV1 = {
  kind: 'passkey_ed25519_yao_http_transport_v1';
  routerOrigin: string;
  fetch: typeof fetch;
};

export type VerifiedPasskeyEd25519YaoRegistrationInputV1 = {
  kind: 'verified_passkey_ed25519_yao_registration_input_v1';
  verifiedIntent: VerifiedPasskeyRegistrationIntentV1;
  verifiedAuthority: VerifiedPasskeyRegistrationAuthorityV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  httpTransport: PasskeyEd25519YaoHttpTransportV1;
};

export type PreparedPasskeyEd25519YaoRegistrationV1 = {
  kind: 'prepared_passkey_ed25519_yao_registration_v1';
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  transportConfig: RouterAbEd25519YaoHttpTransportConfigV1;
};

function requireNonEmptyString(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireMatchingString(left: string, right: string, label: string): void {
  if (left !== right) throw new Error(`${label} does not match the verified registration intent`);
}

function requireNearSigner(
  intent: PasskeyRegistrationIntentV1,
  signerSlot: number,
): RegistrationNearEd25519SignerRequest {
  let matched: RegistrationNearEd25519SignerRequest | null = null;
  for (const signer of intent.signerSelection.signers) {
    if (signer.kind !== 'near_ed25519' || signer.signerSlot !== signerSlot) continue;
    if (matched) {
      throw new Error('Verified registration intent contains duplicate Ed25519 signer slots');
    }
    matched = signer;
  }
  if (!matched) {
    throw new Error('Verified registration intent does not contain the admitted Ed25519 signer');
  }
  return matched;
}

function requireMatchingParticipantIds(
  intended: readonly number[],
  admitted: readonly [number, number],
): void {
  if (intended.length !== 2 || intended[0] !== admitted[0] || intended[1] !== admitted[1]) {
    throw new Error('Yao participant IDs do not match the verified registration intent');
  }
}

function transportConfig(
  input: VerifiedPasskeyEd25519YaoRegistrationInputV1,
): RouterAbEd25519YaoHttpTransportConfigV1 {
  const bearerToken = requireNonEmptyString(
    String(input.verifiedIntent.registrationIntentGrant),
    'registration-intent grant',
  );
  return {
    routerOrigin: requireNonEmptyString(input.httpTransport.routerOrigin, 'Yao Router origin'),
    authorization: `Bearer ${bearerToken}`,
    fetch: input.httpTransport.fetch,
  };
}

export function prepareVerifiedPasskeyEd25519YaoRegistrationV1(
  input: VerifiedPasskeyEd25519YaoRegistrationInputV1,
): PreparedPasskeyEd25519YaoRegistrationV1 {
  requireMatchingString(
    String(input.verifiedIntent.intent.walletId),
    String(input.verifiedAuthority.walletId),
    'Passkey authority wallet ID',
  );
  requireMatchingString(
    input.verifiedIntent.registrationIntentDigestB64u,
    input.verifiedAuthority.registrationIntentDigestB64u,
    'Passkey authority intent digest',
  );
  requireNonEmptyString(input.verifiedAuthority.credentialIdB64u, 'passkey credential ID');
  const parsedAdmission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    input.admissionRequest,
  );
  if (!parsedAdmission.ok) throw new Error(parsedAdmission.message);
  const admissionRequest = parsedAdmission.value;
  requireMatchingString(
    admissionRequest.scope.lifecycle_id,
    requireNonEmptyString(input.verifiedIntent.registrationCeremonyId, 'registration ceremony ID'),
    'Yao lifecycle ID',
  );
  requireMatchingString(
    admissionRequest.application_binding.wallet_id,
    String(input.verifiedIntent.intent.walletId),
    'Yao application wallet ID',
  );
  const intendedSigner = requireNearSigner(
    input.verifiedIntent.intent,
    admissionRequest.application_binding.key_creation_signer_slot,
  );
  requireMatchingParticipantIds(intendedSigner.participantIds, admissionRequest.participant_ids);

  return {
    kind: 'prepared_passkey_ed25519_yao_registration_v1',
    request: admissionRequest,
    transportConfig: transportConfig(input),
  };
}

export async function registerVerifiedPasskeyEd25519YaoV1(
  input: VerifiedPasskeyEd25519YaoRegistrationInputV1,
): Promise<ProductEd25519YaoRegistrationResultV1> {
  try {
    const prepared = prepareVerifiedPasskeyEd25519YaoRegistrationV1(input);
    return await registerProductEd25519YaoV1({
      request: prepared.request,
      factor: {
        kind: 'passkey_prf_first',
        ownedSecret32: input.verifiedAuthority.ownedPasskeyPrfFirst,
      },
      transport: new RouterAbEd25519YaoHttpActivationTransportV1(prepared.transportConfig),
    });
  } catch (error) {
    input.verifiedAuthority.ownedPasskeyPrfFirst.fill(0);
    throw error;
  }
}
