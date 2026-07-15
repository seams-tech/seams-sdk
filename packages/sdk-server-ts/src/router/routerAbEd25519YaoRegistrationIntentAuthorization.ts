import {
  deriveRouterAbEd25519YaoStableContextBindingV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  computeAddSignerNearEd25519SigningKeyId,
  findRegistrationSignerPlanNearEd25519Branch,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  type AddSignerIntentGrant,
  type AddSignerIntentV1,
  type RegistrationIntentGrant,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import type {
  RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  RouterAbEd25519YaoRegistrationAuthorizationInput,
  RouterAbEd25519YaoRegistrationAuthorizationResult,
} from './routerAbEd25519YaoRegistration';

const SHA256_BYTES = 32;
const STRICT_BEARER_VALUE = /^Bearer ([A-Za-z0-9._~-]{1,1024})$/;
const UTF8 = new TextEncoder();

type RouterAbEd25519YaoRegistrationBindingV1 =
  RouterAbEd25519YaoActivationBindingV1<'registration'>;

type AvailableIntentAuthority = {
  readonly kind: 'available';
  readonly purpose: RouterAbEd25519YaoActivationIntentPurposeV1;
  readonly credentialDigestSha256: Uint8Array;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly admissionFingerprint: string;
  readonly expiresAtMs: number;
};

type AdmittedIntentAuthority = {
  readonly kind: 'admitted';
  readonly purpose: RouterAbEd25519YaoActivationIntentPurposeV1;
  readonly credentialDigestSha256: Uint8Array;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly admissionFingerprint: string;
  readonly expiresAtMs: number;
};

type IntentAuthority = AvailableIntentAuthority | AdmittedIntentAuthority;

type RouterAbEd25519YaoActivationIntentPurposeV1 = 'wallet_registration' | 'wallet_add_signer';

export type RouterAbEd25519YaoVerifiedRegistrationIntentV1 = {
  readonly kind: 'verified_registration_intent';
  readonly registrationIntentGrant: RegistrationIntentGrant;
  readonly intent: RegistrationIntentV1;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly expiresAtMs: number;
};

export type RouterAbEd25519YaoVerifiedAddSignerIntentV1 = {
  readonly kind: 'verified_add_signer_intent';
  readonly addSignerIntentGrant: AddSignerIntentGrant;
  readonly intent: AddSignerIntentV1 & {
    readonly signerSelection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>;
  };
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly expiresAtMs: number;
};

export type RouterAbEd25519YaoVerifiedActivationIntentV1 =
  | RouterAbEd25519YaoVerifiedRegistrationIntentV1
  | RouterAbEd25519YaoVerifiedAddSignerIntentV1;

export type RouterAbEd25519YaoRegistrationIntentBindingResult =
  | {
      readonly ok: true;
      readonly code?: never;
      readonly message?: never;
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_registration_intent' | 'registration_intent_conflict';
      readonly message: string;
    };

type BearerExtractionResult =
  | { readonly ok: true; readonly credential: string }
  | { readonly ok: false; readonly result: RouterAbEd25519YaoRegistrationAuthorizationResult };

function authorizationFailure(input: {
  status: 401 | 403 | 409;
  code: string;
  message: string;
}): RouterAbEd25519YaoRegistrationAuthorizationResult {
  return {
    ok: false,
    status: input.status,
    code: input.code,
    message: input.message,
  };
}

function extractStrictBearerCredential(request: Request): BearerExtractionResult {
  const authorization = request.headers.get('authorization');
  if (authorization === null) {
    return {
      ok: false,
      result: authorizationFailure({
        status: 401,
        code: 'registration_intent_credential_missing',
        message: 'Ed25519 Yao registration requires a Bearer registration-intent credential',
      }),
    };
  }
  const match = STRICT_BEARER_VALUE.exec(authorization);
  const credential = match?.[1];
  if (credential === undefined) {
    return {
      ok: false,
      result: authorizationFailure({
        status: 401,
        code: 'registration_intent_credential_malformed',
        message: 'Ed25519 Yao registration requires one canonical Bearer credential',
      }),
    };
  }
  return { ok: true, credential };
}

async function credentialDigestSha256(credential: string): Promise<Uint8Array> {
  const encoded = UTF8.encode(credential);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoded));
  } finally {
    encoded.fill(0);
  }
}

function credentialDigestsEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  for (let index = 0; index < SHA256_BYTES; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function canonicalAdmissionRequest(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
): string {
  return JSON.stringify({
    scope: {
      lifecycle_id: request.scope.lifecycle_id,
      root_share_epoch: request.scope.root_share_epoch,
      account_id: request.scope.account_id,
      wallet_session_id: request.scope.wallet_session_id,
      signer_set_id: request.scope.signer_set_id,
      signing_worker_id: request.scope.signing_worker_id,
    },
    application_binding: {
      wallet_id: request.application_binding.wallet_id,
      near_ed25519_signing_key_id: request.application_binding.near_ed25519_signing_key_id,
      signing_root_id: request.application_binding.signing_root_id,
      key_creation_signer_slot: request.application_binding.key_creation_signer_slot,
    },
    participant_ids: [request.participant_ids[0], request.participant_ids[1]],
  });
}

function copyAdmissionRequest(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  return {
    scope: {
      lifecycle_id: request.scope.lifecycle_id,
      root_share_epoch: request.scope.root_share_epoch,
      account_id: request.scope.account_id,
      wallet_session_id: request.scope.wallet_session_id,
      signer_set_id: request.scope.signer_set_id,
      signing_worker_id: request.scope.signing_worker_id,
    },
    application_binding: {
      wallet_id: request.application_binding.wallet_id,
      near_ed25519_signing_key_id: request.application_binding.near_ed25519_signing_key_id,
      signing_root_id: request.application_binding.signing_root_id,
      key_creation_signer_slot: request.application_binding.key_creation_signer_slot,
    },
    participant_ids: [request.participant_ids[0], request.participant_ids[1]],
  };
}

function registrationIntentMatchesAdmission(
  input: RouterAbEd25519YaoVerifiedRegistrationIntentV1,
): boolean {
  if (String(input.intent.walletId) !== input.admissionRequest.application_binding.wallet_id) {
    return false;
  }
  const plan = registrationSignerPlanFromSelection(input.intent.signerSelection);
  if (!plan.ok) return false;
  const nearEd25519 = findRegistrationSignerPlanNearEd25519Branch(plan.value);
  if (!nearEd25519 || nearEd25519.participantIds.length !== 2) return false;
  return (
    nearEd25519.signerSlot ===
      input.admissionRequest.application_binding.key_creation_signer_slot &&
    nearEd25519.participantIds[0] === input.admissionRequest.participant_ids[0] &&
    nearEd25519.participantIds[1] === input.admissionRequest.participant_ids[1]
  );
}

async function addSignerIntentMatchesAdmission(
  input: RouterAbEd25519YaoVerifiedAddSignerIntentV1,
): Promise<boolean> {
  const selection = input.intent.signerSelection.ed25519;
  const admission = input.admissionRequest;
  const runtimePolicyScope = input.intent.runtimePolicyScope;
  if (
    !runtimePolicyScope?.signingRootVersion ||
    selection.participantIds.length !== 2
  ) {
    return false;
  }
  const signingRootId = deriveSigningRootId(runtimePolicyScope);
  const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
    kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
    walletId: input.intent.walletId,
    signingRootId,
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    signerSlot: selection.signerSlot,
    participantIds: selection.participantIds,
    keyPurpose: selection.keyPurpose,
    keyVersion: selection.keyVersion,
    derivationVersion: selection.derivationVersion,
  });
  return (
    String(input.intent.walletId) === admission.application_binding.wallet_id &&
    String(input.intent.walletId) === admission.scope.account_id &&
    admission.scope.lifecycle_id === admission.scope.wallet_session_id &&
    selection.signerSlot === admission.application_binding.key_creation_signer_slot &&
    selection.participantIds[0] === admission.participant_ids[0] &&
    selection.participantIds[1] === admission.participant_ids[1] &&
    String(registrationNearEd25519BranchKey(selection.signerSlot)) ===
      admission.scope.signer_set_id &&
    runtimePolicyScope.signingRootVersion === admission.scope.root_share_epoch &&
    signingRootId === admission.application_binding.signing_root_id &&
    String(nearEd25519SigningKeyId) ===
      admission.application_binding.near_ed25519_signing_key_id
  );
}

async function activationIntentMatchesAdmission(
  input: RouterAbEd25519YaoVerifiedActivationIntentV1,
): Promise<boolean> {
  switch (input.kind) {
    case 'verified_registration_intent':
      return registrationIntentMatchesAdmission(input);
    case 'verified_add_signer_intent':
      return await addSignerIntentMatchesAdmission(input);
  }
}

function activationIntentPurpose(
  input: RouterAbEd25519YaoVerifiedActivationIntentV1,
): RouterAbEd25519YaoActivationIntentPurposeV1 {
  switch (input.kind) {
    case 'verified_registration_intent':
      return 'wallet_registration';
    case 'verified_add_signer_intent':
      return 'wallet_add_signer';
  }
}

function activationIntentCredential(input: RouterAbEd25519YaoVerifiedActivationIntentV1): string {
  switch (input.kind) {
    case 'verified_registration_intent':
      return String(input.registrationIntentGrant);
    case 'verified_add_signer_intent':
      return String(input.addSignerIntentGrant);
  }
}

function lifecycleMatchesAdmission(input: {
  binding: RouterAbEd25519YaoRegistrationBindingV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): boolean {
  const lifecycle = input.binding.lifecycle;
  const scope = input.admissionRequest.scope;
  return (
    lifecycle.lifecycle_id === scope.lifecycle_id &&
    lifecycle.root_share_epoch === scope.root_share_epoch &&
    lifecycle.account_id === scope.account_id &&
    lifecycle.session_id === scope.wallet_session_id &&
    lifecycle.signer_set_id === scope.signer_set_id &&
    lifecycle.selected_server_id === scope.signing_worker_id
  );
}

async function stableContextMatchesAdmission(input: {
  binding: RouterAbEd25519YaoRegistrationBindingV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): Promise<boolean> {
  const expected = Uint8Array.from(
    await deriveRouterAbEd25519YaoStableContextBindingV1(
      input.admissionRequest.application_binding,
      input.admissionRequest.participant_ids,
    ),
  );
  const actual = Uint8Array.from(input.binding.stable_key_context_binding);
  const matches = credentialDigestsEqual(expected, actual);
  expected.fill(0);
  actual.fill(0);
  return matches;
}

function admittedAuthority(authority: AvailableIntentAuthority): AdmittedIntentAuthority {
  return {
    kind: 'admitted',
    purpose: authority.purpose,
    credentialDigestSha256: authority.credentialDigestSha256,
    admissionRequest: authority.admissionRequest,
    admissionFingerprint: authority.admissionFingerprint,
    expiresAtMs: authority.expiresAtMs,
  };
}

function findAuthorityByCredentialDigest(
  authorities: readonly IntentAuthority[],
  credentialDigest: Uint8Array,
): { readonly authority: IntentAuthority; readonly index: number } | null {
  let matched: { readonly authority: IntentAuthority; readonly index: number } | null = null;
  for (let index = 0; index < authorities.length; index += 1) {
    const authority = authorities[index];
    if (authority && credentialDigestsEqual(authority.credentialDigestSha256, credentialDigest)) {
      matched = { authority, index };
    }
  }
  return matched;
}

function findAuthorityByLifecycleId(
  authorities: readonly IntentAuthority[],
  lifecycleId: string,
): { readonly authority: IntentAuthority; readonly index: number } | null {
  for (let index = 0; index < authorities.length; index += 1) {
    const authority = authorities[index];
    if (authority?.admissionRequest.scope.lifecycle_id === lifecycleId) {
      return { authority, index };
    }
  }
  return null;
}

export class InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1 {
  readonly authorities: IntentAuthority[] = [];
}

export class InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter implements RouterAbEd25519YaoRegistrationAuthorizationAdapter {
  private readonly authorities: IntentAuthority[];

  constructor(
    state: InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1 =
      new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1(),
  ) {
    this.authorities = state.authorities;
  }

  async bindVerifiedIntent(
    verified: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult> {
    const credential = activationIntentCredential(verified);
    if (!STRICT_BEARER_VALUE.test(`Bearer ${credential}`)) {
      return {
        ok: false,
        code: 'invalid_registration_intent',
        message: 'registration intent grant is not a canonical Bearer credential',
      };
    }
    if (!Number.isSafeInteger(verified.expiresAtMs) || verified.expiresAtMs <= Date.now()) {
      return {
        ok: false,
        code: 'invalid_registration_intent',
        message: 'registration intent authority is expired',
      };
    }
    if (!(await activationIntentMatchesAdmission(verified))) {
      return {
        ok: false,
        code: 'invalid_registration_intent',
        message: 'registration intent does not match the Ed25519 Yao admission subject',
      };
    }

    const credentialDigest = await credentialDigestSha256(credential);
    const purpose = activationIntentPurpose(verified);
    const copiedAdmissionRequest = copyAdmissionRequest(verified.admissionRequest);
    const admissionFingerprint = canonicalAdmissionRequest(copiedAdmissionRequest);
    const existingCredential = findAuthorityByCredentialDigest(this.authorities, credentialDigest);
    const existingLifecycle = findAuthorityByLifecycleId(
      this.authorities,
      verified.admissionRequest.scope.lifecycle_id,
    );
    if (existingCredential || existingLifecycle) {
      const existing = existingCredential?.authority ?? existingLifecycle?.authority;
      const exactRetry =
        existing !== undefined &&
        existing.purpose === purpose &&
        credentialDigestsEqual(existing.credentialDigestSha256, credentialDigest) &&
        existing.admissionFingerprint === admissionFingerprint &&
        existing.expiresAtMs === verified.expiresAtMs;
      credentialDigest.fill(0);
      return exactRetry
        ? { ok: true }
        : {
            ok: false,
            code: 'registration_intent_conflict',
            message: 'registration intent credential or lifecycle is already bound',
          };
    }

    this.authorities.push({
      kind: 'available',
      purpose,
      credentialDigestSha256: credentialDigest,
      admissionRequest: copiedAdmissionRequest,
      admissionFingerprint,
      expiresAtMs: verified.expiresAtMs,
    });
    return { ok: true };
  }

  async authorize(
    input: RouterAbEd25519YaoRegistrationAuthorizationInput,
  ): Promise<RouterAbEd25519YaoRegistrationAuthorizationResult> {
    const bearer = extractStrictBearerCredential(input.request);
    if (!bearer.ok) return bearer.result;
    const credentialDigest = await credentialDigestSha256(bearer.credential);
    try {
      switch (input.kind) {
        case 'admit':
          return this.authorizeAdmission(input.body, credentialDigest);
        case 'execute':
          return await this.authorizeExecution(input.body.binding, credentialDigest);
      }
    } finally {
      credentialDigest.fill(0);
    }
  }

  private authorizeAdmission(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    credentialDigest: Uint8Array,
  ): RouterAbEd25519YaoRegistrationAuthorizationResult {
    const matched = findAuthorityByCredentialDigest(this.authorities, credentialDigest);
    if (!matched) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_credential_rejected',
        message: 'registration intent credential is unknown',
      });
    }
    if (matched.authority.expiresAtMs <= Date.now()) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_credential_expired',
        message: 'registration intent credential is expired',
      });
    }
    if (matched.authority.admissionFingerprint !== canonicalAdmissionRequest(request)) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_subject_mismatch',
        message: 'registration intent credential does not authorize this admission subject',
      });
    }
    if (matched.authority.kind === 'available') {
      this.authorities[matched.index] = admittedAuthority(matched.authority);
    }
    return { ok: true };
  }

  private async authorizeExecution(
    binding: RouterAbEd25519YaoRegistrationBindingV1,
    credentialDigest: Uint8Array,
  ): Promise<RouterAbEd25519YaoRegistrationAuthorizationResult> {
    const matched = findAuthorityByLifecycleId(this.authorities, binding.lifecycle.lifecycle_id);
    if (!matched || matched.authority.kind !== 'admitted') {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_admission_required',
        message: 'registration execution requires its authorized admission',
      });
    }
    if (!credentialDigestsEqual(matched.authority.credentialDigestSha256, credentialDigest)) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_subject_mismatch',
        message: 'registration execution credential does not match its admission subject',
      });
    }
    if (matched.authority.expiresAtMs <= Date.now()) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_credential_expired',
        message: 'registration intent credential is expired',
      });
    }
    if (
      !lifecycleMatchesAdmission({ binding, admissionRequest: matched.authority.admissionRequest })
    ) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_subject_mismatch',
        message: 'registration execution lifecycle does not match its admitted subject',
      });
    }
    if (
      !(await stableContextMatchesAdmission({
        binding,
        admissionRequest: matched.authority.admissionRequest,
      }))
    ) {
      return authorizationFailure({
        status: 403,
        code: 'registration_intent_binding_mismatch',
        message: 'registration execution context does not match its admitted application',
      });
    }
    return { ok: true };
  }
}
