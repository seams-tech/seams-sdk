import {
  ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveWalletRecoveryKeyLifecycleId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiWalletRegistrationService,
  RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext,
} from '../../../framework/authServicePort';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import { resolveWalletSessionOperationCredentialAdmission } from '../../../auth/commonRouterUtils';
import { walletSessionFailureMessage } from '../../../auth/walletSessionFailure';
import { NEAR_ED25519_MPC_OPERATION_KINDS } from '@shared/authorization/capabilityKinds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { PreparedEd25519RecoveryAdmissionV1 } from '../../passkeyCustody/walletRecoveryKeyManifest';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationResult,
} from './routerAbEd25519YaoRecovery';
import { resolveWalletSessionAuthorizationV2Admission } from '../../signingOperations/walletExecutionAdmission';

function authorizationFailure(input: {
  readonly status: 401 | 403 | 409 | 429 | 503;
  readonly code: string;
  readonly message: string;
}): RecoveryAuthorizationFailure {
  return { ok: false, status: input.status, code: input.code, message: input.message };
}

type RecoveryAuthorizationFailure = Extract<
  RouterAbEd25519YaoRecoveryAuthorizationResult,
  { readonly ok: false }
>;

export interface PreparedEd25519RecoveryAdmissionReaderV1 {
  readPreparedEd25519RecoveryAdmission(input: {
    readonly challengeId: string;
    readonly nowMs: number;
  }): Promise<PreparedEd25519RecoveryAdmissionV1 | null>;
}

export type RouterAbEd25519YaoRecoveryAuthorizationServicesV1 = {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly preparedRecoveryAdmission: PreparedEd25519RecoveryAdmissionReaderV1;
  readonly resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
};

function sameValue(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

async function entryMatchesAdmission(input: {
  readonly prepared: PreparedEd25519RecoveryAdmissionV1;
  readonly entry: PreparedEd25519RecoveryAdmissionV1['entries'][number];
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
}): Promise<boolean> {
  const expectedLifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId: input.prepared.reservationId,
    keySetId: input.entry.keySetId,
  });
  const basis = input.entry.recoveryBasis;
  return (
    String(input.prepared.walletId) === input.request.scope.account_id &&
    String(input.prepared.walletId) === input.request.application_binding.wallet_id &&
    input.request.scope.lifecycle_id === expectedLifecycleId &&
    input.request.scope.threshold_session_id === `${expectedLifecycleId}:threshold-session` &&
    input.request.scope.root_share_epoch === basis.scope.root_share_epoch &&
    input.request.scope.account_id === basis.scope.account_id &&
    input.request.scope.signer_set_id === basis.scope.signer_set_id &&
    input.request.scope.signing_worker_id === basis.scope.signing_worker_id &&
    sameValue(input.request.active_material_activation, basis.activeMaterialActivation) &&
    sameValue(input.request.application_binding, basis.applicationBinding) &&
    sameValue(input.request.participant_ids, basis.participantIds) &&
    sameValue(input.request.active_capability_binding, basis.activeCapabilityBinding) &&
    sameValue(input.request.registered_public_key, basis.registeredPublicKey)
  );
}

async function authorizePreparedRecovery(input: {
  readonly request: Extract<
    RouterAbEd25519YaoRecoveryAuthorizationInput,
    { readonly kind: 'admit' }
  >;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
  const challengeId = String(
    input.request.request.headers.get(ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1) || '',
  ).trim();
  if (!challengeId) {
    return authorizationFailure({
      status: 401,
      code: 'wallet_recovery_challenge_missing',
      message: 'wallet recovery admission is unavailable',
    });
  }
  let prepared: PreparedEd25519RecoveryAdmissionV1 | null;
  try {
    prepared = await input.services.preparedRecoveryAdmission.readPreparedEd25519RecoveryAdmission({
      challengeId,
      nowMs: Date.now(),
    });
  } catch {
    return authorizationFailure({
      status: 503,
      code: 'wallet_recovery_unavailable',
      message: 'wallet recovery admission is unavailable',
    });
  }
  if (!prepared) {
    return authorizationFailure({
      status: 401,
      code: 'wallet_recovery_challenge_invalid',
      message: 'wallet recovery admission is unavailable',
    });
  }
  const matches = await Promise.all(
    prepared.entries.map((entry) =>
      entryMatchesAdmission({ prepared, entry, request: input.request.body }),
    ),
  );
  if (matches.filter(Boolean).length !== 1) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_recovery_scope_mismatch',
      message: 'wallet recovery admission is unavailable',
    });
  }
  return {
    ok: true,
    authorization: { kind: 'wallet_recovery', walletId: String(prepared.walletId) },
  };
}

type ExactEd25519OperationCredentialAdmission = Extract<
  Extract<
    Awaited<ReturnType<typeof resolveWalletSessionOperationCredentialAdmission>>,
    { readonly kind: 'admitted' }
  >['admission'],
  { readonly curve: 'ed25519' }
>;

type ActiveEd25519MaterialResolution = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>>,
  { readonly ok: true }
>;

type ExactEd25519OperationCredentialAdmissionResolution =
  | {
      readonly kind: 'authorized';
      readonly admission: ExactEd25519OperationCredentialAdmission;
    }
  | {
      readonly kind: 'rejected';
      readonly result: RecoveryAuthorizationFailure;
    };

type ExactEd25519OperationCredentialMaterialResolution =
  | {
      readonly kind: 'authorized';
      readonly admission: ExactEd25519OperationCredentialAdmission;
      readonly activeMaterial: ActiveEd25519MaterialResolution;
      readonly materialActivation: ActiveEd25519MaterialResolution['materialActivation'];
    }
  | {
      readonly kind: 'rejected';
      readonly result: RecoveryAuthorizationFailure;
    };

type ExhaustedEd25519OperationCredentialMaterialResolution =
  | {
      readonly kind: 'authorized';
      readonly candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext;
      readonly admission: Extract<
        ReturnType<typeof resolveWalletSessionAuthorizationV2Admission>,
        { readonly ok: true; readonly keyFamily: 'ed25519' }
      >;
      readonly activeMaterial: ActiveEd25519MaterialResolution;
      readonly materialActivation: ActiveEd25519MaterialResolution['materialActivation'];
    }
  | {
      readonly kind: 'rejected';
      readonly result: RecoveryAuthorizationFailure;
    };

async function resolveExactEd25519OperationCredentialAdmission(input: {
  readonly request: Request;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<ExactEd25519OperationCredentialAdmissionResolution> {
  const token = extractBearerCredential(input.request.headers);
  if (!token) {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 401,
        code: 'wallet_session_missing',
        message: walletSessionFailureMessage('wallet_session_missing'),
      }),
    };
  }
  let resolution: Awaited<ReturnType<typeof resolveWalletSessionOperationCredentialAdmission>>;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.services.authorizationSessions,
      token,
      nowMs: Date.now(),
      operation: {
        keyFamily: 'ed25519',
        operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
      },
    });
  } catch {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 503,
        code: 'wallet_session_unavailable',
        message: walletSessionFailureMessage('wallet_session_unavailable'),
      }),
    };
  }
  if (resolution.kind === 'not_found') {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 401,
        code: 'wallet_session_invalid',
        message: walletSessionFailureMessage('wallet_session_invalid'),
      }),
    };
  }
  if (resolution.kind !== 'admitted' || resolution.admission.curve !== 'ed25519') {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 403,
        code: 'wallet_session_scope_mismatch',
        message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
      }),
    };
  }
  return { kind: 'authorized', admission: resolution.admission };
}

async function resolveExactEd25519OperationCredentialMaterial(input: {
  readonly request: Request;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<ExactEd25519OperationCredentialMaterialResolution> {
  const credential = await resolveExactEd25519OperationCredentialAdmission(input);
  if (credential.kind === 'rejected') return credential;
  const admission = credential.admission;
  const walletId = String(admission.context.authorization.session.walletId);
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    admission.admission.materialActivation,
  );
  let activeMaterial: Awaited<
    ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>
  >;
  try {
    activeMaterial = await input.services.resolveEd25519MaterialActivation({
      walletId,
      materialActivation,
    });
  } catch {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 503,
        code: 'wallet_session_unavailable',
        message: walletSessionFailureMessage('wallet_session_unavailable'),
      }),
    };
  }
  if (!activeMaterial.ok) {
    const code =
      activeMaterial.code === 'internal'
        ? 'wallet_session_unavailable'
        : 'wallet_session_scope_mismatch';
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: activeMaterial.code === 'internal' ? 503 : 403,
        code,
        message: walletSessionFailureMessage(code),
      }),
    };
  }
  return { kind: 'authorized', admission, activeMaterial, materialActivation };
}

async function resolveExhaustedEd25519OperationCredentialMaterial(input: {
  readonly request: Request;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<ExhaustedEd25519OperationCredentialMaterialResolution | null> {
  const token = extractBearerCredential(input.request.headers);
  if (!token) return null;
  let candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext | null;
  try {
    candidate =
      await input.services.authorizationSessions.readExhaustedWalletSessionAuthorizationV2CandidateByOperationCredential(
        {
          tenantId: input.services.authorizationSessions.tenantId,
          token,
          nowMs: Date.now(),
        },
      );
  } catch {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 503,
        code: 'wallet_session_unavailable',
        message: walletSessionFailureMessage('wallet_session_unavailable'),
      }),
    };
  }
  if (!candidate) return null;
  const session = candidate.status.session;
  const admission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority: candidate.authority,
    authMethod: candidate.authMethod,
    operation: {
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      keyFamily: 'ed25519',
      operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    },
    retiredAtMs: candidate.retiredAtMs,
    nowMs: Date.now(),
  });
  if (!admission.ok || admission.keyFamily !== 'ed25519') {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 403,
        code: 'wallet_session_scope_mismatch',
        message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
      }),
    };
  }
  const materialActivation = routerAbMpcMaterialActivationRefToWire(admission.materialActivation);
  let activeMaterial: Awaited<
    ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>
  >;
  try {
    activeMaterial = await input.services.resolveEd25519MaterialActivation({
      walletId: String(session.walletId),
      materialActivation,
    });
  } catch {
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: 503,
        code: 'wallet_session_unavailable',
        message: walletSessionFailureMessage('wallet_session_unavailable'),
      }),
    };
  }
  if (!activeMaterial.ok) {
    const code =
      activeMaterial.code === 'internal'
        ? 'wallet_session_unavailable'
        : 'wallet_session_scope_mismatch';
    return {
      kind: 'rejected',
      result: authorizationFailure({
        status: activeMaterial.code === 'internal' ? 503 : 403,
        code,
        message: walletSessionFailureMessage(code),
      }),
    };
  }
  return { kind: 'authorized', candidate, admission, activeMaterial, materialActivation };
}

function exactRecoveryAdmissionMatches(input: {
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly admission: ExactEd25519OperationCredentialAdmission;
  readonly activeMaterial: ActiveEd25519MaterialResolution;
  readonly materialActivation: ActiveEd25519MaterialResolution['materialActivation'];
}): boolean {
  const request = input.request;
  const identity = input.activeMaterial.exportIdentity;
  const walletId = String(input.admission.context.authorization.session.walletId);
  const registeredPublicKeyB64u = base64UrlEncode(Uint8Array.from(identity.registered_public_key));
  return (
    String(input.admission.admission.signer.walletId) === walletId &&
    registeredPublicKeyB64u === input.admission.admission.signer.registeredPublicKeyB64u &&
    request.scope.account_id === walletId &&
    request.application_binding.wallet_id === walletId &&
    sameValue(request.active_material_activation, input.materialActivation) &&
    sameValue(input.activeMaterial.materialActivation, input.materialActivation) &&
    sameValue(identity.scope.material_activation, input.materialActivation) &&
    request.scope.root_share_epoch === identity.scope.root_share_epoch &&
    request.scope.account_id === identity.scope.account_id &&
    request.scope.threshold_session_id === identity.scope.threshold_session_id &&
    request.scope.signer_set_id === identity.scope.signer_set_id &&
    request.scope.signing_worker_id === identity.scope.signing_worker_id &&
    input.activeMaterial.runtimePolicyScope.signingRootVersion === request.scope.root_share_epoch &&
    input.activeMaterial.nearAccountId.length > 0 &&
    input.activeMaterial.signerSlot === request.application_binding.key_creation_signer_slot &&
    input.activeMaterial.signingWorkerId === request.scope.signing_worker_id &&
    sameValue(request.application_binding, identity.application_binding) &&
    sameValue(request.participant_ids, input.activeMaterial.participantIds) &&
    sameValue(request.participant_ids, identity.participant_ids) &&
    sameValue(request.registered_public_key, identity.registered_public_key)
  );
}

async function authorizeV2RecoveryAdmission(input: {
  readonly request: Extract<
    RouterAbEd25519YaoRecoveryAuthorizationInput,
    { readonly kind: 'admit' }
  >;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
  const resolved = await resolveExactEd25519OperationCredentialMaterial({
    request: input.request.request,
    services: input.services,
  });
  if (resolved.kind === 'rejected') return resolved.result;
  if (!exactRecoveryAdmissionMatches({ request: input.request.body, ...resolved })) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return {
    ok: true,
    authorization: {
      kind: 'wallet_session_v2',
      context: resolved.admission.context,
    },
  };
}

async function authorizeV2WarmBootstrap(input: {
  readonly request: Extract<
    RouterAbEd25519YaoRecoveryAuthorizationInput,
    { readonly kind: 'bootstrap' }
  >;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
  const active = await resolveExactEd25519OperationCredentialMaterial({
    request: input.request.request,
    services: input.services,
  });
  let resolution:
    | Extract<ExactEd25519OperationCredentialMaterialResolution, { readonly kind: 'authorized' }>
    | Extract<
        ExhaustedEd25519OperationCredentialMaterialResolution,
        { readonly kind: 'authorized' }
      >;
  if (active.kind === 'authorized') {
    resolution = active;
  } else {
    if (active.result.code !== 'wallet_session_unavailable') return active.result;
    const exhausted = await resolveExhaustedEd25519OperationCredentialMaterial({
      request: input.request.request,
      services: input.services,
    });
    if (!exhausted) return active.result;
    if (exhausted.kind === 'rejected') return exhausted.result;
    resolution = exhausted;
  }
  const admission =
    'candidate' in resolution ? resolution.admission : resolution.admission.admission;
  const activeMaterial = resolution.activeMaterial;
  const materialActivation = resolution.materialActivation;
  const session =
    'candidate' in resolution
      ? resolution.candidate.status.session
      : resolution.admission.context.authorization.session;
  const walletId = String(session.walletId);
  const request = input.request.body;
  const identity = activeMaterial.exportIdentity;
  const registeredPublicKeyB64u = base64UrlEncode(Uint8Array.from(identity.registered_public_key));
  if (
    walletId !== request.walletId ||
    String(admission.signer.walletId) !== walletId ||
    registeredPublicKeyB64u !== admission.signer.registeredPublicKeyB64u ||
    !sameValue(activeMaterial.materialActivation, materialActivation) ||
    !sameValue(identity.scope.material_activation, materialActivation) ||
    identity.scope.account_id !== walletId ||
    identity.application_binding.wallet_id !== walletId ||
    activeMaterial.nearAccountId !== request.nearAccountId ||
    identity.application_binding.near_ed25519_signing_key_id !== request.nearEd25519SigningKeyId ||
    activeMaterial.signerSlot !== request.signerSlot ||
    identity.application_binding.key_creation_signer_slot !== request.signerSlot ||
    identity.scope.threshold_session_id !== request.thresholdSessionId ||
    activeMaterial.signingWorkerId !== request.signingWorkerId ||
    identity.scope.signing_worker_id !== request.signingWorkerId ||
    !sameValue(activeMaterial.participantIds, request.participantIds) ||
    !sameValue(identity.participant_ids, request.participantIds)
  ) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  if ('candidate' in resolution) {
    return {
      ok: true,
      authorization: {
        kind: 'wallet_session_v2_exhausted_candidate',
        context: resolution.candidate,
      },
    };
  }
  return {
    ok: true,
    authorization: {
      kind: 'wallet_session_v2',
      context: resolution.admission.context,
    },
  };
}

async function authorizeRecoveryContinuation(input: {
  readonly request: Extract<
    RouterAbEd25519YaoRecoveryAuthorizationInput,
    { readonly kind: 'execute' | 'activate' }
  >;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
  if (!extractBearerCredential(input.request.request.headers)) {
    return {
      ok: true,
      authorization: {
        kind: 'wallet_recovery',
        walletId: input.request.body.binding.lifecycle.account_id,
      },
    };
  }
  const resolved = await resolveExactEd25519OperationCredentialAdmission({
    request: input.request.request,
    services: input.services,
  });
  if (resolved.kind === 'rejected') return resolved.result;
  const context = resolved.admission.context;
  const session = context.authorization.session;
  const walletId = String(session.walletId);
  if (
    walletId !== input.request.body.binding.lifecycle.account_id ||
    String(context.authority.walletId) !== walletId ||
    String(context.authMethod.walletId) !== walletId ||
    context.authority.authorityId !== session.authorityId ||
    context.authMethod.walletAuthMethodId !== session.walletAuthMethodId
  ) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return {
    ok: true,
    authorization: {
      kind: 'wallet_session_v2',
      context,
    },
  };
}

export class RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter implements RouterAbEd25519YaoRecoveryAuthorizationAdapter {
  constructor(
    private readonly resolveServices: () => Promise<RouterAbEd25519YaoRecoveryAuthorizationServicesV1>,
  ) {}

  async authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
    let services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
    try {
      services = await this.resolveServices();
    } catch {
      return authorizationFailure({
        status: 503,
        code: 'wallet_recovery_unavailable',
        message: 'wallet recovery admission is unavailable',
      });
    }
    switch (input.kind) {
      case 'bootstrap': {
        return await authorizeV2WarmBootstrap({ request: input, services });
      }
      case 'admit': {
        const challengeId = String(
          input.request.headers.get(ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1) || '',
        ).trim();
        if (challengeId) return await authorizePreparedRecovery({ request: input, services });
        if (extractBearerCredential(input.request.headers)) {
          return await authorizeV2RecoveryAdmission({ request: input, services });
        }
        return await authorizePreparedRecovery({ request: input, services });
      }
      case 'execute':
      case 'activate': {
        return await authorizeRecoveryContinuation({ request: input, services });
      }
    }
  }
}
