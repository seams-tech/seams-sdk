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
} from '../../../framework/authServicePort';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import {
  resolveOpaqueOwnerWalletSessionAdmission,
  resolveWalletSessionOperationCredentialAdmission,
} from '../../../auth/commonRouterUtils';
import { walletSessionFailureMessage } from '../../../auth/walletSessionFailure';
import { NEAR_ED25519_MPC_OPERATION_KINDS } from '@shared/authorization/capabilityKinds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { PreparedEd25519RecoveryAdmissionV1 } from '../../passkeyCustody/walletRecoveryKeyManifest';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationResult,
} from './routerAbEd25519YaoRecovery';

function authorizationFailure(input: {
  readonly status: 401 | 403 | 409 | 429 | 503;
  readonly code: string;
  readonly message: string;
}): RouterAbEd25519YaoRecoveryAuthorizationResult {
  return { ok: false, status: input.status, code: input.code, message: input.message };
}

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

async function authorizeOpaqueOwnerRecovery(input: {
  readonly request: RouterAbEd25519YaoRecoveryAuthorizationInput;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult | null> {
  const token = extractBearerCredential(input.request.request.headers);
  if (!token?.startsWith('wst_')) return null;
  let admission: Awaited<ReturnType<typeof resolveOpaqueOwnerWalletSessionAdmission>>;
  try {
    admission = await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions: input.services.authorizationSessions,
      token,
      curve: 'ed25519',
      nowMs: Date.now(),
    });
  } catch {
    return authorizationFailure({
      status: 503,
      code: 'wallet_session_unavailable',
      message: walletSessionFailureMessage('wallet_session_unavailable'),
    });
  }
  if (!admission || admission.curve !== 'ed25519') {
    return authorizationFailure({
      status: 401,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    });
  }
  const binding = admission.binding;
  let matches: boolean;
  switch (input.request.kind) {
    case 'bootstrap':
      matches =
        binding.walletId === input.request.body.walletId &&
        binding.nearAccountId === input.request.body.nearAccountId &&
        binding.nearEd25519SigningKeyId === input.request.body.nearEd25519SigningKeyId &&
        binding.thresholdSessionId === input.request.body.thresholdSessionId &&
        binding.routerAbNormalSigning.signingWorkerId === input.request.body.signingWorkerId &&
        binding.participantIds[0] === input.request.body.participantIds[0] &&
        binding.participantIds[1] === input.request.body.participantIds[1];
      break;
    case 'admit':
      matches =
        binding.walletId === input.request.body.scope.account_id &&
        binding.walletId === input.request.body.application_binding.wallet_id &&
        binding.nearEd25519SigningKeyId ===
          input.request.body.application_binding.near_ed25519_signing_key_id &&
        binding.runtimePolicyScope.signingRootVersion ===
          input.request.body.scope.root_share_epoch &&
        binding.routerAbNormalSigning.signingWorkerId ===
          input.request.body.scope.signing_worker_id &&
        binding.participantIds[0] === input.request.body.participant_ids[0] &&
        binding.participantIds[1] === input.request.body.participant_ids[1];
      break;
    case 'execute':
    case 'activate':
      matches =
        binding.walletId === input.request.body.binding.lifecycle.account_id &&
        binding.runtimePolicyScope.signingRootVersion ===
          input.request.body.binding.lifecycle.root_share_epoch &&
        binding.routerAbNormalSigning.signingWorkerId ===
          input.request.body.binding.lifecycle.selected_server_id;
      break;
  }
  if (!matches) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return { ok: true, authorization: { kind: 'wallet_session', binding } };
}

async function authorizeV2WarmBootstrap(input: {
  readonly request: Extract<
    RouterAbEd25519YaoRecoveryAuthorizationInput,
    { readonly kind: 'bootstrap' }
  >;
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
  const token = extractBearerCredential(input.request.request.headers);
  if (!token) {
    return authorizationFailure({
      status: 401,
      code: 'wallet_session_missing',
      message: walletSessionFailureMessage('wallet_session_missing'),
    });
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
    return authorizationFailure({
      status: 503,
      code: 'wallet_session_unavailable',
      message: walletSessionFailureMessage('wallet_session_unavailable'),
    });
  }
  if (resolution.kind === 'not_found') {
    return authorizationFailure({
      status: 401,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    });
  }
  if (resolution.kind !== 'admitted' || resolution.admission.curve !== 'ed25519') {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  const admission = resolution.admission;
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
    return authorizationFailure({
      status: 503,
      code: 'wallet_session_unavailable',
      message: walletSessionFailureMessage('wallet_session_unavailable'),
    });
  }
  if (!activeMaterial.ok) {
    return authorizationFailure({
      status: activeMaterial.code === 'internal' ? 503 : 403,
      code:
        activeMaterial.code === 'internal'
          ? 'wallet_session_unavailable'
          : 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage(
        activeMaterial.code === 'internal'
          ? 'wallet_session_unavailable'
          : 'wallet_session_scope_mismatch',
      ),
    });
  }
  const request = input.request.body;
  const identity = activeMaterial.exportIdentity;
  const registeredPublicKeyB64u = base64UrlEncode(Uint8Array.from(identity.registered_public_key));
  if (
    walletId !== request.walletId ||
    String(admission.admission.signer.walletId) !== walletId ||
    registeredPublicKeyB64u !== admission.admission.signer.registeredPublicKeyB64u ||
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
  return {
    ok: true,
    authorization: {
      kind: 'wallet_session_v2',
      context: admission.context,
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
        const opaque = await authorizeOpaqueOwnerRecovery({ request: input, services });
        if (opaque) return opaque;
        return await authorizePreparedRecovery({ request: input, services });
      }
      case 'execute':
      case 'activate': {
        const opaque = await authorizeOpaqueOwnerRecovery({ request: input, services });
        if (opaque) return opaque;
        return {
          ok: true,
          authorization: {
            kind: 'wallet_recovery',
            walletId: input.body.binding.lifecycle.account_id,
          },
        };
      }
    }
  }
}
