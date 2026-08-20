import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type ReusableWalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type ParsedYaoRecoverySessionV1 = {
  readonly walletSessionToken: string;
  readonly sessionKind: 'opaque';
  readonly thresholdSessionId: string;
  readonly authorizationId: ReusableWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly participantIds: readonly [number, number];
  readonly routerAbNormalSigning: NonNullable<
    ReturnType<typeof parseRouterAbEd25519NormalSigningState>
  >;
};

export type ParsedYaoRecoveryCapabilityV1 = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly activeCapabilityBinding: readonly number[];
  readonly registeredPublicKey: readonly number[];
  readonly nearAccountId: AccountId;
  readonly applicationBinding: {
    readonly wallet_id: string;
    readonly near_ed25519_signing_key_id: string;
    readonly signing_root_id: string;
    readonly key_creation_signer_slot: number;
  };
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly lifecycle: {
    readonly lifecycleId: string;
    readonly rootShareEpoch: string;
    readonly accountId: string;
    readonly thresholdSessionId: ThresholdEd25519SessionId;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
  readonly registrationContinuity:
    | {
        readonly kind: 'registration';
        readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
        readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
        readonly activationTranscript: readonly number[];
      }
    | {
        readonly kind: 'recovery';
        readonly activationTranscript: readonly number[];
      };
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function requireThresholdEd25519SessionId(
  value: unknown,
  label: string,
): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(value);
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireBytes32(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  const bytes: number[] = [];
  for (const byte of value) {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label} must contain exactly 32 bytes`);
    }
    bytes.push(byte);
  }
  return Object.freeze(bytes);
}

function requireBytes(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must contain bytes`);
  }
  return value.map((byte) => {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label} must contain bytes`);
    }
    return byte;
  });
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    value[0] < 1 ||
    value[1] < 1 ||
    value[0] === value[1]
  ) {
    throw new Error('participantIds must contain two distinct positive integers');
  }
  return [Number(value[0]), Number(value[1])];
}

function parseRegistrationContinuity(
  value: unknown,
): ParsedYaoRecoveryCapabilityV1['registrationContinuity'] {
  const record = requireRecord(value, 'capability.registrationContinuity');
  if (record.kind === 'recovery') {
    return {
      kind: 'recovery',
      activationTranscript: requireBytes(
        record.activationTranscript,
        'capability.registrationContinuity.activationTranscript',
      ),
    };
  }
  if (record.kind !== 'registration') {
    throw new Error('capability.registrationContinuity kind is invalid');
  }
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    record.admissionRequest,
  );
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    record.admissionReceipt,
  );
  if (!admissionRequest.ok) {
    throw new Error(
      `capability registration continuity transcript is invalid: ${admissionRequest.message}`,
    );
  }
  if (!admissionReceipt.ok) {
    throw new Error(
      `capability registration continuity transcript is invalid: ${admissionReceipt.message}`,
    );
  }
  return {
    kind: 'registration',
    admissionRequest: admissionRequest.value,
    admissionReceipt: admissionReceipt.value,
    activationTranscript: requireBytes(
      record.activationTranscript,
      'capability.registrationContinuity.activationTranscript',
    ),
  };
}

export function parseEd25519YaoRecoveryCapabilityV1(
  raw: unknown,
): ParsedYaoRecoveryCapabilityV1 {
  const record = requireRecord(raw, 'capability');
  if (record.kind !== 'router_ab_ed25519_yao_active_capability_v1') {
    throw new Error('Yao recovery capability kind is invalid');
  }
  const application = requireRecord(record.applicationBinding, 'capability.applicationBinding');
  const lifecycle = requireRecord(record.lifecycle, 'capability.lifecycle');
  let materialActivation: MpcMaterialActivationRef;
  try {
    materialActivation = routerAbMpcMaterialActivationRefFromWire(record.materialActivation);
  } catch (error) {
    throw new Error(
      `capability.materialActivation is invalid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return {
    materialActivation,
    activeCapabilityBinding: requireBytes32(
      record.activeCapabilityBinding,
      'capability.activeCapabilityBinding',
    ),
    registeredPublicKey: requireBytes32(
      record.registeredPublicKey,
      'capability.registeredPublicKey',
    ),
    nearAccountId: toAccountId(requireString(record.nearAccountId, 'capability.nearAccountId')),
    applicationBinding: {
      wallet_id: requireString(application.wallet_id, 'applicationBinding.wallet_id'),
      near_ed25519_signing_key_id: requireString(
        application.near_ed25519_signing_key_id,
        'applicationBinding.near_ed25519_signing_key_id',
      ),
      signing_root_id: requireString(
        application.signing_root_id,
        'applicationBinding.signing_root_id',
      ),
      key_creation_signer_slot: requirePositiveInteger(
        application.key_creation_signer_slot,
        'applicationBinding.key_creation_signer_slot',
      ),
    },
    participantIds: requireParticipantIds(record.participantIds),
    runtimePolicyScope: normalizeRuntimePolicyScope(
      requireRecord(record.runtimePolicyScope, 'capability.runtimePolicyScope'),
    ),
    lifecycle: {
      lifecycleId: requireString(lifecycle.lifecycleId, 'lifecycle.lifecycleId'),
      rootShareEpoch: requireString(lifecycle.rootShareEpoch, 'lifecycle.rootShareEpoch'),
      accountId: requireString(lifecycle.accountId, 'lifecycle.accountId'),
      thresholdSessionId: requireThresholdEd25519SessionId(
        requireString(lifecycle.thresholdSessionId, 'lifecycle.thresholdSessionId'),
        'lifecycle.thresholdSessionId',
      ),
      signerSetId: requireString(lifecycle.signerSetId, 'lifecycle.signerSetId'),
      signingWorkerId: requireString(lifecycle.signingWorkerId, 'lifecycle.signingWorkerId'),
    },
    stateEpoch: requirePositiveInteger(record.stateEpoch, 'capability.stateEpoch'),
    registrationContinuity: parseRegistrationContinuity(record.registrationContinuity),
  };
}
