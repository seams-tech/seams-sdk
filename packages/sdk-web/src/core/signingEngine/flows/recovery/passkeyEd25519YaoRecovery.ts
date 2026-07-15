import type {
  NearEd25519YaoSigningCapability,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoActiveClientV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { base58Encode } from '@shared/utils/base58';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';

export type ParsedYaoRecoverySessionV1 = {
  readonly walletSessionJwt: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly participantIds: readonly [number, number];
  readonly routerAbNormalSigning: NonNullable<
    ReturnType<typeof parseRouterAbEd25519NormalSigningState>
  >;
};

export type ParsedYaoRecoveryCapabilityV1 = {
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
    readonly walletSessionId: string;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
};

export type ParsedPasskeyEd25519YaoRecoveryDescriptorV1 = {
  readonly walletId: WalletId;
  readonly nearAccountId: AccountId;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly operationalPublicKey: string;
  readonly relayerKeyId: string;
  readonly credentialIdB64u: string;
  readonly session: ParsedYaoRecoverySessionV1;
  readonly capability: ParsedYaoRecoveryCapabilityV1;
};

export type ParsedPasskeyEd25519YaoSyncResponseV1 = ParsedPasskeyEd25519YaoRecoveryDescriptorV1 & {
  readonly credentialPublicKeyB64u: string;
};

export type PasskeyEd25519YaoRecoveryResultV1<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1 =
    ParsedPasskeyEd25519YaoSyncResponseV1,
> = {
  readonly activeClient: RouterAbEd25519YaoActiveClientV1;
  readonly walletSessionState: NearResolvedEd25519SigningSessionState;
  readonly parsed: TParsed;
};

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

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function parseRecoverySession(
  raw: Record<string, unknown>,
  participantIds: readonly [number, number],
  identity: {
    readonly walletId: string;
    readonly nearAccountId: string;
    readonly nearEd25519SigningKeyId: string;
  },
): ParsedYaoRecoverySessionV1 {
  if (raw.sessionKind !== 'jwt') throw new Error('Yao recovery session must use JWT');
  if (
    requireString(raw.walletId, 'session.walletId') !== identity.walletId ||
    requireString(raw.nearAccountId, 'session.nearAccountId') !== identity.nearAccountId ||
    requireString(raw.nearEd25519SigningKeyId, 'session.nearEd25519SigningKeyId') !==
      identity.nearEd25519SigningKeyId
  ) {
    throw new Error('Yao recovery session identity does not match the verified passkey');
  }
  const runtimePolicyRecord = requireRecord(raw.runtimePolicyScope, 'session.runtimePolicyScope');
  const runtimePolicyScope = normalizeRuntimePolicyScope(runtimePolicyRecord);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  if (!routerAbNormalSigning) throw new Error('Yao recovery session signing state is invalid');
  return {
    walletSessionJwt: requireString(raw.walletSessionJwt, 'session.walletSessionJwt'),
    thresholdSessionId: requireString(raw.thresholdSessionId, 'session.thresholdSessionId'),
    signingGrantId: requireString(raw.signingGrantId, 'session.signingGrantId'),
    expiresAtMs: requirePositiveInteger(raw.expiresAtMs, 'session.expiresAtMs'),
    remainingUses: requirePositiveInteger(raw.remainingUses, 'session.remainingUses'),
    runtimePolicyScope,
    participantIds,
    routerAbNormalSigning,
  };
}

export function parseEd25519YaoRecoveryCapabilityV1(raw: unknown): ParsedYaoRecoveryCapabilityV1 {
  const record = requireRecord(raw, 'capability');
  if (record.kind !== 'router_ab_ed25519_yao_active_capability_v1') {
    throw new Error('Yao recovery capability kind is invalid');
  }
  const application = requireRecord(record.applicationBinding, 'capability.applicationBinding');
  const lifecycle = requireRecord(record.lifecycle, 'capability.lifecycle');
  return {
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
      walletSessionId: requireString(lifecycle.walletSessionId, 'lifecycle.walletSessionId'),
      signerSetId: requireString(lifecycle.signerSetId, 'lifecycle.signerSetId'),
      signingWorkerId: requireString(lifecycle.signingWorkerId, 'lifecycle.signingWorkerId'),
    },
    stateEpoch: requirePositiveInteger(record.stateEpoch, 'capability.stateEpoch'),
  };
}

function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

export function assertEd25519YaoRecoveryDescriptorContinuity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): void {
  const capability = parsed.capability;
  const session = parsed.session;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(session.runtimePolicyScope);
  if (
    !signingRoot ||
    capability.applicationBinding.wallet_id !== String(parsed.walletId) ||
    capability.applicationBinding.near_ed25519_signing_key_id !== parsed.nearEd25519SigningKeyId ||
    capability.applicationBinding.key_creation_signer_slot !== parsed.signerSlot ||
    capability.nearAccountId !== parsed.nearAccountId ||
    capability.lifecycle.accountId !== String(parsed.walletId) ||
    capability.lifecycle.walletSessionId !== session.thresholdSessionId ||
    capability.lifecycle.signingWorkerId !== parsed.relayerKeyId ||
    session.routerAbNormalSigning?.signingWorkerId !== parsed.relayerKeyId ||
    session.participantIds[0] !== capability.participantIds[0] ||
    session.participantIds[1] !== capability.participantIds[1] ||
    !sameRuntimePolicyScope(session.runtimePolicyScope, capability.runtimePolicyScope) ||
    session.runtimePolicyScope.signingRootVersion !== capability.lifecycle.rootShareEpoch ||
    capability.applicationBinding.signing_root_id !== signingRoot.signingRootId ||
    parsed.operationalPublicKey !==
      `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`
  ) {
    throw new Error('Yao recovery response does not preserve the registered wallet identity');
  }
}

export function parsePasskeyEd25519YaoSyncResponseV1(
  raw: unknown,
): ParsedPasskeyEd25519YaoSyncResponseV1 {
  const response = requireRecord(raw, 'sync-account response');
  if (response.ok !== true || response.verified !== true) {
    throw new Error('sync-account response is not verified');
  }
  const walletId = walletIdFromString(requireString(response.walletId, 'walletId'));
  const nearAccountId = toAccountId(requireString(response.nearAccountId, 'nearAccountId'));
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'nearEd25519SigningKeyId',
  );
  const threshold = requireRecord(response.thresholdEd25519, 'thresholdEd25519');
  const participantIds = requireParticipantIds(threshold.participantIds);
  const recovery = requireRecord(response.ed25519YaoRecovery, 'ed25519YaoRecovery');
  if (recovery.kind !== 'router_ab_ed25519_yao_sync_recovery_v1') {
    throw new Error('sync-account recovery kind is invalid');
  }
  const parsed: ParsedPasskeyEd25519YaoSyncResponseV1 = {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: requirePositiveInteger(response.signerSlot, 'signerSlot'),
    operationalPublicKey: requireString(response.publicKey, 'publicKey'),
    relayerKeyId: requireString(threshold.relayerKeyId, 'thresholdEd25519.relayerKeyId'),
    credentialIdB64u: requireString(response.credentialIdB64u, 'credentialIdB64u'),
    credentialPublicKeyB64u: requireString(
      response.credentialPublicKeyB64u,
      'credentialPublicKeyB64u',
    ),
    session: parseRecoverySession(
      requireRecord(threshold.session, 'thresholdEd25519.session'),
      participantIds,
      {
        walletId: String(walletId),
        nearAccountId: String(nearAccountId),
        nearEd25519SigningKeyId,
      },
    ),
    capability: parseEd25519YaoRecoveryCapabilityV1(recovery.capability),
  };
  assertEd25519YaoRecoveryDescriptorContinuity(parsed);
  return parsed;
}

function recoveryAdmissionRequest(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const replacementCapabilityBinding = new Uint8Array(32);
  globalThis.crypto.getRandomValues(replacementCapabilityBinding);
  try {
    const request = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: secureRandomId('ed25519-yao-recovery', 32, 'Ed25519 Yao recovery IDs'),
        root_share_epoch: parsed.capability.lifecycle.rootShareEpoch,
        account_id: parsed.capability.lifecycle.accountId,
        wallet_session_id: parsed.session.thresholdSessionId,
        signer_set_id: parsed.capability.lifecycle.signerSetId,
        signing_worker_id: parsed.capability.lifecycle.signingWorkerId,
      },
      application_binding: parsed.capability.applicationBinding,
      participant_ids: parsed.capability.participantIds,
      active_capability_binding: parsed.capability.activeCapabilityBinding,
      replacement_capability_binding: [...replacementCapabilityBinding],
      registered_public_key: parsed.capability.registeredPublicKey,
    });
    if (!request.ok) throw new Error(request.message);
    return request.value;
  } finally {
    replacementCapabilityBinding.fill(0);
  }
}

function persistRecoveredWalletSession(input: {
  readonly parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  readonly relayerUrl: string;
  readonly rpId: string;
}): NearResolvedEd25519SigningSessionState {
  const parsed = input.parsed;
  const session = parsed.session;
  const record = persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    walletId: String(parsed.walletId),
    nearAccountId: parsed.nearAccountId,
    nearEd25519SigningKeyId: parsed.nearEd25519SigningKeyId,
    rpId: input.rpId,
    relayerUrl: input.relayerUrl,
    relayerKeyId: parsed.relayerKeyId,
    runtimePolicyScope: session.runtimePolicyScope,
    participantIds: parsed.capability.participantIds,
    signerSlot: parsed.signerSlot,
    routerAbNormalSigning: session.routerAbNormalSigning,
    sessionId: session.thresholdSessionId,
    signingGrantId: session.signingGrantId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    jwt: session.walletSessionJwt,
    passkeyCredentialIdB64u: parsed.credentialIdB64u,
    source: 'login',
  });
  const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!walletSessionState) throw new Error('recovered Yao Wallet Session is unusable');
  return walletSessionState;
}

export async function recoverPasskeyEd25519YaoCapabilityV1(input: {
  readonly syncResponse: unknown;
  readonly ownedPasskeyPrfFirst: Uint8Array;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoRecoveryResultV1> {
  try {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(input.syncResponse);
    return await recoverParsedPasskeyEd25519YaoCapabilityV1({
      parsed,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      fetch: input.fetch,
    });
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
  }
}

export async function recoverParsedPasskeyEd25519YaoCapabilityV1<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
>(input: {
  readonly parsed: TParsed;
  readonly ownedPasskeyPrfFirst: Uint8Array;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoRecoveryResultV1<TParsed>> {
  let ownedActiveClient: RouterAbEd25519YaoActiveClientV1 | null = null;
  try {
    const parsed = input.parsed;
    assertEd25519YaoRecoveryDescriptorContinuity(parsed);
    const client = await RouterAbEd25519YaoClientV1.initializeBundled();
    const result = await client.recover({
      request: recoveryAdmissionRequest(parsed),
      factor: { kind: 'passkey_prf_first', ownedSecret32: input.ownedPasskeyPrfFirst },
      transport: new RouterAbEd25519YaoHttpActivationTransportV1({
        routerOrigin: new URL(input.relayerUrl).origin,
        authorization: `Bearer ${parsed.session.walletSessionJwt}`,
        fetch: input.fetch,
      }),
    });
    if (!result.ok) throw new Error(result.message);
    ownedActiveClient = result.activeClient;
    const metadata = ownedActiveClient.metadata();
    if (
      metadata.stateEpoch !== BigInt(parsed.capability.stateEpoch) + 1n ||
      `ed25519:${base58Encode(metadata.registeredPublicKey)}` !== parsed.operationalPublicKey
    ) {
      throw new Error('recovered Yao Client does not preserve the registered public key');
    }
    const walletSessionState = persistRecoveredWalletSession({
      parsed,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
    });
    const capability: NearEd25519YaoSigningCapability = {
      activeClient: ownedActiveClient,
      walletSessionState,
    };
    ownedActiveClient = null;
    return { activeClient: capability.activeClient, walletSessionState, parsed };
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
    ownedActiveClient?.dispose();
  }
}
