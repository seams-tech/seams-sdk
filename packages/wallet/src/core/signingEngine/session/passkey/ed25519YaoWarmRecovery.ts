import type { CurrentEd25519SealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { readExactEd25519SealedSession } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { ed25519DurableMaterialLocator } from '../sealedRecovery/materialActivationKey';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity,
  parseEd25519YaoRecoveryCapabilityV1,
  type ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
} from '@/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import { toAccountId } from '@/core/types/accountIds';
import { base58Encode } from '@shared/utils/base58';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  buildPasskeyWalletAuthAuthority,
  parsePasskeyWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
  walletAuthAuthoritiesMatch,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { isPlainObject } from '@shared/utils/validation';
import { walletSessionFailureErrorFromPayload } from '../lifecycle/walletSessionFailure';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';
import type { OwnerLaneProtocolSourceV1 } from '@shared/signing-lanes/rotation';
import {
  walletSessionAuthorizations,
  walletSessionAuthorizationIdForCurve,
  walletSessionTokenForCurve,
  walletSessionThresholdSessionIdForCurve,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  mpcMaterialActivationRefsEqual,
  parseWalletId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
  type WalletId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import {
  readEd25519YaoClientRootEnvelopeV1,
  readEd25519YaoExportEnvelopeForPasskeyV1,
  type Ed25519YaoClientRootEnvelopeIdentityV1,
} from './passkeyCustodySessionCache';

export type PasskeyEd25519RecordRuntimePorts = {
  readonly readExactEd25519SealedSession: typeof readExactEd25519SealedSession;
  readonly readActiveWalletSessionAuthorization: (
    walletId: WalletId,
  ) => Promise<WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>>;
  readonly nowMs: () => number;
};

export type PasskeyEd25519WarmRecoverySubject =
  | {
      readonly kind: 'owner_sealed_runtime';
      readonly walletId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly signerSlot: number;
      readonly thresholdSessionId: ThresholdEd25519SessionId;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'delegated_active_bundle';
      readonly walletId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly signerSlot: number;
      /** The linked holder material is only an exact-subject substitution fence. */
      readonly targetMaterialActivation: MpcMaterialActivationRef;
      /** Export material is always the owner source lane, never the holder lane. */
      readonly sourceMaterialActivation: MpcMaterialActivationRef;
      readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
      readonly sourceOwnerCapability: OwnerLaneProtocolSourceV1;
    };

export type PasskeyEd25519YaoWarmRecoveryUnavailableReason =
  | 'sealed_session_missing'
  | 'sealed_session_expired'
  | 'sealed_session_exhausted'
  | 'wallet_session_expired'
  | 'wallet_custody_envelope_missing';

export type PasskeyEd25519YaoExportContextV1 = {
  readonly kind: 'passkey_ed25519_yao_export_context_v1';
  readonly selectedLaneMaterialActivation: MpcMaterialActivationRef;
  readonly material: Omit<ParsedPasskeyEd25519YaoRecoveryDescriptorV1, 'session'>;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
};

export type PasskeyEd25519YaoExportContextResolutionV1 =
  | {
      readonly kind: 'ready';
      readonly context: PasskeyEd25519YaoExportContextV1;
    }
  | {
      readonly kind: 'capability_recovery_required';
      readonly reason: PasskeyEd25519YaoWarmRecoveryUnavailableReason;
    };

type WarmRecoveryRecordResult =
  | { readonly kind: 'ready'; readonly record: CurrentEd25519SealedSessionRecord }
  | {
      readonly kind: 'unavailable';
      readonly reason: Exclude<
        PasskeyEd25519YaoWarmRecoveryUnavailableReason,
        'wallet_session_expired'
      >;
    };

type WarmRecoveryBootstrapResult =
  | { readonly kind: 'ready'; readonly response: Record<string, unknown> }
  | { readonly kind: 'unavailable'; readonly reason: 'wallet_session_expired' };

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
    throw new Error('warm recovery participantIds must contain two distinct positive integers');
  }
  return [Number(value[0]), Number(value[1])];
}

const OWNER_WARM_RECOVERY_RESPONSE_KEYS = [
  'authority',
  'authorityRef',
  'authorityScope',
  'capability',
  'kind',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'participantIds',
  'quotaId',
  'routerAbNormalSigning',
  'runtimePolicyScope',
  'signerSlot',
  'signingWorkerId',
  'thresholdExpiresAtMs',
  'thresholdSessionId',
  'walletId',
  'walletSessionId',
] as const;

const LINKED_DEVICE_WARM_RECOVERY_RESPONSE_KEYS = [
  'capability',
  'kind',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'participantIds',
  'quotaId',
  'routerAbNormalSigning',
  'runtimePolicyScope',
  'signerSlot',
  'signingWorkerId',
  'thresholdExpiresAtMs',
  'thresholdSessionId',
  'walletId',
  'walletSessionId',
] as const;

function exactResponseKeys(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
): void {
  const expected = [...expectedFields].sort();
  const actual = Object.keys(record).sort();
  if (actual.length !== expected.length) {
    throw new Error('warm recovery bootstrap response fields are invalid');
  }
  for (let index = 0; index < actual.length; index += 1) {
    if (actual[index] !== expected[index]) {
      throw new Error('warm recovery bootstrap response fields are invalid');
    }
  }
}

function sealedRecordMatchesSubject(
  record: CurrentEd25519SealedSessionRecord,
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'owner_sealed_runtime' }>,
): boolean {
  if (record.authMethod !== 'passkey') return false;
  const restore = record.ed25519Restore;
  if (!restore.credentialIdB64u) return false;
  return (
    record.walletId === subject.walletId &&
    restore.nearAccountId === subject.nearAccountId &&
    restore.nearEd25519SigningKeyId === subject.nearEd25519SigningKeyId &&
    restore.signerSlot === subject.signerSlot
  );
}

async function resolveExactWarmRecoveryRecord(
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'owner_sealed_runtime' }>,
  runtime: PasskeyEd25519RecordRuntimePorts,
): Promise<WarmRecoveryRecordResult> {
  const record = await runtime.readExactEd25519SealedSession(
    ed25519DurableMaterialLocator({
      authMethod: 'passkey',
      materialActivation: subject.materialActivation,
    }),
  );
  if (
    record &&
    (record.curve !== 'ed25519' ||
      !sealedRecordMatchesSubject(record, subject) ||
      !mpcMaterialActivationRefsEqual(
        record.ed25519Restore.materialActivation,
        subject.materialActivation,
      ))
  ) {
    return { kind: 'unavailable', reason: 'sealed_session_missing' };
  }
  if (!record) return { kind: 'unavailable', reason: 'sealed_session_missing' };
  if (record.expiresAtMs <= runtime.nowMs()) {
    return { kind: 'unavailable', reason: 'sealed_session_expired' };
  }
  if (record.remainingUses < 1) {
    return { kind: 'unavailable', reason: 'sealed_session_exhausted' };
  }
  return { kind: 'ready', record };
}

function unavailableReasonForWarmMaterialCode(
  code: string,
): Exclude<PasskeyEd25519YaoWarmRecoveryUnavailableReason, 'wallet_session_expired'> | null {
  switch (code) {
    case 'not_found':
    case 'missing':
      return 'sealed_session_missing';
    case 'expired':
      return 'sealed_session_expired';
    case 'exhausted':
      return 'sealed_session_exhausted';
    default:
      return null;
  }
}

export async function requirePasskeyEd25519RestoreAuthorization(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorizationRead: WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>;
  readonly nowMs: number;
}): Promise<ActiveWalletSessionAuthorizationProjection | null> {
  if (args.authorizationRead.kind !== 'found') return null;
  const restore = args.record.ed25519Restore;
  const authority = await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId: args.record.walletId,
      rpId: restore.rpId,
      credentialIdB64u: requireString(restore.credentialIdB64u, 'ed25519Restore.credentialIdB64u'),
    }),
  });
  const authorization = args.authorizationRead.projection;
  if (
    authorization.authMethod !== 'passkey' ||
    String(authorization.walletId) !== args.record.walletId ||
    authorization.authority.authorityDigest !== authority.authorityDigest ||
    authorization.expiresAtMs <= args.nowMs
  ) {
    return null;
  }
  if (!walletSessionTokenForCurve(authorization, 'ed25519')) return null;
  return authorization;
}

type ActiveLinkedDeviceEd25519ExecutionV1 = Extract<
  ActiveLinkedDeviceExecutionChildV1,
  { readonly keyFamily: 'ed25519' }
>;

type DelegatedPasskeyRootBindingV1 = {
  readonly identity: Ed25519YaoClientRootEnvelopeIdentityV1;
  readonly rpId: string;
  readonly credentialIdB64u: string;
};

function isActiveLinkedDeviceEd25519ExecutionV1(
  execution: ActiveLinkedDeviceExecutionChildV1,
): execution is ActiveLinkedDeviceEd25519ExecutionV1 {
  return execution.keyFamily === 'ed25519';
}

function activeLinkedDeviceEd25519ExecutionForExport(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
): ActiveLinkedDeviceEd25519ExecutionV1 {
  let selected: ActiveLinkedDeviceEd25519ExecutionV1 | null = null;
  for (const execution of bundle.orderedExecutions) {
    if (!isActiveLinkedDeviceEd25519ExecutionV1(execution)) continue;
    if (selected) {
      throw new Error('delegated Ed25519 export subject contains multiple Ed25519 executions');
    }
    selected = execution;
  }
  if (!selected) {
    throw new Error('delegated Ed25519 export subject is missing its Ed25519 execution');
  }
  return selected;
}

function ownerCapabilityMatchesExecution(
  source: OwnerLaneProtocolSourceV1,
  execution: ActiveLinkedDeviceEd25519ExecutionV1,
): boolean {
  const expected = execution.job.source;
  if (expected.sourceKind !== 'owner_registration') return false;
  return (
    source.sourceKind === expected.sourceKind &&
    source.laneKind === expected.laneKind &&
    source.laneId === expected.laneId &&
    source.laneShareEpoch === expected.laneShareEpoch &&
    source.revocationEpoch === expected.revocationEpoch &&
    source.participantBindingDigestB64u === expected.participantBindingDigestB64u &&
    mpcMaterialActivationRefsEqual(source.materialActivation, expected.materialActivation) &&
    source.ownerParticipantContinuity.signerId === expected.ownerParticipantContinuity.signerId &&
    source.ownerParticipantContinuity.signingWorkerId ===
      expected.ownerParticipantContinuity.signingWorkerId &&
    source.ownerParticipantContinuity.custodyKeyManifestDigestB64u ===
      expected.ownerParticipantContinuity.custodyKeyManifestDigestB64u &&
    source.ownerParticipantContinuity.sourceIdentityDigestB64u ===
      expected.ownerParticipantContinuity.sourceIdentityDigestB64u &&
    source.ownerParticipantContinuity.participantIds[0] ===
      expected.ownerParticipantContinuity.participantIds[0] &&
    source.ownerParticipantContinuity.participantIds[1] ===
      expected.ownerParticipantContinuity.participantIds[1]
  );
}

function delegatedPasskeyRootBindingForSubject(
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'delegated_active_bundle' }>,
  nowMs: number,
): DelegatedPasskeyRootBindingV1 {
  const bundle = subject.bundle;
  if (!hasDelegatedWalletPermissionV1(bundle.permission, 'export_keys')) {
    throw new Error('delegated Ed25519 export requires the export_keys permission');
  }
  if (
    String(bundle.walletId) !== subject.walletId ||
    String(bundle.nearAccountId) !== subject.nearAccountId ||
    bundle.expiresAtMs <= nowMs ||
    bundle.remainingUses < 1
  ) {
    throw new Error('delegated Ed25519 export subject is not active');
  }
  const execution = activeLinkedDeviceEd25519ExecutionForExport(bundle);
  if (
    !mpcMaterialActivationRefsEqual(
      execution.materialActivation,
      subject.targetMaterialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(
      execution.job.source.materialActivation,
      subject.sourceMaterialActivation,
    ) ||
    String(execution.job.nearEd25519SigningKeyId) !== subject.nearEd25519SigningKeyId ||
    execution.walletKey.keyCreationSignerSlot !== subject.signerSlot ||
    !ownerCapabilityMatchesExecution(subject.sourceOwnerCapability, execution)
  ) {
    throw new Error('delegated Ed25519 export subject does not match its active execution');
  }
  const root = bundle.targetPreparation.ed25519ExportRoot;
  const registration = bundle.targetCredentialRegistration;
  if (
    !root ||
    root.walletKeyId !== execution.walletKeyId ||
    registration.targetFactor.kind !== 'passkey_prf' ||
    bundle.targetPreparation.targetFactor.kind !== 'passkey_prf'
  ) {
    throw new Error('delegated Ed25519 export root is unavailable for the Passkey target');
  }
  const webauthnRegistration = registration.webauthnRegistration;
  const ownerRegistration = bundle.targetPreparation.ownerEnrollment.registration;
  if (!webauthnRegistration || !ownerRegistration) {
    throw new Error('delegated Ed25519 export root is missing Passkey registration evidence');
  }
  if (
    String(webauthnRegistration.credentialIdB64u) === '' ||
    String(ownerRegistration.rpId) === '' ||
    registration.walletId !== bundle.walletId ||
    registration.enrollmentId !== bundle.enrollmentId ||
    registration.deviceId !== bundle.deviceId ||
    registration.linkSessionId !== bundle.linkSessionId
  ) {
    throw new Error('delegated Ed25519 export root target identity changed');
  }
  return {
    identity: {
      walletId: String(bundle.walletId),
      linkSessionId: String(bundle.linkSessionId),
      walletKeyId: String(execution.walletKeyId),
      enrollmentId: String(bundle.enrollmentId),
      deviceId: String(bundle.deviceId),
      applicationBindingDigestB64u: String(root.applicationBindingDigestB64u),
      registeredPublicKeyB64u: String(root.registeredPublicKeyB64u),
      revocationEpoch: root.revocationEpoch,
      targetFactor: {
        kind: 'passkey_prf',
        rpId: String(ownerRegistration.rpId),
        credentialIdB64u: String(webauthnRegistration.credentialIdB64u),
      },
    },
    rpId: String(ownerRegistration.rpId),
    credentialIdB64u: String(webauthnRegistration.credentialIdB64u),
  };
}

export async function requireDelegatedPasskeyExportAuthorization(args: {
  readonly subject: Extract<
    PasskeyEd25519WarmRecoverySubject,
    { readonly kind: 'delegated_active_bundle' }
  >;
  readonly authorizationRead: WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>;
  readonly nowMs: number;
}): Promise<ActiveWalletSessionAuthorizationProjection | null> {
  if (args.authorizationRead.kind !== 'found') return null;
  const root = delegatedPasskeyRootBindingForSubject(args.subject, args.nowMs);
  const expectedAuthority = await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId: args.subject.walletId,
      rpId: root.rpId,
      credentialIdB64u: root.credentialIdB64u,
    }),
  });
  const authorization = args.authorizationRead.projection;
  const authorizationId = walletSessionAuthorizationIdForCurve(authorization, 'ed25519');
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(authorization, 'ed25519');
  if (
    authorization.authMethod !== 'passkey' ||
    String(authorization.walletId) !== args.subject.walletId ||
    String(authorization.walletSessionId) !== String(args.subject.bundle.walletSessionId) ||
    String(authorization.quotaId) !== String(args.subject.bundle.quotaId) ||
    authorizationId === null ||
    !thresholdSessionId ||
    String(authorizationId) !== String(args.subject.bundle.authorizationId) ||
    authorization.authority.walletAuthMethodId !== expectedAuthority.walletAuthMethodId ||
    authorization.authority.authorityDigest !== expectedAuthority.authorityDigest ||
    authorization.expiresAtMs <= args.nowMs ||
    authorization.expiresAtMs > args.subject.bundle.expiresAtMs ||
    !walletSessionTokenForCurve(authorization, 'ed25519')
  ) {
    return null;
  }
  return authorization;
}

function requireDelegatedWalletSessionThresholdSessionId(
  authorization: ActiveWalletSessionAuthorizationProjection,
): ThresholdEd25519SessionId {
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(authorization, 'ed25519');
  if (!thresholdSessionId) {
    throw new Error('delegated Ed25519 export requires an active linked Wallet Session threshold');
  }
  return thresholdSessionId;
}

function delegatedWarmRecoveryBootstrapRequest(
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'delegated_active_bundle' }>,
  authorization: ActiveWalletSessionAuthorizationProjection,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  const execution = activeLinkedDeviceEd25519ExecutionForExport(subject.bundle);
  const source = subject.sourceOwnerCapability;
  const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: subject.walletId,
    nearAccountId: subject.nearAccountId,
    nearEd25519SigningKeyId: String(execution.job.nearEd25519SigningKeyId),
    signerSlot: execution.job.keyCreationSignerSlot,
    thresholdSessionId: requireDelegatedWalletSessionThresholdSessionId(authorization),
    signingWorkerId: String(source.ownerParticipantContinuity.signingWorkerId),
    participantIds: source.ownerParticipantContinuity.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function ownerWarmRecoveryBootstrapRequest(
  record: CurrentEd25519SealedSessionRecord,
  thresholdSessionId: ThresholdEd25519SessionId,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  const restore = record.ed25519Restore;
  const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId,
    signingWorkerId: restore.routerAbNormalSigning.signingWorkerId,
    participantIds: restore.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

async function fetchWarmRecoveryBootstrap(args: {
  readonly request: RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<WarmRecoveryBootstrapResult> {
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ed25519');
  if (!walletSessionToken) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  if (
    args.authorization.walletId !== args.request.walletId ||
    args.authorization.authMethod !== 'passkey' ||
    !args.authorization.walletSessionId ||
    !args.authorization.quotaId
  ) {
    throw new Error(
      '[SigningEngine][near] active Wallet Session authorization does not match sealed material',
    );
  }
  const response = await args.fetch(
    `${new URL(args.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${walletSessionToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(args.request),
    },
  );
  const body = await parseJsonResponseOrNull(response);
  const parsedBody = isPlainObject(body) ? body : null;
  if (!response.ok) {
    const code = parsedBody ? String(parsedBody.code || '').trim() : '';
    if (response.status === 401 && code === 'wallet_session_expired') {
      return { kind: 'unavailable', reason: 'wallet_session_expired' };
    }
    const message = parsedBody ? String(parsedBody.message || '').trim() : '';
    const tokenClaims = decodeJwtPayloadRecord(walletSessionToken);
    const tokenKind = String(tokenClaims?.kind || 'opaque');
    throw new Error(
      `[SigningEngine][near] Ed25519 warm recovery bootstrap failed (HTTP ${response.status}${code ? `, ${code}` : ''}, token ${tokenKind}): ${message || 'invalid response'}`,
    );
  }
  if (!parsedBody) throw new Error('Ed25519 warm recovery bootstrap returned invalid JSON');
  return { kind: 'ready', response: parsedBody };
}

async function parseJsonResponseOrNull(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
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

async function parseWarmRecoveryDescriptor(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly response: Record<string, unknown>;
}): Promise<ParsedPasskeyEd25519YaoRecoveryDescriptorV1> {
  const record = args.record;
  const response = args.response;
  exactResponseKeys(response, OWNER_WARM_RECOVERY_RESPONSE_KEYS);
  if (response.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('warm recovery bootstrap response kind is invalid');
  }
  const restore = record.ed25519Restore;
  const credentialIdB64u = requireString(
    restore.credentialIdB64u,
    'ed25519Restore.credentialIdB64u',
  );
  const walletId = requireString(response.walletId, 'response.walletId');
  const nearAccountId = requireString(response.nearAccountId, 'response.nearAccountId');
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'response.nearEd25519SigningKeyId',
  );
  const signerSlot = requirePositiveInteger(response.signerSlot, 'response.signerSlot');
  const thresholdSessionId = requireString(
    response.thresholdSessionId,
    'response.thresholdSessionId',
  );
  const signingWorkerId = requireString(response.signingWorkerId, 'response.signingWorkerId');
  const thresholdExpiresAtMs = requirePositiveInteger(
    response.thresholdExpiresAtMs,
    'response.thresholdExpiresAtMs',
  );
  const participantIds = requireParticipantIds(response.participantIds);
  const authority = parsePasskeyWalletAuthAuthority(response.authority);
  const authorityRef = parseWalletAuthAuthorityRef(response.authorityRef);
  const expectedAuthority = buildPasskeyWalletAuthAuthority({
    walletId: record.walletId,
    rpId: restore.rpId,
    credentialIdB64u,
  });
  const authorityScope = requireRecord(response.authorityScope, 'response.authorityScope');
  const responseRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(response.runtimePolicyScope, 'response.runtimePolicyScope'),
  );
  const sealedRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(restore.runtimePolicyScope, 'ed25519Restore.runtimePolicyScope'),
  );
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    response.routerAbNormalSigning,
  );
  const walletSessionId = parseWalletSessionId(response.walletSessionId);
  const authorizationId = walletSessionAuthorizationIdForCurve(args.authorization, 'ed25519');
  const quotaId = parseMpcWalletSigningQuotaId(response.quotaId);
  const capability = parseEd25519YaoRecoveryCapabilityV1(response.capability);
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ed25519');
  const authorizationThresholdSessionId = walletSessionThresholdSessionIdForCurve(
    args.authorization,
    'ed25519',
  );
  const expectedAuthorityRef = authority ? await walletAuthAuthorityRef({ authority }) : null;
  if (
    !authority ||
    !authorityRef ||
    !expectedAuthorityRef ||
    authorityRef.walletId !== expectedAuthorityRef.walletId ||
    authorityRef.authorityDigest !== expectedAuthorityRef.authorityDigest ||
    !walletAuthAuthoritiesMatch(authority, expectedAuthority) ||
    authorityScope.kind !== 'passkey_rp' ||
    !walletSessionId.ok ||
    !authorizationId ||
    !quotaId.ok ||
    String(walletSessionId.value) !== String(args.authorization.walletSessionId) ||
    String(quotaId.value) !== String(args.authorization.quotaId) ||
    authorityRef.authorityDigest !== args.authorization.authority.authorityDigest ||
    authorityScope.rpId !== restore.rpId ||
    !routerAbNormalSigning ||
    walletId !== record.walletId ||
    nearAccountId !== restore.nearAccountId ||
    nearEd25519SigningKeyId !== restore.nearEd25519SigningKeyId ||
    signerSlot !== restore.signerSlot ||
    !authorizationThresholdSessionId ||
    thresholdSessionId !== String(authorizationThresholdSessionId) ||
    !walletSessionToken ||
    signingWorkerId !== restore.relayerKeyId ||
    signingWorkerId !== restore.routerAbNormalSigning.signingWorkerId ||
    routerAbNormalSigning.signingWorkerId !== signingWorkerId ||
    // A renewed Wallet Session may outlive the sealed material. The material
    // expiry remains the upper bound for this restore lane.
    record.expiresAtMs > thresholdExpiresAtMs ||
    participantIds[0] !== restore.participantIds[0] ||
    participantIds[1] !== restore.participantIds[1] ||
    !sameRuntimePolicyScope(responseRuntimePolicyScope, sealedRuntimePolicyScope)
  ) {
    throw new Error('warm recovery bootstrap does not match the exact sealed Ed25519 lane');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(responseRuntimePolicyScope);
  if (!signingRoot) throw new Error('warm recovery bootstrap signing-root scope is invalid');
  if (!walletSessionToken) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  const descriptor: ParsedPasskeyEd25519YaoRecoveryDescriptorV1 = {
    authority: authorityRef,
    walletId: walletIdFromString(walletId),
    nearAccountId: toAccountId(nearAccountId),
    nearEd25519SigningKeyId,
    signerSlot,
    operationalPublicKey: `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`,
    relayerKeyId: signingWorkerId,
    credentialIdB64u,
    session: {
      sessionKind: 'opaque',
      walletSessionToken,
      thresholdSessionId,
      walletSessionId: walletSessionId.value,
      authorizationId,
      quotaId: quotaId.value,
      expiresAtMs: thresholdExpiresAtMs,
      remainingUses: record.remainingUses,
      runtimePolicyScope: responseRuntimePolicyScope,
      participantIds,
      routerAbNormalSigning,
    },
    capability,
  };
  assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity(
    descriptor,
    restore.materialActivation,
  );
  return descriptor;
}

async function parseDelegatedWarmRecoveryDescriptor(args: {
  readonly subject: Extract<
    PasskeyEd25519WarmRecoverySubject,
    { readonly kind: 'delegated_active_bundle' }
  >;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly response: Record<string, unknown>;
  readonly nowMs: number;
}): Promise<ParsedPasskeyEd25519YaoRecoveryDescriptorV1> {
  const response = args.response;
  const subject = args.subject;
  const bundle = subject.bundle;
  const execution = activeLinkedDeviceEd25519ExecutionForExport(bundle);
  const root = delegatedPasskeyRootBindingForSubject(subject, args.nowMs);
  exactResponseKeys(response, LINKED_DEVICE_WARM_RECOVERY_RESPONSE_KEYS);
  if (response.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('linked Device 2 warm recovery bootstrap response kind is invalid');
  }
  const walletId = requireString(response.walletId, 'response.walletId');
  const nearAccountId = requireString(response.nearAccountId, 'response.nearAccountId');
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'response.nearEd25519SigningKeyId',
  );
  const signerSlot = requirePositiveInteger(response.signerSlot, 'response.signerSlot');
  const thresholdSessionId = requireString(
    response.thresholdSessionId,
    'response.thresholdSessionId',
  );
  const signingWorkerId = requireString(response.signingWorkerId, 'response.signingWorkerId');
  const thresholdExpiresAtMs = requirePositiveInteger(
    response.thresholdExpiresAtMs,
    'response.thresholdExpiresAtMs',
  );
  const participantIds = requireParticipantIds(response.participantIds);
  const responseRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(response.runtimePolicyScope, 'response.runtimePolicyScope'),
  );
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    response.routerAbNormalSigning,
  );
  const walletSessionId = parseWalletSessionId(response.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(response.quotaId);
  const capability = parseEd25519YaoRecoveryCapabilityV1(response.capability);
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ed25519');
  const authorizationId = walletSessionAuthorizationIdForCurve(args.authorization, 'ed25519');
  const expectedParticipantIds =
    subject.sourceOwnerCapability.ownerParticipantContinuity.participantIds;
  const expectedSigningWorkerId = String(
    subject.sourceOwnerCapability.ownerParticipantContinuity.signingWorkerId,
  );
  const expectedPublicKey = base64UrlEncode(Uint8Array.from(capability.registeredPublicKey));
  const signingRoot = signingRootScopeFromRuntimePolicyScope(responseRuntimePolicyScope);
  if (
    !signingRoot ||
    !routerAbNormalSigning ||
    !walletSessionToken ||
    !authorizationId ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    walletId !== subject.walletId ||
    nearAccountId !== subject.nearAccountId ||
    nearEd25519SigningKeyId !== subject.nearEd25519SigningKeyId ||
    signerSlot !== subject.signerSlot ||
    signingWorkerId !== expectedSigningWorkerId ||
    routerAbNormalSigning.signingWorkerId !== signingWorkerId ||
    participantIds[0] !== expectedParticipantIds[0] ||
    participantIds[1] !== expectedParticipantIds[1] ||
    String(walletSessionId.value) !== String(args.authorization.walletSessionId) ||
    String(walletSessionId.value) !== String(bundle.walletSessionId) ||
    String(quotaId.value) !== String(args.authorization.quotaId) ||
    String(quotaId.value) !== String(bundle.quotaId) ||
    String(authorizationId) !== String(bundle.authorizationId) ||
    thresholdExpiresAtMs <= args.nowMs ||
    thresholdExpiresAtMs > bundle.expiresAtMs ||
    capability.applicationBinding.wallet_id !== subject.walletId ||
    capability.applicationBinding.near_ed25519_signing_key_id !== subject.nearEd25519SigningKeyId ||
    capability.applicationBinding.key_creation_signer_slot !== subject.signerSlot ||
    capability.nearAccountId !== subject.nearAccountId ||
    capability.lifecycle.thresholdSessionId !== thresholdSessionId ||
    capability.lifecycle.signingWorkerId !== signingWorkerId ||
    capability.participantIds[0] !== participantIds[0] ||
    capability.participantIds[1] !== participantIds[1] ||
    expectedPublicKey !== root.identity.registeredPublicKeyB64u
  ) {
    throw new Error('linked Device 2 warm recovery bootstrap does not match the exact export lane');
  }
  const descriptor: ParsedPasskeyEd25519YaoRecoveryDescriptorV1 = {
    authority: args.authorization.authority,
    walletId: walletIdFromString(walletId),
    nearAccountId: toAccountId(nearAccountId),
    nearEd25519SigningKeyId,
    signerSlot,
    operationalPublicKey: `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`,
    relayerKeyId: signingWorkerId,
    credentialIdB64u: root.credentialIdB64u,
    session: {
      sessionKind: 'opaque',
      walletSessionToken,
      thresholdSessionId,
      walletSessionId: walletSessionId.value,
      authorizationId,
      quotaId: quotaId.value,
      expiresAtMs: thresholdExpiresAtMs,
      remainingUses: bundle.remainingUses,
      runtimePolicyScope: responseRuntimePolicyScope,
      participantIds,
      routerAbNormalSigning,
    },
    capability,
  };
  if (
    !mpcMaterialActivationRefsEqual(
      capability.materialActivation,
      subject.sourceMaterialActivation,
    )
  ) {
    throw new Error('linked Device 2 warm recovery bootstrap changed material activation');
  }
  assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity(
    descriptor,
    subject.sourceMaterialActivation,
  );
  return descriptor;
}

export async function resolvePasskeyEd25519YaoExportContextV1(input: {
  readonly subject: PasskeyEd25519WarmRecoverySubject;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
  return await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(input, {
    readExactEd25519SealedSession,
    readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
      walletSessionAuthorizations,
    ),
    nowMs: Date.now,
  });
}

export async function resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
  input: {
    readonly subject: PasskeyEd25519WarmRecoverySubject;
    readonly relayerUrl: string;
    readonly fetch: typeof fetch;
  },
  runtime: PasskeyEd25519RecordRuntimePorts,
): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
  if (input.subject.kind === 'delegated_active_bundle') {
    const walletId = parseWalletId(input.subject.walletId);
    if (!walletId.ok) {
      throw new Error('[SigningEngine][near] delegated Ed25519 wallet identity is invalid');
    }
    const nowMs = runtime.nowMs();
    const authorizationRead = await runtime.readActiveWalletSessionAuthorization(walletId.value);
    const authorization = await requireDelegatedPasskeyExportAuthorization({
      subject: input.subject,
      authorizationRead,
      nowMs,
    });
    if (!authorization) {
      return {
        kind: 'capability_recovery_required',
        reason: 'wallet_session_expired',
      };
    }
    const root = delegatedPasskeyRootBindingForSubject(input.subject, nowMs);
    const bootstrap = await fetchWarmRecoveryBootstrap({
      request: delegatedWarmRecoveryBootstrapRequest(input.subject, authorization),
      authorization,
      relayerUrl: input.relayerUrl,
      fetch: input.fetch,
    });
    if (bootstrap.kind === 'unavailable') {
      return {
        kind: 'capability_recovery_required',
        reason: bootstrap.reason,
      };
    }
    const descriptor = await parseDelegatedWarmRecoveryDescriptor({
      subject: input.subject,
      authorization,
      response: bootstrap.response,
      nowMs,
    });
    const walletCustodyEnvelope = await readEd25519YaoClientRootEnvelopeV1(root.identity);
    if (!walletCustodyEnvelope) {
      return {
        kind: 'capability_recovery_required',
        reason: 'wallet_custody_envelope_missing',
      };
    }
    if (
      walletCustodyEnvelope.binding.registeredPublicKeyB64u !==
        root.identity.registeredPublicKeyB64u ||
      base64UrlEncode(Uint8Array.from(descriptor.capability.registeredPublicKey)) !==
        root.identity.registeredPublicKeyB64u
    ) {
      throw new Error('delegated Ed25519 export root envelope is bound to another key');
    }
    return {
      kind: 'ready',
      context: {
        kind: 'passkey_ed25519_yao_export_context_v1',
        selectedLaneMaterialActivation: input.subject.targetMaterialActivation,
        material: {
          authority: descriptor.authority,
          walletId: descriptor.walletId,
          nearAccountId: descriptor.nearAccountId,
          nearEd25519SigningKeyId: descriptor.nearEd25519SigningKeyId,
          signerSlot: descriptor.signerSlot,
          operationalPublicKey: descriptor.operationalPublicKey,
          relayerKeyId: descriptor.relayerKeyId,
          credentialIdB64u: descriptor.credentialIdB64u,
          capability: descriptor.capability,
        },
        authorization,
        relayerUrl: input.relayerUrl,
        rpId: root.rpId,
        walletCustodyEnvelope,
      },
    };
  }
  const exactRecord = await resolveExactWarmRecoveryRecord(input.subject, runtime);
  if (exactRecord.kind === 'unavailable') {
    return {
      kind: 'capability_recovery_required',
      reason: exactRecord.reason,
    };
  }
  const walletId = parseWalletId(exactRecord.record.walletId);
  if (!walletId.ok) {
    throw new Error('[SigningEngine][near] sealed Ed25519 wallet identity is invalid');
  }
  const authorizationRead = await runtime.readActiveWalletSessionAuthorization(walletId.value);
  const authorization = await requirePasskeyEd25519RestoreAuthorization({
    record: exactRecord.record,
    authorizationRead,
    nowMs: runtime.nowMs(),
  });
  if (!authorization) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_session_expired',
    };
  }
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(authorization, 'ed25519');
  if (!thresholdSessionId) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_session_expired',
    };
  }
  const bootstrap = await fetchWarmRecoveryBootstrap({
    request: ownerWarmRecoveryBootstrapRequest(exactRecord.record, thresholdSessionId),
    authorization,
    relayerUrl: input.relayerUrl,
    fetch: input.fetch,
  });
  if (bootstrap.kind === 'unavailable') {
    return {
      kind: 'capability_recovery_required',
      reason: bootstrap.reason,
    };
  }
  const descriptor = await parseWarmRecoveryDescriptor({
    record: exactRecord.record,
    authorization,
    response: bootstrap.response,
  });
  const walletCustodyEnvelope = await readEd25519YaoExportEnvelopeForPasskeyV1({
    walletId: String(descriptor.walletId),
    credentialIdB64u: descriptor.credentialIdB64u,
  });
  if (!walletCustodyEnvelope) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_custody_envelope_missing',
    };
  }
  return {
    kind: 'ready',
    context: {
      kind: 'passkey_ed25519_yao_export_context_v1',
      selectedLaneMaterialActivation: descriptor.capability.materialActivation,
      material: {
        authority: descriptor.authority,
        walletId: descriptor.walletId,
        nearAccountId: descriptor.nearAccountId,
        nearEd25519SigningKeyId: descriptor.nearEd25519SigningKeyId,
        signerSlot: descriptor.signerSlot,
        operationalPublicKey: descriptor.operationalPublicKey,
        relayerKeyId: descriptor.relayerKeyId,
        credentialIdB64u: descriptor.credentialIdB64u,
        capability: descriptor.capability,
      },
      authorization,
      relayerUrl: input.relayerUrl,
      rpId: exactRecord.record.ed25519Restore.rpId,
      walletCustodyEnvelope,
    },
  };
}
