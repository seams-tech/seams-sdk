import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  NonceCoordinatorDegradationReason,
  NonceCoordinatorFallback,
  NonceLeaseState,
  type NonceCoordinatorDegradation,
  type NonceCoordinatorDiagnostics,
  type NonceCoordinatorOutcomeMetrics,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  ReusableWalletSessionState,
  WalletSession,
  WalletSessionAppIdentity,
  WalletSessionCapabilityLaneReadiness,
  WalletSessionCapabilityProjection,
  WalletSessionCapabilityReadiness,
  WalletSessionIdentityResolveFailure,
  WalletAuthenticationState,
} from '@/core/types/seams';
import type { WalletSessionId } from '@/core/types/sdkSentEvents';
import {
  parseCapabilityInstanceRef,
  parseWalletAuthMethodId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type WalletSessionAuthorizationId,
} from '@shared/authorization/capabilityKinds';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import { isWalletAuthMethod, type WalletAuthMethod } from '@shared/utils/signerDomain';
import {
  walletAuthMethodBindingFromRaw,
  type WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

type WalletIframeExactSessionIdentityBase = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly expiresAtMs: number;
};

export type WalletIframeExactSessionIdentity = WalletIframeExactSessionIdentityBase & {
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly authMethod: WalletAuthMethod;
};

export type WalletIframeExactSessionIdentityInput = {
  readonly walletId: string;
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly authMethod: WalletAuthMethod;
  readonly expiresAtMs: number;
};

export type WalletIframeSessionUnavailableReason =
  | 'exhausted'
  | 'absent'
  | 'not_found'
  | 'unavailable'
  | 'status_unknown'
  // Replaced rather than broken: the host discards what it holds and reads
  // current state again. Collapsing this into `invalid` sent a routine
  // replacement down an error path.
  | 'superseded'
  | 'invalid';

export type WalletIframeExactSessionState =
  | { readonly kind: 'wallet_locked' }
  | {
      readonly kind: 'wallet_authenticated_identity_unresolvable';
      readonly walletId: WalletId;
      readonly reason: WalletSessionIdentityResolveFailure | 'invalid';
    }
  | {
      readonly kind: 'wallet_unlocked_without_signing_session';
      readonly walletId: WalletId;
      readonly reason: Exclude<WalletIframeSessionUnavailableReason, 'not_found'>;
    }
  | {
      readonly kind: 'wallet_unlocked_without_signing_session';
      readonly walletId: WalletId;
      readonly reason: 'not_found';
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
    }
  | ({
      readonly kind: 'active_session';
      readonly status: 'active';
    } & WalletIframeExactSessionIdentity)
  | ({ readonly kind: 'expired_session' } & WalletIframeExactSessionIdentity);

export type WalletIframePendingSessionBinding =
  | { readonly kind: 'unbound' }
  | ({ readonly kind: 'exact_session' } & WalletIframeExactSessionIdentity);

export type WalletIframeSessionExpiredFailure = {
  readonly kind: 'wallet_iframe_request_failure';
  readonly code: 'wallet_session_expired';
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
};

export type WalletIframeExactSessionLockResult =
  | {
      readonly kind: 'locked';
      readonly identity: WalletIframeExactSessionIdentity;
    }
  | {
      readonly kind: 'stale_session';
      readonly expected: WalletIframeExactSessionIdentity;
      readonly current: WalletIframeExactSessionState;
    };

export class WalletIframeSessionExpiredRequestError extends Error {
  readonly failure: WalletIframeSessionExpiredFailure;

  constructor(failure: WalletIframeSessionExpiredFailure) {
    super('Wallet session expired');
    this.name = 'WalletIframeSessionExpiredRequestError';
    this.failure = failure;
  }
}

export function exactSessionStateFromWalletSession(
  session: WalletSession,
): WalletIframeExactSessionState {
  if (session.authentication.kind === 'signed_out') return { kind: 'wallet_locked' };
  const authenticatedWalletId = session.authentication.walletId;
  if (session.appIdentity.kind === 'anonymous') {
    return {
      kind: 'wallet_authenticated_identity_unresolvable',
      walletId: authenticatedWalletId,
      reason: 'invalid',
    };
  }
  if (session.appIdentity.kind === 'unresolvable') {
    return {
      kind: 'wallet_authenticated_identity_unresolvable',
      walletId: authenticatedWalletId,
      reason:
        session.appIdentity.walletId === authenticatedWalletId
          ? session.appIdentity.reason
          : 'invalid',
    };
  }
  const walletId = session.appIdentity.walletId;
  if (!walletSessionWalletIdsAgree(session, walletId)) {
    return {
      kind: 'wallet_authenticated_identity_unresolvable',
      walletId: authenticatedWalletId,
      reason: 'invalid',
    };
  }
  const reusableWalletSession = session.reusableWalletSession;
  switch (reusableWalletSession.kind) {
    case 'active': {
      const identity = exactIdentity(walletId, reusableWalletSession);
      if (identity === null) return unavailableSession(walletId, 'invalid');
      return { kind: 'active_session', status: 'active', ...identity };
    }
    case 'expired': {
      const identity = exactIdentity(walletId, reusableWalletSession);
      if (identity === null) return unavailableSession(walletId, 'invalid');
      return { kind: 'expired_session', ...identity };
    }
    case 'exhausted':
      return unavailableSession(walletId, 'exhausted');
    case 'superseded':
      return unavailableSession(walletId, 'superseded');
    case 'missing':
      return {
        kind: 'wallet_unlocked_without_signing_session',
        walletId,
        reason: 'not_found',
        authorizationId: reusableWalletSession.authorizationId,
        walletSessionId: reusableWalletSession.walletSessionId,
        authMethod: reusableWalletSession.authMethod,
      };
    case 'unavailable':
      return unavailableSession(walletId, 'unavailable');
    case 'invalid':
      return unavailableSession(walletId, 'invalid');
    case 'absent':
      return unavailableSession(walletId, 'absent');
  }
  reusableWalletSession satisfies never;
  return { kind: 'wallet_locked' };
}

export function parseWalletIframeExactSessionState(value: unknown): WalletIframeExactSessionState {
  if (!isRecord(value)) throw new Error('Wallet iframe exact session state must be an object');
  switch (value.kind) {
    case 'wallet_locked':
      return { kind: 'wallet_locked' };
    case 'wallet_authenticated_identity_unresolvable':
      return {
        kind: value.kind,
        walletId: requireWalletId(value.walletId),
        reason:
          value.reason === 'invalid' ? 'invalid' : requireIdentityResolveFailure(value.reason),
      };
    case 'wallet_unlocked_without_signing_session': {
      const walletId = requireWalletId(value.walletId);
      const reason = requireUnavailableReason(value.reason);
      if (reason !== 'not_found') return { kind: value.kind, walletId, reason };
      const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
      const walletSessionId = parseWalletSessionId(value.walletSessionId);
      if (!authorizationId.ok) {
        throw new Error('Wallet iframe missing authorization ID is invalid');
      }
      if (!walletSessionId.ok) {
        throw new Error('Wallet iframe missing Wallet Session ID is invalid');
      }
      assertDistinctAuthorizationIdentity(authorizationId.value, walletSessionId.value);
      if (!isWalletAuthMethod(value.authMethod)) {
        throw new Error('Wallet iframe missing auth method is invalid');
      }
      return {
        kind: value.kind,
        walletId,
        reason,
        authorizationId: authorizationId.value,
        walletSessionId: walletSessionId.value,
        authMethod: value.authMethod,
      };
    }
    case 'active_session': {
      const identity = parseIdentity(value);
      if (value.status !== 'active') {
        throw new Error('Wallet iframe active session status is invalid');
      }
      return { kind: value.kind, status: 'active', ...identity };
    }
    case 'expired_session':
      return { kind: value.kind, ...parseIdentity(value) };
    default:
      throw new Error('Wallet iframe exact session state kind is invalid');
  }
}

export function parseWalletSessionFromBoundary(
  value: unknown,
  expectedWalletId?: unknown,
): WalletSession {
  const record = requireRecord(value, 'Wallet Session');
  const appIdentity = parseWalletSessionAppIdentity(record.appIdentity);
  const authentication = parseWalletAuthenticationState(record.authentication);
  const reusableWalletSession = parseReusableWalletSession(record.reusableWalletSession);
  const capabilityProjection = parseWalletSessionCapabilityProjection(record.capabilityProjection);
  const parsed: WalletSession = {
    appIdentity,
    authentication,
    reusableWalletSession,
    capabilityProjection,
    nonceDiagnostics: parseNullableNonceDiagnostics(record.nonceDiagnostics),
  };
  const expected = expectedWalletId === undefined ? null : requireWalletId(expectedWalletId);
  const canonicalWalletId = walletSessionCanonicalWalletId(parsed);
  if (expected !== null && canonicalWalletId === null) {
    throw new Error('Wallet iframe Wallet Session omitted the requested wallet identity');
  }
  if (expected !== null && canonicalWalletId !== expected) {
    throw new Error('Wallet iframe Wallet Session does not match the requested wallet');
  }
  if (canonicalWalletId !== null && !walletSessionWalletIdsAgree(parsed, canonicalWalletId)) {
    throw new Error('Wallet iframe Wallet Session wallet identities disagree');
  }
  return parsed;
}

function parseWalletAuthenticationState(value: unknown): WalletAuthenticationState {
  const record = requireRecord(value, 'Wallet Session authentication');
  switch (record.kind) {
    case 'signed_out':
      return { kind: 'signed_out' };
    case 'authenticated':
      if (!isWalletAuthMethod(record.authMethod)) {
        throw new Error('Wallet Session authentication method is invalid');
      }
      return {
        kind: 'authenticated',
        walletId: requireWalletId(record.walletId),
        authMethod: record.authMethod,
      };
    default:
      throw new Error('Wallet Session authentication kind is invalid');
  }
}

export function parseWalletIframeExactSessionIdentity(
  value: unknown,
): WalletIframeExactSessionIdentity {
  if (!isRecord(value)) throw new Error('Wallet iframe exact session identity must be an object');
  return parseIdentity(value);
}

export function parseWalletIframeExactSessionLockResult(
  value: unknown,
): WalletIframeExactSessionLockResult {
  if (!isRecord(value))
    throw new Error('Wallet iframe exact session lock result must be an object');
  switch (value.kind) {
    case 'locked':
      return {
        kind: 'locked',
        identity: parseWalletIframeExactSessionIdentity(value.identity),
      };
    case 'stale_session':
      return {
        kind: 'stale_session',
        expected: parseWalletIframeExactSessionIdentity(value.expected),
        current: parseWalletIframeExactSessionState(value.current),
      };
    default:
      throw new Error('Wallet iframe exact session lock result kind is invalid');
  }
}

function parseWalletSessionAppIdentity(value: unknown): WalletSessionAppIdentity {
  const record = requireRecord(value, 'Wallet Session appIdentity');
  switch (record.kind) {
    case 'anonymous':
      return { kind: 'anonymous' };
    case 'unresolvable':
      return {
        kind: 'unresolvable',
        walletId: requireWalletId(record.walletId),
        reason: requireIdentityResolveFailure(record.reason),
      };
    case 'resolved': {
      const walletId = requireWalletId(record.walletId);
      const authMethods = requireArray(record.authMethods, 'Wallet Session authMethods').map(
        parseWalletAuthMethodBinding,
      );
      for (const binding of authMethods) {
        if (walletIdFromAuthBinding(binding) !== walletId) {
          throw new Error('Wallet Session auth-method wallet identity disagrees');
        }
      }
      return {
        kind: 'resolved',
        walletId,
        nearAccountId:
          record.nearAccountId === null
            ? null
            : toAccountId(requireNonEmptyString(record.nearAccountId, 'nearAccountId')),
        nearOperationalPublicKey: requireNullableString(
          record.nearOperationalPublicKey,
          'nearOperationalPublicKey',
        ),
        userData: parseNullableClientUserData(record.userData, walletId),
        authMethods,
        thresholdEcdsaEthereumAddress: requireNullableString(
          record.thresholdEcdsaEthereumAddress,
          'thresholdEcdsaEthereumAddress',
        ),
        thresholdEcdsaPublicKeyB64u: requireNullableString(
          record.thresholdEcdsaPublicKeyB64u,
          'thresholdEcdsaPublicKeyB64u',
        ),
      };
    }
    default:
      throw new Error('Wallet Session appIdentity kind is invalid');
  }
}

function parseReusableWalletSession(value: unknown): ReusableWalletSessionState {
  const record = requireRecord(value, 'reusable Wallet Session');
  switch (record.kind) {
    case 'absent':
      return { kind: 'absent' };
    case 'active':
      return {
        kind: 'active',
        ...parseReusableWalletSessionIdentityWithExpiry(record),
        // R109C: only an active session names the exact credential it was
        // issued to; a retired one is addressed by its authorization id.
        walletAuthMethodId: requireParsedWalletAuthMethodId(
          record.walletAuthMethodId,
          'walletAuthMethodId',
        ),
        remainingUses: requirePositiveSafeInteger(record.remainingUses, 'remainingUses'),
      };
    case 'exhausted':
      if (record.remainingUses !== 0) {
        throw new Error('Exhausted Wallet Session remainingUses must be zero');
      }
      return {
        kind: 'exhausted',
        ...parseReusableWalletSessionIdentityWithExpiry(record),
        remainingUses: 0,
      };
    case 'expired':
      return {
        kind: 'expired',
        ...parseReusableWalletSessionIdentityWithExpiry(record),
        detectedAtMs: requirePositiveSafeInteger(record.detectedAtMs, 'detectedAtMs'),
      };
    case 'missing': {
      const authorizationId = parseWalletSessionAuthorizationId(record.authorizationId);
      const walletSessionId = parseWalletSessionId(record.walletSessionId);
      if (!authorizationId.ok) throw new Error('Reusable authorization ID is invalid');
      if (!walletSessionId.ok) throw new Error('Reusable Wallet Session ID is invalid');
      if (!isWalletAuthMethod(record.authMethod)) {
        throw new Error('Reusable Wallet Session auth method is invalid');
      }
      return {
        kind: 'missing',
        walletId: requireWalletId(record.walletId),
        authorizationId: authorizationId.value,
        walletSessionId: walletSessionId.value,
        authMethod: record.authMethod,
      };
    }
    case 'superseded':
      return {
        kind: 'superseded',
        ...parseReusableWalletSessionIdentity(record),
        detectedAtMs: requirePositiveSafeInteger(record.detectedAtMs, 'detectedAtMs'),
      };
    case 'unavailable':
      if (record.reason !== 'persistence_unavailable') {
        throw new Error('Unavailable Wallet Session reason is invalid');
      }
      return {
        kind: 'unavailable',
        walletId: requireWalletId(record.walletId),
        reason: record.reason,
      };
    case 'invalid':
      return {
        kind: 'invalid',
        walletId: requireWalletId(record.walletId),
        reason: requireInvalidWalletSessionReason(record.reason),
      };
    default:
      throw new Error('Reusable Wallet Session kind is invalid');
  }
}

/** Who the session belongs to. Separate from its budget, because a superseded
 * session still names its wallet and factor but no longer has an expiry that
 * governs anything. */
function parseReusableWalletSessionIdentity(
  record: Record<string, unknown>,
): Pick<
  Extract<ReusableWalletSessionState, { kind: 'active' }>,
  'walletId' | 'authorizationId' | 'walletSessionId' | 'authMethod'
> {
  const authorizationId = parseWalletSessionAuthorizationId(record.authorizationId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  if (!authorizationId.ok) throw new Error('Reusable authorization ID is invalid');
  if (!walletSessionId.ok) throw new Error('Reusable Wallet Session ID is invalid');
  assertDistinctAuthorizationIdentity(authorizationId.value, walletSessionId.value);
  if (!isWalletAuthMethod(record.authMethod)) {
    throw new Error('Reusable Wallet Session auth method is invalid');
  }
  return {
    walletId: requireWalletId(record.walletId),
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    authMethod: record.authMethod,
  };
}

function requireParsedWalletAuthMethodId(value: unknown, field: string): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(requireNonEmptyString(value, field));
  if (!parsed.ok) throw new Error(`${field} is not a wallet auth method id`);
  return parsed.value;
}

function parseReusableWalletSessionIdentityWithExpiry(
  record: Record<string, unknown>,
): Pick<
  Extract<ReusableWalletSessionState, { kind: 'active' }>,
  'walletId' | 'authorizationId' | 'walletSessionId' | 'authMethod' | 'expiresAtMs'
> {
  return {
    ...parseReusableWalletSessionIdentity(record),
    expiresAtMs: requirePositiveSafeInteger(record.expiresAtMs, 'expiresAtMs'),
  };
}

function parseWalletSessionCapabilityProjection(value: unknown): WalletSessionCapabilityProjection {
  const record = requireRecord(value, 'Wallet Session capabilityProjection');
  switch (record.kind) {
    case 'not_requested':
      return { kind: 'not_requested' };
    case 'unresolvable':
      return {
        kind: 'unresolvable',
        reason: requireIdentityResolveFailure(record.reason),
      };
    case 'resolved': {
      const subjectSet = parseWalletUnlockSubjectSet(record.subjectSet);
      const capabilityValues = requireNonEmptyArray(
        record.capabilities,
        'Wallet Session capabilities',
      );
      const capabilities = capabilityValues.map(parseWalletSessionCapabilityReadiness);
      for (const capability of capabilities) {
        if (capability.subject.walletId !== subjectSet.walletId) {
          throw new Error('Wallet Session capability wallet identity disagrees');
        }
      }
      return {
        kind: 'resolved',
        subjectSet,
        capabilities: requireNonEmptyCapabilities(capabilities),
      };
    }
    default:
      throw new Error('Wallet Session capabilityProjection kind is invalid');
  }
}

function parseWalletUnlockSubjectSet(
  value: unknown,
): Extract<WalletSessionCapabilityProjection, { kind: 'resolved' }>['subjectSet'] {
  const record = requireRecord(value, 'wallet unlock subject set');
  if (record.kind !== 'wallet_unlock_subject_set') {
    throw new Error('Wallet unlock subject set kind is invalid');
  }
  const walletId = requireWalletId(record.walletId);
  const values = requireNonEmptyArray(record.subjects, 'wallet unlock subjects');
  const subjects = values.map(parseWalletUnlockSubject);
  for (const subject of subjects) {
    if (subject.walletId !== walletId) {
      throw new Error('Wallet unlock subject wallet identity disagrees');
    }
  }
  const first = subjects[0];
  if (!first) throw new Error('Wallet unlock subject set must be non-empty');
  return {
    kind: 'wallet_unlock_subject_set',
    walletId,
    subjects: [first, ...subjects.slice(1)],
  };
}

function parseWalletUnlockSubject(
  value: unknown,
): Extract<
  WalletSessionCapabilityProjection,
  { kind: 'resolved' }
>['subjectSet']['subjects'][number] {
  const record = requireRecord(value, 'wallet unlock subject');
  const walletId = requireWalletId(record.walletId);
  switch (record.kind) {
    case 'near_ed25519_wallet': {
      const signerSlot = parseSignerSlot(record.signerSlot);
      if (signerSlot === null) throw new Error('Wallet unlock signerSlot is invalid');
      return {
        kind: 'near_ed25519_wallet',
        walletId,
        nearAccountId: toAccountId(requireNonEmptyString(record.nearAccountId, 'nearAccountId')),
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(record.nearEd25519SigningKeyId),
        signerSlot,
      };
    }
    case 'evm_family_ecdsa_wallet': {
      const capability = parseCapabilityInstanceRef(record.capability);
      if (!capability.ok) throw new Error(capability.error.message);
      const authority = parseWalletAuthAuthorityRef(record.authority);
      if (!authority || authority.walletId !== walletId) {
        throw new Error('Wallet unlock ECDSA authority is invalid');
      }
      return {
        kind: 'evm_family_ecdsa_wallet',
        walletId,
        capability: capability.value,
        authority,
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
      };
    }
    default:
      throw new Error('Wallet unlock subject kind is invalid');
  }
}

function parseWalletSessionCapabilityReadiness(value: unknown): WalletSessionCapabilityReadiness {
  const record = requireRecord(value, 'Wallet Session capability readiness');
  switch (record.kind) {
    case 'near_ed25519':
      return {
        kind: 'near_ed25519',
        subject: parseNearWalletUnlockSubject(record.subject),
        lane: parseWalletSessionCapabilityLaneReadiness(record.lane),
      };
    case 'evm_family_ecdsa':
      return {
        kind: 'evm_family_ecdsa',
        subject: parseEcdsaWalletUnlockSubject(record.subject),
        targets: parseEcdsaCapabilityTargets(record.targets),
      };
    default:
      throw new Error('Wallet Session capability readiness kind is invalid');
  }
}

function parseNearWalletUnlockSubject(
  value: unknown,
): Extract<WalletSessionCapabilityReadiness, { kind: 'near_ed25519' }>['subject'] {
  const subject = parseWalletUnlockSubject(value);
  if (subject.kind !== 'near_ed25519_wallet') {
    throw new Error('Near capability requires a Near wallet subject');
  }
  return subject;
}

function parseEcdsaWalletUnlockSubject(
  value: unknown,
): Extract<WalletSessionCapabilityReadiness, { kind: 'evm_family_ecdsa' }>['subject'] {
  const subject = parseWalletUnlockSubject(value);
  if (subject.kind !== 'evm_family_ecdsa_wallet') {
    throw new Error('ECDSA capability requires an ECDSA wallet subject');
  }
  return subject;
}

function parseEcdsaCapabilityTargets(
  value: unknown,
): Extract<WalletSessionCapabilityReadiness, { kind: 'evm_family_ecdsa' }>['targets'] {
  const record = requireRecord(value, 'ECDSA capability targets');
  switch (record.kind) {
    case 'no_configured_target':
      return { kind: 'no_configured_target' };
    case 'configured_targets': {
      const laneValues = requireNonEmptyArray(record.lanes, 'ECDSA capability target lanes');
      const lanes = laneValues.map(parseEcdsaCapabilityTargetLane);
      const first = lanes[0];
      if (!first) throw new Error('ECDSA capability target lanes must be non-empty');
      return {
        kind: 'configured_targets',
        lanes: [first, ...lanes.slice(1)],
      };
    }
    default:
      throw new Error('ECDSA capability targets kind is invalid');
  }
}

function parseEcdsaCapabilityTargetLane(value: unknown): {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly readiness: WalletSessionCapabilityLaneReadiness;
} {
  const record = requireRecord(value, 'ECDSA capability target lane');
  return {
    chainTarget: thresholdEcdsaChainTargetFromRequest(
      requireRecord(record.chainTarget, 'ECDSA chain target'),
    ),
    readiness: parseWalletSessionCapabilityLaneReadiness(record.readiness),
  };
}

function parseWalletSessionCapabilityLaneReadiness(
  value: unknown,
): WalletSessionCapabilityLaneReadiness {
  const record = requireRecord(value, 'Wallet Session capability lane readiness');
  switch (record.kind) {
    case 'ready':
      return { kind: 'ready' };
    case 'pending':
      return { kind: 'pending', resume: requireCapabilityLaneResume(record.resume) };
    case 'authorization_required':
      return {
        kind: 'authorization_required',
        requirement: requireCapabilityLaneAuthorizationRequirement(record.requirement),
      };
    case 'superseded':
      if (record.replacement !== 're_resolve_current_capability') {
        throw new Error('Superseded capability lane replacement is invalid');
      }
      return { kind: 'superseded', replacement: record.replacement };
    case 'failed':
      return { kind: 'failed', reason: requireFailedCapabilityLaneReason(record.reason) };
    default:
      throw new Error('Wallet Session capability lane readiness kind is invalid');
  }
}

function requireCapabilityLaneResume(
  value: unknown,
): Extract<WalletSessionCapabilityLaneReadiness, { kind: 'pending' }>['resume'] {
  if (value === 'restore_material' || value === 'resolve_deferred_state') return value;
  throw new Error('Pending capability lane resume action is invalid');
}

function requireCapabilityLaneAuthorizationRequirement(
  value: unknown,
): Extract<
  WalletSessionCapabilityLaneReadiness,
  { kind: 'authorization_required' }
>['requirement'] {
  switch (value) {
    case 'same_method_step_up':
    case 'wallet_session_expired':
    case 'wallet_session_exhausted':
      return value;
    default:
      throw new Error('Capability lane authorization requirement is invalid');
  }
}

function parseWalletAuthMethodBinding(value: unknown): WalletAuthMethodBinding {
  const parsed = walletAuthMethodBindingFromRaw(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function walletIdFromAuthBinding(binding: WalletAuthMethodBinding): WalletId {
  switch (binding.kind) {
    case 'passkey':
      return binding.scope.wallet.walletId;
    case 'email_otp':
      return binding.wallet.walletId;
  }
  binding satisfies never;
  throw new Error('Wallet auth-method binding kind is invalid');
}

function parseNullableClientUserData(
  value: unknown,
  expectedWalletId: WalletId,
): Extract<WalletSessionAppIdentity, { kind: 'resolved' }>['userData'] {
  if (value === null) return null;
  const record = requireRecord(value, 'Wallet Session userData');
  const walletId = requireWalletId(record.walletId);
  if (walletId !== expectedWalletId) {
    throw new Error('Wallet Session userData wallet identity disagrees');
  }
  const passkeyCredential = requireRecord(record.passkeyCredential, 'passkeyCredential');
  const signerSlot = parseSignerSlot(record.signerSlot);
  if (signerSlot === null) throw new Error('Wallet Session userData signerSlot is invalid');
  const authMethod = parseNullableWalletAuthMethod(record.authMethod);
  return {
    walletId,
    nearAccountId: toAccountId(
      requireNonEmptyString(record.nearAccountId, 'userData.nearAccountId'),
    ),
    loginDisplayName: requireNonEmptyString(record.loginDisplayName, 'userData.loginDisplayName'),
    signerSlot,
    ...(record.version === undefined
      ? {}
      : { version: requireNonNegativeSafeInteger(record.version, 'userData.version') }),
    ...(record.registeredAt === undefined
      ? {}
      : {
          registeredAt: requireNonNegativeSafeInteger(record.registeredAt, 'userData.registeredAt'),
        }),
    ...(record.lastLogin === undefined
      ? {}
      : {
          lastLogin: requireNonNegativeSafeInteger(record.lastLogin, 'userData.lastLogin'),
        }),
    ...(record.lastUpdated === undefined
      ? {}
      : {
          lastUpdated: requireNonNegativeSafeInteger(record.lastUpdated, 'userData.lastUpdated'),
        }),
    operationalPublicKey: requireNonEmptyString(
      record.operationalPublicKey,
      'userData.operationalPublicKey',
    ),
    nearEd25519SigningKeyId: requireNonEmptyString(
      record.nearEd25519SigningKeyId,
      'userData.nearEd25519SigningKeyId',
    ),
    passkeyCredential: {
      id: requireNonEmptyString(passkeyCredential.id, 'passkeyCredential.id'),
      rawId: requireNonEmptyString(passkeyCredential.rawId, 'passkeyCredential.rawId'),
    },
    ...(authMethod === undefined ? {} : { authMethod }),
    ...(record.preferences === undefined
      ? {}
      : { preferences: parseUserPreferences(record.preferences) }),
  };
}

function parseNullableWalletAuthMethod(value: unknown): WalletAuthMethod | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (!isWalletAuthMethod(value)) throw new Error('Wallet Session userData authMethod is invalid');
  return value;
}

function parseUserPreferences(
  value: unknown,
): NonNullable<Extract<WalletSessionAppIdentity, { kind: 'resolved' }>['userData']>['preferences'] {
  const record = requireRecord(value, 'Wallet Session user preferences');
  if (typeof record.useRelayer !== 'boolean') {
    throw new Error('Wallet Session user preferences useRelayer is invalid');
  }
  if (record.useNetwork !== 'testnet' && record.useNetwork !== 'mainnet') {
    throw new Error('Wallet Session user preferences useNetwork is invalid');
  }
  const confirmation = requireRecord(
    record.confirmationConfig,
    'Wallet Session confirmationConfig',
  );
  if (
    confirmation.uiMode !== 'none' &&
    confirmation.uiMode !== 'modal' &&
    confirmation.uiMode !== 'drawer'
  ) {
    throw new Error('Wallet Session confirmationConfig uiMode is invalid');
  }
  if (confirmation.behavior !== 'requireClick' && confirmation.behavior !== 'skipClick') {
    throw new Error('Wallet Session confirmationConfig behavior is invalid');
  }
  const autoProceedDelay =
    confirmation.autoProceedDelay === undefined
      ? undefined
      : requireNonNegativeSafeInteger(
          confirmation.autoProceedDelay,
          'confirmationConfig.autoProceedDelay',
        );
  return {
    useRelayer: record.useRelayer,
    useNetwork: record.useNetwork,
    confirmationConfig: {
      uiMode: confirmation.uiMode,
      behavior: confirmation.behavior,
      ...(autoProceedDelay === undefined ? {} : { autoProceedDelay }),
    },
  };
}

function parseNullableNonceDiagnostics(value: unknown): NonceCoordinatorDiagnostics | null {
  if (value === null) return null;
  const record = requireRecord(value, 'Wallet Session nonce diagnostics');
  const near = requireRecord(record.near, 'near nonce diagnostics');
  return {
    leaseCount: requireNonNegativeSafeInteger(record.leaseCount, 'nonce leaseCount'),
    leasesByState: parseRequiredNonceStateCounts(record.leasesByState),
    laneCount: requireNonNegativeSafeInteger(record.laneCount, 'nonce laneCount'),
    metrics: parseNonceMetrics(record.metrics),
    coordinationWarnings: requireArray(
      record.coordinationWarnings,
      'nonce coordination warnings',
    ).map(parseNonceCoordinationWarning),
    lanes: requireArray(record.lanes, 'nonce diagnostic lanes').map(parseNonceDiagnosticLane),
    near: {
      ...(near.activeAccountId === undefined
        ? {}
        : {
            activeAccountId: requireNonEmptyString(near.activeAccountId, 'near activeAccountId'),
          }),
      ...(near.activePublicKey === undefined
        ? {}
        : {
            activePublicKey: requireNonEmptyString(near.activePublicKey, 'near activePublicKey'),
          }),
      hasContext: requireBoolean(near.hasContext, 'near hasContext'),
      reservedNonceCount: requireNonNegativeSafeInteger(
        near.reservedNonceCount,
        'near reservedNonceCount',
      ),
      ...(near.lastReservedNonce === undefined
        ? {}
        : {
            lastReservedNonce: requireNonEmptyString(
              near.lastReservedNonce,
              'near lastReservedNonce',
            ),
          }),
    },
  };
}

function parseNonceMetrics(value: unknown): NonceCoordinatorDiagnostics['metrics'] {
  const record = requireRecord(value, 'nonce metrics');
  return {
    atMs: requireNonNegativeSafeInteger(record.atMs, 'nonce metrics atMs'),
    ...(record.accountId === undefined
      ? {}
      : { accountId: requireNonEmptyString(record.accountId, 'nonce metrics accountId') }),
    leaseCount: requireNonNegativeSafeInteger(record.leaseCount, 'nonce metrics leaseCount'),
    laneCount: requireNonNegativeSafeInteger(record.laneCount, 'nonce metrics laneCount'),
    oldestLeaseAgeMs: requireNonNegativeSafeInteger(
      record.oldestLeaseAgeMs,
      'nonce metrics oldestLeaseAgeMs',
    ),
    oldestInFlightLeaseAgeMs: requireNonNegativeSafeInteger(
      record.oldestInFlightLeaseAgeMs,
      'nonce metrics oldestInFlightLeaseAgeMs',
    ),
    staleInFlightLeaseCount: requireNonNegativeSafeInteger(
      record.staleInFlightLeaseCount,
      'nonce metrics staleInFlightLeaseCount',
    ),
    staleInFlightLaneCount: requireNonNegativeSafeInteger(
      record.staleInFlightLaneCount,
      'nonce metrics staleInFlightLaneCount',
    ),
    reservedLeaseCount: requireNonNegativeSafeInteger(
      record.reservedLeaseCount,
      'nonce metrics reservedLeaseCount',
    ),
    signedLeaseCount: requireNonNegativeSafeInteger(
      record.signedLeaseCount,
      'nonce metrics signedLeaseCount',
    ),
    broadcastAcceptedLeaseCount: requireNonNegativeSafeInteger(
      record.broadcastAcceptedLeaseCount,
      'nonce metrics broadcastAcceptedLeaseCount',
    ),
    droppedLeaseCount: requireNonNegativeSafeInteger(
      record.droppedLeaseCount,
      'nonce metrics droppedLeaseCount',
    ),
    replacedLeaseCount: requireNonNegativeSafeInteger(
      record.replacedLeaseCount,
      'nonce metrics replacedLeaseCount',
    ),
    reconciledLeaseCount: requireNonNegativeSafeInteger(
      record.reconciledLeaseCount,
      'nonce metrics reconciledLeaseCount',
    ),
    releasedLeaseCount: requireNonNegativeSafeInteger(
      record.releasedLeaseCount,
      'nonce metrics releasedLeaseCount',
    ),
    outcomes: parseNonceOutcomeMetrics(record.outcomes),
  };
}

function parseNonceOutcomeMetrics(value: unknown): NonceCoordinatorOutcomeMetrics {
  const record = requireRecord(value, 'nonce outcome metrics');
  return {
    droppedCount: requireNonNegativeSafeInteger(record.droppedCount, 'droppedCount'),
    replacedCount: requireNonNegativeSafeInteger(record.replacedCount, 'replacedCount'),
    reconciledCount: requireNonNegativeSafeInteger(record.reconciledCount, 'reconciledCount'),
    releasedCount: requireNonNegativeSafeInteger(record.releasedCount, 'releasedCount'),
    expiredCount: requireNonNegativeSafeInteger(record.expiredCount, 'expiredCount'),
    broadcastRejectedCount: requireNonNegativeSafeInteger(
      record.broadcastRejectedCount,
      'broadcastRejectedCount',
    ),
    releaseReasons: parseStringCountMap(record.releaseReasons, 'releaseReasons'),
    reconcileReasons: parseStringCountMap(record.reconcileReasons, 'reconcileReasons'),
    expiryReasons: parseStringCountMap(record.expiryReasons, 'expiryReasons'),
  };
}

function parseStringCountMap(value: unknown, label: string): Record<string, number> {
  const record = requireRecord(value, label);
  const parsed: Record<string, number> = {};
  for (const [key, count] of Object.entries(record)) {
    if (!key) throw new Error(`${label} key must be non-empty`);
    parsed[key] = requireNonNegativeSafeInteger(count, `${label}.${key}`);
  }
  return parsed;
}

function parseNonceCoordinationWarning(value: unknown): NonceCoordinatorDegradation {
  const record = requireRecord(value, 'nonce coordination warning');
  return {
    reason: requireNonceDegradationReason(record.reason),
    ...(record.laneFamily === undefined
      ? {}
      : { laneFamily: requireNonceLaneFamily(record.laneFamily) }),
    ...(record.networkKey === undefined
      ? {}
      : { networkKey: requireNonEmptyString(record.networkKey, 'warning networkKey') }),
    ...(record.accountId === undefined
      ? {}
      : { accountId: requireNonEmptyString(record.accountId, 'warning accountId') }),
    fallback: requireNonceCoordinatorFallback(record.fallback),
  };
}

function parseNonceDiagnosticLane(value: unknown): NonceCoordinatorDiagnostics['lanes'][number] {
  const record = requireRecord(value, 'nonce diagnostic lane');
  const family = requireNonceLaneFamily(record.family);
  const chain = record.chain === undefined ? undefined : requireEvmNonceChain(record.chain);
  if (family === 'near' && (chain !== undefined || record.chainId !== undefined)) {
    throw new Error('Near nonce diagnostic lane cannot contain EVM chain identity');
  }
  return {
    family,
    ...(record.accountId === undefined
      ? {}
      : { accountId: requireNonEmptyString(record.accountId, 'lane accountId') }),
    networkKey: requireNonEmptyString(record.networkKey, 'lane networkKey'),
    ...(chain === undefined ? {} : { chain }),
    ...(record.chainId === undefined
      ? {}
      : { chainId: requireNonNegativeSafeInteger(record.chainId, 'lane chainId') }),
    leaseCount: requireNonNegativeSafeInteger(record.leaseCount, 'lane leaseCount'),
    states: parsePartialNonceStateCounts(record.states),
  };
}

function parseRequiredNonceStateCounts(
  value: unknown,
): NonceCoordinatorDiagnostics['leasesByState'] {
  const record = requireRecord(value, 'nonce state counts');
  return {
    [NonceLeaseState.Reserved]: requireNonceStateCount(record, NonceLeaseState.Reserved),
    [NonceLeaseState.Released]: requireNonceStateCount(record, NonceLeaseState.Released),
    [NonceLeaseState.Expired]: requireNonceStateCount(record, NonceLeaseState.Expired),
    [NonceLeaseState.Signed]: requireNonceStateCount(record, NonceLeaseState.Signed),
    [NonceLeaseState.SignedLeaseExpired]: requireNonceStateCount(
      record,
      NonceLeaseState.SignedLeaseExpired,
    ),
    [NonceLeaseState.BroadcastAccepted]: requireNonceStateCount(
      record,
      NonceLeaseState.BroadcastAccepted,
    ),
    [NonceLeaseState.BroadcastRejected]: requireNonceStateCount(
      record,
      NonceLeaseState.BroadcastRejected,
    ),
    [NonceLeaseState.Finalized]: requireNonceStateCount(record, NonceLeaseState.Finalized),
    [NonceLeaseState.Dropped]: requireNonceStateCount(record, NonceLeaseState.Dropped),
    [NonceLeaseState.Replaced]: requireNonceStateCount(record, NonceLeaseState.Replaced),
    [NonceLeaseState.Reconciled]: requireNonceStateCount(record, NonceLeaseState.Reconciled),
  };
}

function parsePartialNonceStateCounts(
  value: unknown,
): NonceCoordinatorDiagnostics['lanes'][number]['states'] {
  const record = requireRecord(value, 'nonce state counts');
  return {
    ...(record[NonceLeaseState.Reserved] === undefined
      ? {}
      : {
          [NonceLeaseState.Reserved]: requireNonceStateCount(record, NonceLeaseState.Reserved),
        }),
    ...(record[NonceLeaseState.Released] === undefined
      ? {}
      : {
          [NonceLeaseState.Released]: requireNonceStateCount(record, NonceLeaseState.Released),
        }),
    ...(record[NonceLeaseState.Expired] === undefined
      ? {}
      : {
          [NonceLeaseState.Expired]: requireNonceStateCount(record, NonceLeaseState.Expired),
        }),
    ...(record[NonceLeaseState.Signed] === undefined
      ? {}
      : {
          [NonceLeaseState.Signed]: requireNonceStateCount(record, NonceLeaseState.Signed),
        }),
    ...(record[NonceLeaseState.SignedLeaseExpired] === undefined
      ? {}
      : {
          [NonceLeaseState.SignedLeaseExpired]: requireNonceStateCount(
            record,
            NonceLeaseState.SignedLeaseExpired,
          ),
        }),
    ...(record[NonceLeaseState.BroadcastAccepted] === undefined
      ? {}
      : {
          [NonceLeaseState.BroadcastAccepted]: requireNonceStateCount(
            record,
            NonceLeaseState.BroadcastAccepted,
          ),
        }),
    ...(record[NonceLeaseState.BroadcastRejected] === undefined
      ? {}
      : {
          [NonceLeaseState.BroadcastRejected]: requireNonceStateCount(
            record,
            NonceLeaseState.BroadcastRejected,
          ),
        }),
    ...(record[NonceLeaseState.Finalized] === undefined
      ? {}
      : {
          [NonceLeaseState.Finalized]: requireNonceStateCount(record, NonceLeaseState.Finalized),
        }),
    ...(record[NonceLeaseState.Dropped] === undefined
      ? {}
      : {
          [NonceLeaseState.Dropped]: requireNonceStateCount(record, NonceLeaseState.Dropped),
        }),
    ...(record[NonceLeaseState.Replaced] === undefined
      ? {}
      : {
          [NonceLeaseState.Replaced]: requireNonceStateCount(record, NonceLeaseState.Replaced),
        }),
    ...(record[NonceLeaseState.Reconciled] === undefined
      ? {}
      : {
          [NonceLeaseState.Reconciled]: requireNonceStateCount(record, NonceLeaseState.Reconciled),
        }),
  };
}

function requireNonceStateCount(record: Record<string, unknown>, state: string): number {
  return requireNonNegativeSafeInteger(record[state], `nonce state ${state}`);
}

function requireNonceDegradationReason(value: unknown): NonceCoordinatorDegradation['reason'] {
  switch (value) {
    case NonceCoordinatorDegradationReason.WebLocksUnavailable:
    case NonceCoordinatorDegradationReason.IndexedDBUnavailable:
    case NonceCoordinatorDegradationReason.DurableLockTimeout:
    case NonceCoordinatorDegradationReason.DurableStoreError:
    case NonceCoordinatorDegradationReason.MalformedDurableRecord:
      return value;
    default:
      throw new Error('Nonce coordination warning reason is invalid');
  }
}

function requireNonceCoordinatorFallback(value: unknown): NonceCoordinatorDegradation['fallback'] {
  switch (value) {
    case NonceCoordinatorFallback.InRuntimeLock:
    case NonceCoordinatorFallback.None:
      return value;
    default:
      throw new Error('Nonce coordination warning fallback is invalid');
  }
}

function requireNonceLaneFamily(value: unknown): 'near' | 'evm' {
  if (value === 'near' || value === 'evm') return value;
  throw new Error('Nonce lane family is invalid');
}

function requireEvmNonceChain(value: unknown): 'evm' | 'tempo' {
  if (value === 'evm' || value === 'tempo') return value;
  throw new Error('Nonce lane chain is invalid');
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

function requireNonEmptyCapabilities(
  values: readonly WalletSessionCapabilityReadiness[],
): readonly [WalletSessionCapabilityReadiness, ...WalletSessionCapabilityReadiness[]] {
  const first = values[0];
  if (!first) throw new Error('Wallet Session capabilities must be non-empty');
  return [first, ...values.slice(1)];
}

function walletSessionCanonicalWalletId(session: WalletSession): WalletId | null {
  if (session.authentication.kind !== 'signed_out') {
    return session.authentication.walletId;
  }
  switch (session.appIdentity.kind) {
    case 'resolved':
    case 'unresolvable':
      return session.appIdentity.walletId;
    case 'anonymous':
      break;
  }
  switch (session.reusableWalletSession.kind) {
    case 'active':
    case 'exhausted':
    case 'expired':
    case 'superseded':
    case 'missing':
    case 'unavailable':
    case 'invalid':
      return session.reusableWalletSession.walletId;
    case 'absent':
      break;
  }
  if (session.capabilityProjection.kind === 'resolved') {
    return session.capabilityProjection.subjectSet.walletId;
  }
  return null;
}

function walletSessionWalletIdsAgree(session: WalletSession, walletId: WalletId): boolean {
  if (
    session.authentication.kind !== 'signed_out' &&
    session.authentication.walletId !== walletId
  ) {
    return false;
  }
  if (session.appIdentity.kind !== 'anonymous' && session.appIdentity.walletId !== walletId) {
    return false;
  }
  const reusable = session.reusableWalletSession;
  if (reusable.kind !== 'absent' && reusable.walletId !== walletId) return false;
  const projection = session.capabilityProjection;
  if (projection.kind !== 'resolved') return true;
  if (projection.subjectSet.walletId !== walletId) return false;
  for (const subject of projection.subjectSet.subjects) {
    if (subject.walletId !== walletId) return false;
  }
  for (const capability of projection.capabilities) {
    if (capability.subject.walletId !== walletId) return false;
  }
  return true;
}

function requireIdentityResolveFailure(value: unknown): WalletSessionIdentityResolveFailure {
  switch (value) {
    case 'missing_wallet_profile':
    case 'ambiguous_wallet_profile':
    case 'missing_requested_capability_subject':
    case 'capability_subject_lookup_failed':
    case 'invalid_capability_subject':
    case 'activation_reconciliation_pending':
    case 'activation_reconciliation_failed':
    case 'invalid_wallet_profile':
      return value;
    default:
      throw new Error('Wallet Session identity resolve failure is invalid');
  }
}

function requireInvalidWalletSessionReason(
  value: unknown,
): Extract<ReusableWalletSessionState, { kind: 'invalid' }>['reason'] {
  switch (value) {
    case 'malformed':
    case 'identity_mismatch':
    case 'ambiguous_wallet_session':
    case 'auth_method_mismatch':
      return value;
    default:
      // `lifecycle_mismatch` is gone: replacement crosses the boundary as the
      // `superseded` kind, not as an invalid reason.
      throw new Error('Invalid Wallet Session reason is invalid');
  }
}

function requireFailedCapabilityLaneReason(
  value: unknown,
): Extract<WalletSessionCapabilityLaneReadiness, { kind: 'failed' }>['reason'] {
  switch (value) {
    case 'missing':
    case 'persistence_unavailable':
    case 'malformed':
    case 'identity_mismatch':
    case 'ambiguous_lane':
      return value;
    default:
      throw new Error('Failed capability lane reason is invalid');
  }
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function requireNonEmptyArray(value: unknown, label: string): readonly [unknown, ...unknown[]] {
  const values = requireArray(value, label);
  const first = values[0];
  if (first === undefined) throw new Error(`${label} must be non-empty`);
  return [first, ...values.slice(1)];
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

function requireNullableString(value: unknown, label: string): string | null {
  if (value === null) return null;
  return requireNonEmptyString(value, label);
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (!isPositiveSafeInteger(value)) throw new Error(`${label} must be a positive integer`);
  return value;
}

function requireNonNegativeSafeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function exactIdentity(
  walletId: WalletId,
  session: Extract<WalletSession['reusableWalletSession'], { kind: 'active' | 'expired' }>,
): WalletIframeExactSessionIdentity | null {
  const walletSessionId = parseWalletSessionId(session.walletSessionId);
  if (!walletSessionId.ok || !isWalletAuthMethod(session.authMethod)) {
    return null;
  }
  if (!isPositiveSafeInteger(session.expiresAtMs)) return null;
  if (String(session.authorizationId) === String(walletSessionId.value)) return null;
  return {
    walletId,
    authorizationId: session.authorizationId,
    walletSessionId: walletSessionId.value,
    authMethod: session.authMethod,
    expiresAtMs: session.expiresAtMs,
  };
}

export function exactSessionIdentitiesMatch(
  left: WalletIframeExactSessionIdentity,
  right: WalletIframeExactSessionIdentity,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.authorizationId === right.authorizationId &&
    left.walletSessionId === right.walletSessionId
  );
}

function parseIdentity(value: Record<string, unknown>): WalletIframeExactSessionIdentity {
  const walletSessionId = parseWalletSessionId(value.walletSessionId);
  if (!walletSessionId.ok) throw new Error('Wallet iframe walletSessionId is invalid');
  if (!isPositiveSafeInteger(value.expiresAtMs))
    throw new Error('Wallet iframe expiresAtMs is invalid');
  const walletId = requireWalletId(value.walletId);
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  if (!authorizationId.ok) throw new Error('Wallet iframe authorizationId is invalid');
  if (!isWalletAuthMethod(value.authMethod)) throw new Error('Wallet iframe authMethod is invalid');
  assertDistinctAuthorizationIdentity(authorizationId.value, walletSessionId.value);
  return {
    walletId,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    authMethod: value.authMethod,
    expiresAtMs: value.expiresAtMs,
  };
}

function assertDistinctAuthorizationIdentity(
  authorizationId: WalletSessionAuthorizationId,
  walletSessionId: WalletSessionId,
): void {
  if (String(authorizationId) === String(walletSessionId)) {
    throw new Error('Wallet iframe authorization and Wallet Session IDs must be distinct');
  }
}

function unavailableSession(
  walletId: WalletId,
  reason: Exclude<WalletIframeSessionUnavailableReason, 'not_found'>,
): WalletIframeExactSessionState {
  return { kind: 'wallet_unlocked_without_signing_session', walletId, reason };
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error('Wallet iframe walletId is invalid');
  return parsed.value;
}

function requireUnavailableReason(value: unknown): WalletIframeSessionUnavailableReason {
  switch (value) {
    case 'exhausted':
    case 'absent':
    case 'not_found':
    case 'unavailable':
    case 'status_unknown':
    case 'superseded':
    case 'invalid':
      return value;
    default:
      throw new Error('Wallet iframe unavailable reason is invalid');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}
