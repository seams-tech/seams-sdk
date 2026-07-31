import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  parseRouterAbEd25519WalletSessionIdentityClaims,
} from '../routerAbSigningWalletSession';
import {
  listExactSealedSessionsForWallet,
  type CurrentEd25519SealedSessionRecord,
} from '../persistence/sealedSessionStore';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import {
  SigningSessionIds,
  type SigningGrantId,
  type ThresholdEd25519SessionId,
} from '../operationState/types';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { ExactEd25519SigningLaneIdentity } from '../identity/exactSigningLaneIdentity';

type Ed25519SealedSessionFactor =
  | {
      readonly kind: 'passkey';
      readonly rpId: ReturnType<typeof toRpId>;
      readonly credentialIdB64u: string;
      readonly provider?: never;
      readonly providerSubjectId?: never;
      readonly emailHashHex?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly provider: 'google' | 'email';
      readonly providerSubjectId: string;
      readonly emailHashHex: string;
      readonly rpId?: never;
      readonly credentialIdB64u?: never;
    };

export type ExactEd25519SealedSessionRuntime = {
  readonly kind: 'exact_ed25519_sealed_session_runtime';
  readonly sealedRecord: CurrentEd25519SealedSessionRecord;
  readonly walletId: WalletId;
  readonly nearAccountId: AccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly signerSlot: SignerSlot;
  readonly factor: Ed25519SealedSessionFactor;
  readonly auth: SigningLaneAuthBinding;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly signingGrantId: SigningGrantId;
  readonly walletSessionJwt: string;
  readonly remainingUses: number;
  readonly expiresAtMs: number;
  readonly relayerUrl: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type Ed25519SealedSessionRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly runtime: ExactEd25519SealedSessionRuntime;
    }
  | {
      readonly kind: 'missing';
      readonly runtime?: never;
    }
  | {
      readonly kind: 'conflict';
      readonly runtime?: never;
    }
  | {
      readonly kind: 'corrupt';
      readonly runtime?: never;
    };

export type Ed25519SealedSessionRuntimeResolver = {
  readonly listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
};

function nonEmptyString(value: unknown): string | null {
  const normalized = String(value ?? '').trim();
  return normalized || null;
}

function positiveSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : null;
}

function nonNegativeSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

function exactParticipantIds(value: unknown): readonly [number, number] | null {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  return participantIds?.length === 2
    ? [participantIds[0], participantIds[1]]
    : null;
}

function sealedFactor(
  record: CurrentEd25519SealedSessionRecord,
): Ed25519SealedSessionFactor | null {
  const restore = record.ed25519Restore;
  switch (record.authMethod) {
    case SIGNER_AUTH_METHODS.passkey: {
      const credentialIdB64u = nonEmptyString(restore.credentialIdB64u);
      if (!credentialIdB64u) return null;
      return {
        kind: 'passkey',
        rpId: toRpId(restore.rpId),
        credentialIdB64u,
      };
    }
    case SIGNER_AUTH_METHODS.emailOtp: {
      if (!('provider' in restore)) return null;
      const providerSubjectId = nonEmptyString(restore.providerSubjectId);
      const emailHashHex = nonEmptyString(restore.emailHashHex);
      if (!providerSubjectId || !emailHashHex) return null;
      return {
        kind: 'email_otp',
        provider: restore.provider,
        providerSubjectId,
        emailHashHex,
      };
    }
  }
}

function authBinding(factor: Ed25519SealedSessionFactor): SigningLaneAuthBinding {
  switch (factor.kind) {
    case 'passkey':
      return {
        kind: SIGNER_AUTH_METHODS.passkey,
        rpId: factor.rpId,
        credentialIdB64u: factor.credentialIdB64u,
      };
    case 'email_otp':
      return {
        kind: SIGNER_AUTH_METHODS.emailOtp,
        providerSubjectId: factor.providerSubjectId,
      };
  }
}

export function parseExactEd25519SealedSessionRuntime(
  record: CurrentEd25519SealedSessionRecord,
): ExactEd25519SealedSessionRuntime | null {
  const restore = record.ed25519Restore;
  if (restore.sessionKind !== 'jwt') return null;
  const thresholdSessionIdRaw = nonEmptyString(record.thresholdSessionIds.ed25519);
  const signingGrantIdRaw = nonEmptyString(record.signingGrantId);
  const walletSessionJwt = nonEmptyString(restore.walletSessionJwt);
  const relayerUrl = nonEmptyString(record.relayerUrl);
  const relayerKeyId = nonEmptyString(restore.relayerKeyId);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const remainingUses = nonNegativeSafeInteger(record.remainingUses);
  const signerSlot = parseSignerSlot(restore.signerSlot);
  const participantIds = exactParticipantIds(restore.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
  const signingRoot = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootVersion = nonEmptyString(signingRoot?.signingRootVersion);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    restore.routerAbNormalSigning,
  );
  const factor = sealedFactor(record);
  if (
    !thresholdSessionIdRaw ||
    !signingGrantIdRaw ||
    !walletSessionJwt ||
    !relayerUrl ||
    !relayerKeyId ||
    !expiresAtMs ||
    remainingUses === null ||
    !signerSlot ||
    !participantIds ||
    !runtimePolicyScope ||
    !signingRoot ||
    !signingRootVersion ||
    !routerAbNormalSigning ||
    routerAbNormalSigning.signingWorkerId !== relayerKeyId ||
    !factor
  ) {
    return null;
  }
  if (
    record.signingRootId !== signingRoot.signingRootId ||
    record.signingRootVersion !== signingRootVersion
  ) {
    return null;
  }
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(walletSessionJwt);
  if (
    !claims ||
    claims.walletId !== record.walletId ||
    claims.nearAccountId !== restore.nearAccountId ||
    claims.nearEd25519SigningKeyId !== restore.nearEd25519SigningKeyId ||
    claims.thresholdSessionId !== thresholdSessionIdRaw ||
    claims.signingGrantId !== signingGrantIdRaw
  ) {
    return null;
  }
  try {
    return {
      kind: 'exact_ed25519_sealed_session_runtime',
      sealedRecord: record,
      walletId: toWalletId(record.walletId),
      nearAccountId: toAccountId(restore.nearAccountId),
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
        restore.nearEd25519SigningKeyId,
      ),
      signerSlot,
      factor,
      auth: authBinding(factor),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionIdRaw),
      signingGrantId: SigningSessionIds.signingGrant(signingGrantIdRaw),
      walletSessionJwt,
      remainingUses,
      expiresAtMs,
      relayerUrl,
      relayerKeyId,
      participantIds,
      runtimePolicyScope,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion,
      routerAbNormalSigning,
    };
  } catch {
    return null;
  }
}

function authBindingsEqual(
  left: SigningLaneAuthBinding,
  right: SigningLaneAuthBinding,
): boolean {
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u
      );
    case 'email_otp':
      return right.kind === 'email_otp' && left.providerSubjectId === right.providerSubjectId;
  }
}

function rawRecordMatchesLaneSubject(args: {
  record: CurrentEd25519SealedSessionRecord;
  laneIdentity: ExactEd25519SigningLaneIdentity;
}): boolean {
  const signer = args.laneIdentity.signer;
  const restore = args.record.ed25519Restore;
  return (
    args.record.walletId === signer.account.wallet.walletId &&
    restore.nearAccountId === signer.account.nearAccountId &&
    restore.nearEd25519SigningKeyId === signer.nearEd25519SigningKeyId &&
    restore.signerSlot === signer.signerSlot &&
    args.record.thresholdSessionIds.ed25519 === args.laneIdentity.thresholdSessionId &&
    args.record.signingGrantId === args.laneIdentity.signingGrantId
  );
}

function runtimeMatchesLane(
  runtime: ExactEd25519SealedSessionRuntime,
  laneIdentity: ExactEd25519SigningLaneIdentity,
): boolean {
  return authBindingsEqual(runtime.auth, laneIdentity.auth);
}

export async function resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(
  args: {
    readonly walletId: WalletId;
    readonly laneIdentity: ExactEd25519SigningLaneIdentity;
  },
  resolver: Ed25519SealedSessionRuntimeResolver,
): Promise<Ed25519SealedSessionRuntimeResolution> {
  const records = await resolver.listExactSealedSessionsForWallet({
    walletId: args.walletId,
    filter: {
      authMethod: args.laneIdentity.auth.kind,
      curve: 'ed25519',
    },
  });
  const candidates = records.filter(
    (record): record is CurrentEd25519SealedSessionRecord =>
      record.curve === 'ed25519' &&
      rawRecordMatchesLaneSubject({ record, laneIdentity: args.laneIdentity }),
  );
  if (candidates.length === 0) return { kind: 'missing' };
  if (candidates.length > 1) return { kind: 'conflict' };
  const runtime = parseExactEd25519SealedSessionRuntime(candidates[0]);
  if (!runtime || !runtimeMatchesLane(runtime, args.laneIdentity)) {
    return { kind: 'corrupt' };
  }
  return { kind: 'resolved', runtime };
}

export async function resolveExactEd25519SealedSessionRuntimeForLane(args: {
  readonly walletId: WalletId;
  readonly laneIdentity: ExactEd25519SigningLaneIdentity;
}): Promise<Ed25519SealedSessionRuntimeResolution> {
  return await resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(args, {
    listExactSealedSessionsForWallet,
  });
}
