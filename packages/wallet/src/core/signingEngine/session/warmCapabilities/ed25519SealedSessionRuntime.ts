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
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
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
import { SigningSessionIds, type ThresholdEd25519SessionId } from '../operationState/types';
import {
  nearEd25519SessionMatchesMaterialActivation,
  type ExactNearEd25519WalletSessionAuthorization,
} from '../material/nearEd25519YaoSigningPreparation';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { ExactEd25519SigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import {
  parseEmailOtpWalletAuthAuthority,
  parsePasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';

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

export type Ed25519WalletSealedSessionRuntimeResolution =
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

function nonEmptyString(value: unknown): string | null {
  const normalized = String(value ?? '').trim();
  return normalized || null;
}

function positiveSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function nonNegativeSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function exactParticipantIds(value: unknown): readonly [number, number] | null {
  const participantIds = normalizeThresholdEd25519ParticipantIds(value);
  return participantIds?.length === 2 ? [participantIds[0], participantIds[1]] : null;
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
  const thresholdSessionIdRaw = nonEmptyString(record.thresholdSessionIds.ed25519);
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
  try {
    return {
      kind: 'exact_ed25519_sealed_session_runtime',
      sealedRecord: record,
      walletId: toWalletId(record.walletId),
      nearAccountId: toAccountId(restore.nearAccountId),
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
      signerSlot,
      factor,
      auth: authBinding(factor),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionIdRaw),
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

export async function ed25519SealedRuntimeAuthorityRef(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  walletAuthMethodId: WalletAuthMethodId;
}): Promise<WalletAuthAuthorityRef> {
  let authority: WalletAuthAuthority | null;
  switch (args.runtime.factor.kind) {
    case 'passkey':
      authority = parsePasskeyWalletAuthAuthority({
        walletId: args.runtime.walletId,
        factor: {
          kind: 'passkey',
          credentialIdB64u: args.runtime.factor.credentialIdB64u,
        },
        verifier: {
          kind: 'webauthn',
          rpId: args.runtime.factor.rpId,
        },
        bindingId: args.walletAuthMethodId,
      });
      break;
    case 'email_otp':
      authority = parseEmailOtpWalletAuthAuthority({
        walletId: args.runtime.walletId,
        factor: {
          kind: 'email_otp',
          provider: args.runtime.factor.provider,
          providerUserId: args.runtime.factor.providerSubjectId,
        },
        verifier: {
          kind: 'email_otp_wallet_auth_method',
          emailHashHex: args.runtime.factor.emailHashHex,
        },
        bindingId: args.walletAuthMethodId,
      });
      break;
    default:
      return assertNeverEd25519Factor(args.runtime.factor);
  }
  if (!authority) {
    throw new Error('[SigningEngine][near] sealed Ed25519 authority is invalid');
  }
  return await walletAuthAuthorityRef({ authority });
}

function assertNeverEd25519Factor(value: never): never {
  throw new Error(`Unsupported Ed25519 factor: ${String(value)}`);
}

export async function ed25519AuthorizationIdentityMatchesRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ExactNearEd25519WalletSessionAuthorization;
}): Promise<boolean> {
  const { authorization, runtime } = args;
  if (
    authorization.session.walletId !== runtime.walletId ||
    authorization.session.authMethodId !== authorization.selectedAuthMethod.walletAuthMethodId ||
    authorization.session.quotaId !== authorization.status.quotaId ||
    authorization.operationCredential.walletSessionId !== authorization.status.walletSessionId ||
    authorization.operationCredential.token.trim().length === 0 ||
    authorization.status.remainingUses <= 0 ||
    !nearEd25519SessionMatchesMaterialActivation({
      session: authorization.session,
      materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
    })
  ) {
    return false;
  }
  if (runtime.factor.kind === 'passkey') {
    if (
      authorization.selectedAuthMethod.kind !== 'passkey' ||
      String(authorization.selectedAuthMethod.rpId) !== String(runtime.factor.rpId) ||
      authorization.selectedAuthMethod.credentialIdB64u !== runtime.factor.credentialIdB64u ||
      authorization.selectedFactorAuthority.factor.kind !== 'passkey' ||
      authorization.selectedFactorAuthority.factor.credentialIdB64u !==
        runtime.factor.credentialIdB64u ||
      authorization.selectedFactorAuthority.verifier.kind !== 'webauthn' ||
      String(authorization.selectedFactorAuthority.verifier.rpId) !== String(runtime.factor.rpId)
    ) {
      return false;
    }
  } else if (
    authorization.selectedAuthMethod.kind !== 'email_otp' ||
    authorization.selectedAuthMethod.emailHashHex !== runtime.factor.emailHashHex ||
    authorization.selectedFactorAuthority.factor.kind !== 'email_otp' ||
    authorization.selectedFactorAuthority.factor.provider !== runtime.factor.provider ||
    authorization.selectedFactorAuthority.factor.providerUserId !==
      runtime.factor.providerSubjectId ||
    authorization.selectedFactorAuthority.verifier.kind !== 'email_otp_wallet_auth_method' ||
    authorization.selectedFactorAuthority.verifier.emailHashHex !== runtime.factor.emailHashHex
  ) {
    return false;
  }
  try {
    const expected = await ed25519SealedRuntimeAuthorityRef({
      runtime,
      walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
    });
    const selectedFactorRef = await walletAuthAuthorityRef({
      authority: authorization.selectedFactorAuthority,
    });
    return (
      expected.walletId === authorization.selectedAuthority.walletId &&
      expected.walletAuthMethodId === authorization.selectedAuthMethod.walletAuthMethodId &&
      expected.walletId === selectedFactorRef.walletId &&
      expected.walletAuthMethodId === selectedFactorRef.walletAuthMethodId &&
      expected.authorityDigest === selectedFactorRef.authorityDigest
    );
  } catch {
    return false;
  }
}

export async function ed25519WalletSessionAuthorizationForRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authorization: ExactNearEd25519WalletSessionAuthorization;
}): Promise<ExactNearEd25519WalletSessionAuthorization | null> {
  return (await ed25519AuthorizationIdentityMatchesRuntime(args)) ? args.authorization : null;
}

function authBindingsEqual(left: SigningLaneAuthBinding, right: SigningLaneAuthBinding): boolean {
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
    args.record.thresholdSessionIds.ed25519 === args.laneIdentity.thresholdSessionId
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

export async function resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(
  walletId: WalletId,
  resolver: Ed25519SealedSessionRuntimeResolver,
): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  return resolveOneEd25519SealedSessionRuntime(
    await listEd25519SealedSessionRecordsForWallet(walletId, resolver),
  );
}

async function listEd25519SealedSessionRecordsForWallet(
  walletId: WalletId,
  resolver: Ed25519SealedSessionRuntimeResolver,
): Promise<CurrentEd25519SealedSessionRecord[]> {
  const listedRecords = await Promise.all([
    resolver.listExactSealedSessionsForWallet({
      walletId,
      filter: {
        authMethod: SIGNER_AUTH_METHODS.passkey,
        curve: 'ed25519',
      },
    }),
    resolver.listExactSealedSessionsForWallet({
      walletId,
      filter: {
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        curve: 'ed25519',
      },
    }),
  ]);
  const records: CurrentEd25519SealedSessionRecord[] = [];
  for (const listed of listedRecords) {
    for (const record of listed) {
      if (record.curve === 'ed25519') records.push(record);
    }
  }
  return records;
}

function resolveOneEd25519SealedSessionRuntime(
  records: CurrentEd25519SealedSessionRecord[],
): Ed25519WalletSealedSessionRuntimeResolution {
  if (records.length === 0) return { kind: 'missing' };
  if (records.length > 1) return { kind: 'conflict' };
  const runtime = parseExactEd25519SealedSessionRuntime(records[0]);
  return runtime ? { kind: 'resolved', runtime } : { kind: 'corrupt' };
}

export async function resolveExactEd25519SealedSessionRuntimeForWallet(
  walletId: WalletId,
): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  return await resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(walletId, {
    listExactSealedSessionsForWallet,
  });
}

export async function resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver(
  args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  },
  resolver: Ed25519SealedSessionRuntimeResolver,
): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  const records = await listEd25519SealedSessionRecordsForWallet(args.walletId, resolver);
  const matches: CurrentEd25519SealedSessionRecord[] = [];
  for (const record of records) {
    if (
      record.ed25519Restore.nearAccountId === args.nearAccountId &&
      record.ed25519Restore.nearEd25519SigningKeyId === args.nearEd25519SigningKeyId
    ) {
      matches.push(record);
    }
  }
  return resolveOneEd25519SealedSessionRuntime(matches);
}

export async function resolveExactEd25519SealedSessionRuntimeForWalletSubjectAndActivationWithResolver(
  args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    materialActivation: MpcMaterialActivationRef;
    authMethod: SignerAuthMethod;
  },
  resolver: Ed25519SealedSessionRuntimeResolver,
): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  const records = await resolver.listExactSealedSessionsForWallet({
    walletId: args.walletId,
    filter: {
      authMethod: args.authMethod,
      curve: 'ed25519',
    },
  });
  const matches: CurrentEd25519SealedSessionRecord[] = [];
  for (const record of records) {
    if (
      record.curve === 'ed25519' &&
      record.authMethod === args.authMethod &&
      record.ed25519Restore.nearAccountId === args.nearAccountId &&
      record.ed25519Restore.nearEd25519SigningKeyId === args.nearEd25519SigningKeyId &&
      mpcMaterialActivationRefsEqual(
        record.ed25519Restore.materialActivation,
        args.materialActivation,
      )
    ) {
      matches.push(record);
    }
  }
  return resolveOneEd25519SealedSessionRuntime(matches);
}

export async function resolveExactEd25519SealedSessionRuntimeForWalletSubject(args: {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
}): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  return await resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver(args, {
    listExactSealedSessionsForWallet,
  });
}

export async function resolveExactEd25519SealedSessionRuntimeForWalletSubjectAndActivation(args: {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  materialActivation: MpcMaterialActivationRef;
  authMethod: SignerAuthMethod;
}): Promise<Ed25519WalletSealedSessionRuntimeResolution> {
  return await resolveExactEd25519SealedSessionRuntimeForWalletSubjectAndActivationWithResolver(
    args,
    { listExactSealedSessionsForWallet },
  );
}
