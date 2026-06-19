import type {
  EcdsaSigningLookupArgs,
  EvmFamilyChain,
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
  PasskeyEcdsaSigningLookupArgs,
} from '../../interfaces/operationDeps';
import {
  selectedEcdsaLane,
  type SelectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
  type EcdsaTransactionSigningLane,
} from '../../session/operationState/lanes';
import type {
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import { thresholdEcdsaSessionRecordReadModel } from '../../session/persistence/records';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  SigningSessionIds,
  type ResolvedEcdsaSigningSessionIdentity,
  type ThresholdEcdsaSessionId,
  type SigningGrantId,
} from '../../session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  toWalletId,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  tryBuildEcdsaSessionIdentity,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  resolveRouterAbEcdsaWalletSessionAuthFromRecord,
} from '../../session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  type EvmFamilyEcdsaKeyIdentity,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';

export type EvmFamilyEcdsaAuthMethod =
  | typeof SIGNER_AUTH_METHODS.emailOtp
  | typeof SIGNER_AUTH_METHODS.passkey;

export type ResolvedEvmFamilyEcdsaSigningLane = EcdsaTransactionSigningLane & {
    authMethod: EvmFamilyEcdsaAuthMethod;
    curve: 'ecdsa';
    keyKind: 'threshold_ecdsa_secp256k1';
    chainFamily: EvmFamilyChain;
    key: EvmFamilyEcdsaKeyIdentity;
    chainTarget: ThresholdEcdsaChainTarget;
    signingGrantId: SigningGrantId;
    thresholdSessionId: ThresholdEcdsaSessionId;
  } & ResolvedEcdsaSigningSessionIdentity;

export function summarizeEvmFamilyEcdsaSessionRecord(
  record: ThresholdEcdsaSessionRecord | undefined,
): Record<string, unknown> {
  if (!record) return { present: false };
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  return {
    present: true,
    source: record.source,
    chain: record.chainTarget.kind,
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    keyHandle: record.keyHandle,
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
    emailOtpRetention: record.source === 'email_otp' ? record.emailOtpAuthContext.retention : null,
    emailOtpReason: record.source === 'email_otp' ? record.emailOtpAuthContext.reason : null,
    routerAbWalletSessionAuth: walletSessionAuth.kind,
    routerAbWalletSessionAuthSource:
      walletSessionAuth.kind === 'ready' ? walletSessionAuth.source : walletSessionAuth.reason,
    hasRelayerKeyId: !!record.relayerKeyId,
  };
}

export function summarizeEvmFamilyEcdsaLane(
  lane: EcdsaTransactionSigningLane | SelectedEcdsaLane | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  return {
    present: true,
    walletId: lane.walletId,
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.chain,
    chainFamily: 'chainFamily' in lane ? lane.chainFamily : lane.chain,
    keyKind: 'keyKind' in lane ? lane.keyKind : 'threshold_ecdsa_secp256k1',
    sessionOrigin: 'sessionOrigin' in lane ? lane.sessionOrigin : undefined,
    storageSource: 'storageSource' in lane ? lane.storageSource : undefined,
    retention: 'retention' in lane ? lane.retention : undefined,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    chainTarget: lane.chainTarget,
    evmFamilyKeyPresent: Boolean('key' in lane && lane.key),
  };
}

export function logEvmFamilyEcdsaLaneDiagnostic(
  message: string,
  details: Record<string, unknown>,
): void {
  try {
    console.warn(`[SigningEngine][ecdsa] ${message}`, details);
  } catch {}
}

export function requireResolvedEvmFamilyEcdsaSigningLane(args: {
  lane: EcdsaTransactionSigningLane | undefined;
  chain: EvmFamilyChain;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const lane = args.lane;
  if (!lane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing selected signing lane', {
      context: args.context,
      chain: args.chain,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing selected signing lane for ${args.context}`);
  }
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane is not ECDSA', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} requires an ECDSA signing lane`);
  }
  if (
    lane.authMethod !== SIGNER_AUTH_METHODS.emailOtp &&
    lane.authMethod !== SIGNER_AUTH_METHODS.passkey
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane has no concrete auth method', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} requires a concrete ECDSA auth method`);
  }
  if (lane.chainFamily !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane chain mismatch', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} chain does not match selected lane`);
  }

  const laneIdentity = tryBuildEcdsaSessionIdentity(lane);
  if (!laneIdentity) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing ECDSA session identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing ECDSA session identity for ${args.context}`);
  }
  const chainTarget = (lane as { chainTarget?: ThresholdEcdsaChainTarget }).chainTarget;
  if (!chainTarget || chainTarget.kind !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing concrete chain target', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing concrete chain target for ${args.context}`);
  }
  const key = (lane as { key?: EvmFamilyEcdsaKeyIdentity }).key;
  if (!key?.ecdsaThresholdKeyId || !key.signingRootId || !key.signingRootVersion) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing full ECDSA identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] incomplete ECDSA lane identity for ${args.context}`);
  }
  if (
    !key ||
    String(key.walletId) !== String(lane.walletId) ||
    String(lane.keyHandle || '').trim() === ''
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing matching shared key identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing shared key identity for ${args.context}`);
  }

  const selectedLane = selectedEcdsaLane({
    key,
    keyHandle: lane.keyHandle,
    walletId: lane.walletId,
    authMethod: lane.authMethod,
    signingGrantId: laneIdentity.signingGrantId,
    thresholdSessionId: laneIdentity.thresholdSessionId,
    chainTarget,
  });

  return {
    ...lane,
    ...selectedLane,
    key,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: args.chain,
  };
}

export function updateResolvedEvmFamilyEcdsaSigningLaneIdentity(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chain: EvmFamilyChain;
  thresholdSessionId: string;
  signingGrantId: string;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const lane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: args.lane,
    chain: args.chain,
    context: args.context,
    diagnostics: args.diagnostics,
  });
  const identity = tryBuildEcdsaSessionIdentity(args);
  if (!identity) {
    logEvmFamilyEcdsaLaneDiagnostic('updated ECDSA lane identity is incomplete', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(
      `[SigningEngine][ecdsa] incomplete updated signing lane identity for ${args.context}`,
    );
  }
  return {
    ...lane,
    signingGrantId: SigningSessionIds.signingGrant(identity.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(identity.thresholdSessionId),
  };
}

export function selectedEvmFamilyEcdsaLaneForMaterialIdentity(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  identity: ThresholdEcdsaSessionRecord;
  context: string;
}): SelectedEcdsaLane {
  const keyHandle = String(args.identity.keyHandle || '').trim();
  const laneKeyHandle = String(args.lane.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error(
      `[SigningEngine][ecdsa] ${args.context} received incomplete ECDSA material identity`,
    );
  }
  if (!laneKeyHandle || keyHandle !== laneKeyHandle) {
    throw new Error(
      `[SigningEngine][ecdsa] ${args.context} ECDSA material keyHandle did not match selected lane`,
    );
  }
  return selectedEcdsaLane({
    key: args.lane.key,
    keyHandle,
    walletId: args.lane.walletId,
    authMethod: args.lane.authMethod,
    chainTarget: args.chainTarget,
    signingGrantId: args.lane.signingGrantId,
    thresholdSessionId: args.lane.thresholdSessionId,
  });
}

export function requireEvmFamilyEcdsaAuthMethod(
  authMethod: EvmFamilyEcdsaAuthMethod | undefined,
): EvmFamilyEcdsaAuthMethod {
  if (!authMethod) {
    throw new Error('[SigningEngine] ECDSA auth method is required for transaction auth planning');
  }
  return authMethod;
}

export function buildEvmFamilyEcdsaSigningLaneContext(
  args: {
    walletId: string;
    chain: EvmFamilyChain;
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    material: ReadyEvmFamilyEcdsaMaterial;
  },
): ResolvedEvmFamilyEcdsaSigningLane | undefined {
  const { key, lane: materialLane, record } = args.material;
  if (String(key.walletId) !== String(args.walletId)) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched wallet identity',
      {
        walletId: args.walletId,
        materialWalletId: key.walletId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
      },
    );
    return undefined;
  }
  if (!thresholdEcdsaChainTargetsEqual(materialLane.chainTarget, args.chainTarget)) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched chain target',
      {
        walletId: args.walletId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        materialChainTarget: materialLane.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
      },
    );
    return undefined;
  }
  if (materialLane.authMethod !== args.authMethod || materialLane.source !== args.source) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched auth source',
      {
        walletId: args.walletId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        materialAuthMethod: materialLane.authMethod,
        materialSource: materialLane.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
      },
    );
    return undefined;
  }

  const base = {
    key,
    keyHandle: record.keyHandle,
    walletId: toAccountId(key.walletId),
    signingGrantId: materialLane.signingGrantId,
    thresholdSessionId: materialLane.thresholdSessionId,
  };
  const buildLane =
    args.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;

  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const emailOtpAuthContext =
      record?.source === 'email_otp' ? record.emailOtpAuthContext : null;
    const lane = buildLane({
      ...base,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      retention: emailOtpAuthContext?.retention || 'session',
      sessionOrigin: emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
    });
    return requireResolvedEvmFamilyEcdsaSigningLane({
      lane,
      chain: args.chain,
      context: 'build EVM-family ECDSA signing lane',
    });
  }

  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return undefined;
  const lane = buildLane({
    ...base,
    chainTarget: args.chainTarget,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    storageSource: args.source,
  });
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: args.chain,
    context: 'build EVM-family ECDSA signing lane',
  });
}

export function getThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletId: EcdsaSigningLookupArgs['walletId'];
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord {
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    return args.deps.getEmailOtpThresholdEcdsaSessionRecordForSigning({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
    });
  }
  const passkeySource = args.source as PasskeyEcdsaSessionStoreSource;
  return args.deps.getPasskeyThresholdEcdsaSessionRecordForSigning({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: passkeySource,
  });
}

export function tryGetThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletId: EcdsaSigningLookupArgs['walletId'];
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord | undefined {
  try {
    return getThresholdEcdsaSessionRecordForLane(args);
  } catch {
    return undefined;
  }
}

export function tryGetEmailOtpThresholdEcdsaSessionRecordForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletId: EcdsaSigningLookupArgs['walletId'];
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord | undefined {
  return tryGetThresholdEcdsaSessionRecordForLane({
    ...args,
    source: SIGNER_AUTH_METHODS.emailOtp,
  });
}

export function tryGetPasskeyThresholdEcdsaSessionRecordForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletId: EcdsaSigningLookupArgs['walletId'];
  chainTarget: ThresholdEcdsaChainTarget;
  source: PasskeyEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord | undefined {
  const candidate = tryGetThresholdEcdsaSessionRecordForLane({
    deps: args.deps,
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: args.source,
  });
  return candidate && !isEmailOtpThresholdEcdsaSigningContext({ record: candidate })
    ? candidate
    : undefined;
}

export function isEmailOtpThresholdEcdsaSigningContext(
  args: { record: ThresholdEcdsaSessionRecord; keyRef?: never },
): boolean {
  const record = args.record;
  return (
    record.source === SIGNER_AUTH_METHODS.emailOtp ||
    record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
  );
}

export function emailOtpEcdsaAuthLaneFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): EmailOtpAuthLane | undefined {
  const identity = record ? tryBuildEcdsaSessionIdentity(record) : null;
  const walletSessionAuth = record
    ? resolveRouterAbEcdsaWalletSessionAuthFromRecord(record)
    : null;
  if (
    record?.source !== SIGNER_AUTH_METHODS.emailOtp ||
    walletSessionAuth?.kind !== 'ready' ||
    !identity
  ) {
    return undefined;
  }
  return {
    kind: 'signing_session',
    jwt: walletSessionAuth.walletSessionJwt,
    thresholdSessionId: identity.thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(
      identity.signingGrantId,
    ),
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
  };
}

function ecdsaMaterialSourceMatchesAuth(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
}): boolean {
  const isEmailOtpMaterial = args.record
    ? isEmailOtpThresholdEcdsaSigningContext({ record: args.record })
    : false;
  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    if (args.source === SIGNER_AUTH_METHODS.emailOtp) return true;
    return isEmailOtpMaterial;
  }
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return false;
  return !isEmailOtpMaterial;
}

export function findExactEcdsaSessionRecordForSelectedLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane: SelectedEcdsaLane;
}): ThresholdEcdsaSessionRecord | undefined {
  return args.deps.getThresholdEcdsaSessionRecordByKey(args.lane) || undefined;
}

export function readSelectedEcdsaRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane?: SelectedEcdsaLane;
}): ThresholdEcdsaSessionRecord | undefined {
  if (!args.lane) return undefined;
  const record = findExactEcdsaSessionRecordForSelectedLane({
    deps: args.deps,
    lane: args.lane,
  });
  if (!record) return undefined;
  if (
    ecdsaMaterialSourceMatchesAuth({
      authMethod: args.lane.authMethod,
      source: record.source,
      record,
    })
  ) {
    return record;
  }
  throw new Error('[SigningEngine][ecdsa] selected ECDSA record auth source mismatch');
}

export function validateSelectedEcdsaRecordCandidateForLane(args: {
  lane?: SelectedEcdsaLane;
  record?: ThresholdEcdsaSessionRecord;
  context: string;
}): ThresholdEcdsaSessionRecord | undefined {
  if (!args.lane || !args.record) return undefined;
  const lane = args.lane;
  const record = args.record;
  const mismatchReason = getSelectedEcdsaRecordLaneMismatchReason({ lane, record });
  if (!mismatchReason) return record;
  logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA record candidate does not match resolved lane', {
    context: args.context,
    reason: mismatchReason,
    lane: summarizeEvmFamilyEcdsaLane(lane),
    record: summarizeEvmFamilyEcdsaSessionRecord(record),
  });
  throw new Error(
    `[SigningEngine][ecdsa] selected ECDSA record candidate does not match resolved lane for ${args.context}`,
  );
}

function ecdsaRecordMatchesSharedLaneKey(args: {
  lane: SelectedEcdsaLane;
  record: ThresholdEcdsaSessionRecord;
}): boolean {
  return args.record.keyHandle === args.lane.keyHandle;
}

export function findSharedEvmFamilyEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane?: SelectedEcdsaLane;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
}): ThresholdEcdsaSessionRecord | undefined {
  const lane = args.lane;
  if (!lane) return undefined;
  const walletId = toWalletId(lane.walletId);
  const candidates: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  for (const chainTarget of args.chainTargets) {
    for (const record of args.deps.listThresholdEcdsaSessionRecordsForSigning({
      walletId,
      chainTarget,
    })) {
      const candidateKey = [
        record.source,
        thresholdEcdsaChainTargetKey(record.chainTarget),
        record.signingGrantId,
        record.thresholdSessionId,
      ].join(':');
      if (seen.has(candidateKey)) continue;
      seen.add(candidateKey);
      if (
        !ecdsaMaterialSourceMatchesAuth({
          authMethod: lane.authMethod,
          source: record.source,
          record,
        })
      ) {
        continue;
      }
      if (!ecdsaRecordMatchesSharedLaneKey({ lane, record })) continue;
      candidates.push(record);
    }
  }
  return candidates.sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  )[0];
}

function getSelectedEcdsaRecordLaneMismatchReason(args: {
  lane: SelectedEcdsaLane;
  record: ThresholdEcdsaSessionRecord;
}): string | null {
  const { lane, record } = args;
  if (lane.curve !== 'ecdsa') {
    return 'lane is not an ECDSA transaction lane';
  }
  if (lane.chain !== 'tempo' && lane.chain !== 'evm') {
    return 'lane chain is not an EVM-family chain';
  }
  if (String(record.walletId || '') !== String(lane.walletId)) {
    return 'wallet id mismatch';
  }
  if (
    !ecdsaMaterialSourceMatchesAuth({
      authMethod: lane.authMethod,
      source: record.source,
      record,
    })
  ) {
    return 'auth source mismatch';
  }
  const laneIdentity = buildEcdsaSessionIdentity(lane);
  const recordIdentity = tryBuildEcdsaSessionIdentity(record);
  if (!recordIdentity || recordIdentity.thresholdSessionId !== laneIdentity.thresholdSessionId) {
    return 'threshold session id mismatch';
  }
  if (recordIdentity.signingGrantId !== laneIdentity.signingGrantId) {
    return 'wallet signing session id mismatch';
  }
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, lane.chainTarget)) {
    return 'chain mismatch';
  }
  try {
    thresholdEcdsaSessionRecordReadModel(record).key;
  } catch {
    return 'record key identity mismatch';
  }
  if (
    String(record.keyHandle || '').trim() !== String(lane.keyHandle || '').trim()
  ) {
    return 'key handle mismatch';
  }
  return null;
}
