import type {
  EcdsaSigningLookupArgs,
  EvmFamilyChain,
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
} from '../../interfaces/operationDeps';
import {
  selectedEcdsaLane,
  selectedLaneAuthMethod,
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type SelectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
  type EcdsaTransactionSigningLane,
} from '../../session/operationState/lanes';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  thresholdEcdsaLaneCandidateFromSessionRecord,
  thresholdEcdsaSessionRecordReadModel,
} from '../../session/persistence/records';
import {
  type ResolvedEcdsaSigningSessionIdentity,
  type ThresholdEcdsaSessionId,
  type SigningGrantId,
} from '../../session/operationState/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  toWalletId,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  tryBuildEcdsaSessionIdentity,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../../session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  type EvmFamilyEcdsaKeyIdentity,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';

export type EvmFamilyEcdsaAuthMethod =
  | typeof SIGNER_AUTH_METHODS.emailOtp
  | typeof SIGNER_AUTH_METHODS.passkey;

export type ResolvedEvmFamilyEcdsaSigningLane = EcdsaTransactionSigningLane & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: EvmFamilyChain;
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: ReturnType<typeof requireEvmFamilyEcdsaSigner>['keyHandle'];
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
    emailOtpRetention:
      record.source === 'email_otp'
        ? emailOtpAuthContextRetention(record.emailOtpAuthContext)
        : null,
    emailOtpReason:
      record.source === 'email_otp' ? emailOtpAuthContextReason(record.emailOtpAuthContext) : null,
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
  const signer = requireEvmFamilyEcdsaSigner(lane.identity, 'ECDSA lane summary');
  return {
    present: true,
    walletId: signer.walletId,
    authMethod: signingLaneAuthMethod(lane.auth),
    curve: lane.curve,
    chain: lane.chain,
    chainFamily: 'chainFamily' in lane ? lane.chainFamily : lane.chain,
    keyKind: 'keyKind' in lane ? lane.keyKind : 'threshold_ecdsa_secp256k1',
    sessionOrigin: 'sessionOrigin' in lane ? lane.sessionOrigin : undefined,
    storageSource: 'storageSource' in lane ? lane.storageSource : undefined,
    retention: 'retention' in lane ? lane.retention : undefined,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
    chainTarget: signer.chainTarget,
    evmFamilyKeyPresent: Boolean(signer.key),
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
  const identity = lane.identity;
  const signer = requireEvmFamilyEcdsaSigner(identity, `${args.context} resolved ECDSA lane`);
  const chainTarget = signer.chainTarget;
  if (chainTarget.kind !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane chain mismatch', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} chain does not match selected lane`);
  }

  const key = signer.key;
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
    String(key.walletId) !== String(signer.walletId) ||
    String(signer.keyHandle || '').trim() === ''
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
    keyHandle: signer.keyHandle,
    walletId: signer.walletId,
    auth: identity.auth,
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    chainTarget,
  });

  return {
    ...lane,
    ...selectedLane,
    key,
    keyHandle: signer.keyHandle,
    chainTarget,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: signer.chainTarget.kind,
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
  const signer = requireEvmFamilyEcdsaSigner(
    lane.identity,
    `${args.context} updated ECDSA lane`,
  );
  const updatedSelectedLane = selectedEcdsaLane({
    key: signer.key,
    keyHandle: signer.keyHandle,
    walletId: signer.walletId,
    auth: lane.auth,
    chainTarget: signer.chainTarget,
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
  });
  return {
    ...lane,
    ...updatedSelectedLane,
    key: signer.key,
    keyHandle: signer.keyHandle,
    chainTarget: signer.chainTarget,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: signer.chainTarget.kind,
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
  const signer = requireEvmFamilyEcdsaSigner(
    args.lane.identity,
    `${args.context} material identity`,
  );
  const laneKeyHandle = String(signer.keyHandle || '').trim();
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
    key: signer.key,
    keyHandle,
    walletId: signer.walletId,
    auth: args.lane.auth,
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

export function buildEvmFamilyEcdsaSigningLaneContext(args: {
  walletId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  material: ReadyEvmFamilyEcdsaMaterial;
}): ResolvedEvmFamilyEcdsaSigningLane | undefined {
  const { key, lane: materialLane, record } = args.material;
  if (String(key.walletId) !== String(args.walletId)) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched wallet identity', {
      walletId: args.walletId,
      materialWalletId: key.walletId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
    });
    return undefined;
  }
  if (!thresholdEcdsaChainTargetsEqual(materialLane.chainTarget, args.chainTarget)) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched chain target', {
      walletId: args.walletId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      materialChainTarget: materialLane.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
    });
    return undefined;
  }
  if (materialLane.authMethod !== args.authMethod || materialLane.source !== args.source) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched auth source', {
      walletId: args.walletId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      materialAuthMethod: materialLane.authMethod,
      materialSource: materialLane.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
    });
    return undefined;
  }
  let recordCandidate: ReturnType<typeof thresholdEcdsaLaneCandidateFromSessionRecord>;
  try {
    recordCandidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record });
  } catch (error) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from missing exact auth binding', {
      walletId: args.walletId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      message: error instanceof Error ? error.message : String(error),
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
    });
    return undefined;
  }

  const base = {
    key,
    keyHandle: record.keyHandle,
    walletId: toWalletId(key.walletId),
    signingGrantId: materialLane.signingGrantId,
    thresholdSessionId: materialLane.thresholdSessionId,
  };
  const buildLane =
    args.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;

  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    if (recordCandidate.auth.kind !== 'email_otp') {
      logEvmFamilyEcdsaLaneDiagnostic('Email OTP ECDSA lane is missing Email OTP auth binding', {
        walletId: args.walletId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
      });
      return undefined;
    }
    const emailOtpAuthContext = record?.source === 'email_otp' ? record.emailOtpAuthContext : null;
    const lane = buildLane({
      ...base,
      auth: recordCandidate.auth,
      chainTarget: args.chainTarget,
      retention: emailOtpAuthContext
        ? emailOtpAuthContextRetention(emailOtpAuthContext)
        : 'session',
      sessionOrigin:
        emailOtpAuthContext && emailOtpAuthContextReason(emailOtpAuthContext) === 'login'
          ? 'login'
          : 'per_operation',
    });
    return requireResolvedEvmFamilyEcdsaSigningLane({
      lane,
      chain: args.chain,
      context: 'build EVM-family ECDSA signing lane',
    });
  }

  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return undefined;
  if (recordCandidate.auth.kind !== 'passkey') {
    logEvmFamilyEcdsaLaneDiagnostic('passkey ECDSA lane is missing passkey auth binding', {
      walletId: args.walletId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
    });
    return undefined;
  }
  const lane = buildLane({
    ...base,
    auth: recordCandidate.auth,
    chainTarget: args.chainTarget,
    storageSource: args.source,
  });
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: args.chain,
    context: 'build EVM-family ECDSA signing lane',
  });
}

export function tryGetPasskeyThresholdEcdsaSessionRecordForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  walletId: EcdsaSigningLookupArgs['walletId'];
  chainTarget: ThresholdEcdsaChainTarget;
  source: PasskeyEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord | undefined {
  let candidate: ThresholdEcdsaSessionRecord | undefined;
  try {
    candidate = args.deps.getPasskeyThresholdEcdsaSessionRecordForSigning({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      source: args.source,
    });
  } catch {
    candidate = undefined;
  }
  return candidate && !isEmailOtpThresholdEcdsaSigningContext({ record: candidate })
    ? candidate
    : undefined;
}

export function isEmailOtpThresholdEcdsaSigningContext(args: {
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
}): boolean {
  const record = args.record;
  return (
    record.source === SIGNER_AUTH_METHODS.emailOtp ||
    record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
  );
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
      authMethod: selectedLaneAuthMethod(args.lane),
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
  const signer = requireEvmFamilyEcdsaSigner(lane.identity, 'selected ECDSA record validation');
  if (String(record.walletId || '') !== String(signer.walletId)) {
    return 'wallet id mismatch';
  }
  if (
    !ecdsaMaterialSourceMatchesAuth({
      authMethod: selectedLaneAuthMethod(lane),
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
    return 'signing grant id mismatch';
  }
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, signer.chainTarget)) {
    return 'chain mismatch';
  }
  try {
    const readModel = thresholdEcdsaSessionRecordReadModel(record);
    if (!readModel.key) return 'record key identity mismatch';
  } catch {
    return 'record key identity mismatch';
  }
  if (String(record.keyHandle || '').trim() !== String(signer.keyHandle || '').trim()) {
    return 'key handle mismatch';
  }
  return null;
}
