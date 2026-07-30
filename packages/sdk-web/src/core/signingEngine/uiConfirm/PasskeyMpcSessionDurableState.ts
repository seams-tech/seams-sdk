import type {
  WarmSessionSealAndPersistDiagnostics,
  WarmSessionSealAndPersistResult,
} from '../../types/secure-confirm-worker';
import {
  buildCurrentSealedSessionRecord,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
  type CurrentEd25519RestoreMetadata,
  type CurrentSealedSessionRecord,
  type SigningSessionSealedRecordFilter,
  type SigningSessionSealedStoreRecord,
} from '../session/persistence/sealedSessionStore';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionRecord,
} from '../session/persistence/records';
import { parseRouterAbEd25519WalletSessionAuthorityFromRecord } from '../session/routerAbSigningWalletSession';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
} from '../session/identity/laneIdentity';
import type { ThresholdEd25519SessionStoreSource } from '../session/identity/laneIdentity';
import { thresholdEcdsaChainTargetKey } from '../interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetsEqual } from '../interfaces/ecdsaChainTarget';
import {
  SIGNING_SESSION_SEAL_GROUP_ID,
  type SealedSigningSessionWalletSessionAuth,
} from '@shared/utils/signingSessionSeal';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '../session/passkey/warmSessionMaterialWriter';
import type { WarmSessionLanePurpose } from '../session/emailOtp/sealedRuntimePurpose';
import type {
  PasskeyWarmSessionSealTransportInput,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './uiConfirm.types';

type PasskeyMpcSessionDurableStateDeps = {
  signingSessionPersistenceMode: 'none' | 'sealed_refresh_v1';
  sealAndPersistWarmSessionMaterial(args: {
    sessionId: string;
    transport: PasskeyWarmSessionSealTransportInput;
  }): Promise<WarmSessionSealAndPersistResult>;
  readWarmSessionStatus(args: { sessionId: string }): Promise<WarmSessionStatusResult>;
};

type PasskeySealedRecordAccountMetadata = {
  walletId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaRestore?: SigningSessionSealedStoreRecord['ecdsaRestore'];
  ed25519Restore?: CurrentEd25519RestoreMetadata;
};

const signingSessionSealPersistSingleFlight = new Map<
  string,
  Promise<WarmSessionSealAndPersistResult>
>();

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function roundDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function recordDiagnosticDuration(args: {
  diagnostics: WarmSessionMaterialWriteDiagnostics | undefined;
  bucket: WarmSessionMaterialWriteDiagnosticBucket;
  startedAt: number;
}): void {
  args.diagnostics?.recordDuration(args.bucket, roundDurationMs(args.startedAt));
}

function recordSealResultDiagnostics(args: {
  diagnostics: WarmSessionMaterialWriteDiagnostics | undefined;
  resultDiagnostics: WarmSessionSealAndPersistDiagnostics | undefined;
}): void {
  if (!args.diagnostics || !args.resultDiagnostics) return;
  args.diagnostics.recordDuration(
    'sealed_record_apply_runtime_setup',
    args.resultDiagnostics.runtimeSetupMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_client_seal',
    args.resultDiagnostics.clientSealMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_server_route',
    args.resultDiagnostics.serverSealRouteMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_client_unseal',
    args.resultDiagnostics.clientUnsealMs,
  );
  args.diagnostics.recordDuration(
    'sealed_record_apply_policy_update',
    args.resultDiagnostics.policyUpdateMs,
  );
}

function assertNever(value: never): never {
  throw new Error(`Unexpected warm-session seal auth source: ${String(value)}`);
}

function sealedAuthMethodForThresholdEd25519Source(
  source: ThresholdEd25519SessionStoreSource,
): 'passkey' | 'email_otp' {
  switch (source) {
    case 'email_otp':
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNever(source);
  }
}

function ed25519RestoreWalletSessionAuthFields(
  record: ThresholdEd25519SessionRecord,
): SealedSigningSessionWalletSessionAuth | null {
  if (record.thresholdSessionKind === 'jwt') {
    const authority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
    return authority.ok
      ? { sessionKind: 'jwt', walletSessionJwt: authority.value.auth.walletSessionJwt }
      : null;
  }
  return record.thresholdSessionKind === 'cookie' ? { sessionKind: 'cookie' } : null;
}

type CurrentEd25519RestoreAuthBranch =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      provider: 'google' | 'email';
      providerSubjectId: string;
      emailHashHex: string;
    };

function currentEd25519RestoreAuthBranchFromRecord(
  record: ThresholdEd25519SessionRecord,
): CurrentEd25519RestoreAuthBranch | null {
  if (record.source === 'email_otp') {
    if (!record.emailOtpAuthContext) return null;
    const providerSubjectId = emailOtpAuthContextProviderUserId(record.emailOtpAuthContext);
    const provider = emailOtpAuthContextProvider(record.emailOtpAuthContext);
    const emailHashHex = emailOtpAuthContextEmailHashHex(record.emailOtpAuthContext);
    return providerSubjectId && emailHashHex
      ? { kind: 'email_otp', provider, providerSubjectId, emailHashHex }
      : null;
  }
  const credentialIdB64u = String(record.passkeyCredentialIdB64u || '').trim();
  return credentialIdB64u ? { kind: 'passkey', credentialIdB64u } : null;
}

function currentEd25519RestoreMetadataFromSessionRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): CurrentEd25519RestoreMetadata | undefined {
  if (!record) return undefined;
  const rpId = String(record.rpId || '').trim();
  const nearAccountId = String(record.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(record.nearEd25519SigningKeyId || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const signerSlot = positiveInteger(record.signerSlot);
  const routerAbNormalSigning = record.routerAbNormalSigning;
  const authBranch = currentEd25519RestoreAuthBranchFromRecord(record);
  const walletSessionAuth = ed25519RestoreWalletSessionAuthFields(record);
  if (
    !rpId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !relayerKeyId ||
    !record.participantIds.length ||
    !signerSlot ||
    !routerAbNormalSigning ||
    authBranch?.kind !== 'passkey' ||
    !walletSessionAuth
  ) {
    return undefined;
  }
  return {
    rpId,
    nearAccountId,
    nearEd25519SigningKeyId,
    relayerKeyId,
    participantIds: record.participantIds,
    ...walletSessionAuth,
    signerSlot,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    routerAbNormalSigning,
    credentialIdB64u: authBranch.credentialIdB64u,
  };
}

function buildPasskeySealedRecordAccountMetadata(args: {
  thresholdSessionId: string;
  transport: PasskeyWarmSessionSealTransportInput;
}): PasskeySealedRecordAccountMetadata {
  if (args.transport.curve === 'ecdsa') {
    return {
      ...(args.transport.walletId ? { walletId: args.transport.walletId } : {}),
      ...(args.transport.ecdsaRestore ? { ecdsaRestore: args.transport.ecdsaRestore } : {}),
    };
  }
  const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  if (
    ed25519Record &&
    sealedAuthMethodForThresholdEd25519Source(ed25519Record.source) !== 'passkey'
  ) {
    return {};
  }
  const walletId = String(ed25519Record?.walletId || args.transport.walletId || '').trim();
  const ed25519Restore = currentEd25519RestoreMetadataFromSessionRecord(ed25519Record);
  return {
    ...(walletId ? { walletId } : {}),
    ...(ed25519Record?.signingRootId ? { signingRootId: ed25519Record.signingRootId } : {}),
    ...(ed25519Record?.signingRootVersion
      ? { signingRootVersion: ed25519Record.signingRootVersion }
      : {}),
    ...(ed25519Restore ? { ed25519Restore } : {}),
  };
}

function sealedRecordPurpose(args: {
  transport: PasskeyWarmSessionSealTransportInput;
}): SigningSessionSealedRecordFilter | null {
  if (args.transport.curve === 'ed25519') {
    return { authMethod: 'passkey', curve: 'ed25519' };
  }
  return {
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.transport.chainTarget,
  };
}

function persistenceSingleFlightKey(args: {
  thresholdSessionId: string;
  transport: PasskeyWarmSessionSealTransportInput;
}): string {
  if (args.transport.curve === 'ecdsa') {
    const material = args.transport.ecdsaRestore?.roleLocalMaterialRef;
    return [
      'persist',
      'passkey',
      'ecdsa',
      thresholdEcdsaChainTargetKey(args.transport.chainTarget),
      material?.materialActivation.activationId || args.thresholdSessionId,
      material?.durableMaterialRef || '',
      material?.bindingDigest || '',
    ].join('|');
  }
  return [
    'persist',
    'passkey',
    'ed25519',
    args.thresholdSessionId,
  ].join('|');
}

function buildCurrentRecordInput(args: {
  thresholdSessionId: string;
  transport: PasskeyWarmSessionSealTransportInput;
  metadata: PasskeySealedRecordAccountMetadata;
  sealedSecretB64u: string;
  signingGrantId: string;
  relayerUrl: string;
  keyVersion: string;
  groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
  existing?: CurrentSealedSessionRecord;
}): BuildCurrentSealedSessionRecordInput {
  if (args.transport.curve === 'ecdsa') {
    const walletId = String(args.metadata.walletId || '').trim();
    if (!walletId || !args.metadata.ecdsaRestore) {
      throw new Error('[SigningSessionSealedStore] missing Passkey ECDSA seal metadata');
    }
    const thresholdSessionIds =
      args.existing?.curve === 'ecdsa'
        ? args.existing.thresholdSessionIds
        : { ecdsa: args.thresholdSessionId };
    return {
      thresholdSessionId: args.thresholdSessionId,
      sealedSecretB64u: args.sealedSecretB64u,
      curve: 'ecdsa',
      authMethod: 'passkey',
      signingGrantId: args.signingGrantId,
      thresholdSessionIds,
      walletId,
      relayerUrl: args.relayerUrl,
      keyVersion: args.keyVersion,
      groupId: args.groupId,
      ecdsaRestore: args.metadata.ecdsaRestore,
      ...(args.metadata.ed25519Restore
        ? { ed25519Restore: args.metadata.ed25519Restore }
        : {}),
      issuedAtMs: args.issuedAtMs,
      expiresAtMs: args.expiresAtMs,
      remainingUses: args.remainingUses,
      updatedAtMs: args.updatedAtMs,
    };
  }
  const walletId = String(args.metadata.walletId || '').trim();
  if (!walletId || !args.metadata.ed25519Restore) {
    throw new Error('[SigningSessionSealedStore] missing Passkey Ed25519 seal metadata');
  }
  const thresholdSessionIds =
    args.existing?.curve === 'ed25519'
      ? args.existing.thresholdSessionIds
      : { ed25519: args.thresholdSessionId };
  return {
    thresholdSessionId: args.thresholdSessionId,
    sealedSecretB64u: args.sealedSecretB64u,
    curve: 'ed25519',
    authMethod: 'passkey',
    signingGrantId: args.signingGrantId,
    thresholdSessionIds,
    walletId,
    ...(args.metadata.signingRootId ? { signingRootId: args.metadata.signingRootId } : {}),
    ...(args.metadata.signingRootVersion
      ? { signingRootVersion: args.metadata.signingRootVersion }
      : {}),
    relayerUrl: args.relayerUrl,
    keyVersion: args.keyVersion,
    groupId: args.groupId,
    ...(args.metadata.ecdsaRestore ? { ecdsaRestore: args.metadata.ecdsaRestore } : {}),
    ed25519Restore: args.metadata.ed25519Restore,
    issuedAtMs: args.issuedAtMs,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
    updatedAtMs: args.updatedAtMs,
  };
}

async function writeCurrentRecord(
  input: BuildCurrentSealedSessionRecordInput,
): Promise<void> {
  const record = buildCurrentSealedSessionRecord(input);
  if (!record) {
    throw new Error('[SigningSessionSealedStore] invalid sealed session record write input');
  }
  await writeExactSealedSession(record);
}

function jsonFactsEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function ecdsaRestoreNamesSameMaterial(
  left: NonNullable<PasskeySealedRecordAccountMetadata['ecdsaRestore']>,
  right: NonNullable<PasskeySealedRecordAccountMetadata['ecdsaRestore']>,
): boolean {
  return (
    left.source === right.source &&
    thresholdEcdsaChainTargetsEqual(left.chainTarget, right.chainTarget) &&
    left.keyHandle === right.keyHandle &&
    left.ecdsaThresholdKeyId === right.ecdsaThresholdKeyId &&
    left.ethereumAddress === right.ethereumAddress &&
    left.relayerKeyId === right.relayerKeyId &&
    left.clientVerifyingShareB64u === right.clientVerifyingShareB64u &&
    left.thresholdEcdsaPublicKeyB64u === right.thresholdEcdsaPublicKeyB64u &&
    left.roleLocalMaterialRef.materialActivation.activationId ===
      right.roleLocalMaterialRef.materialActivation.activationId &&
    left.roleLocalMaterialRef.durableMaterialRef ===
      right.roleLocalMaterialRef.durableMaterialRef &&
    left.roleLocalMaterialRef.bindingDigest === right.roleLocalMaterialRef.bindingDigest &&
    jsonFactsEqual(left.participantIds, right.participantIds) &&
    jsonFactsEqual(left.authority, right.authority) &&
    jsonFactsEqual(left.publicCapability, right.publicCapability) &&
    jsonFactsEqual(
      left.routerAbEcdsaDerivationNormalSigning,
      right.routerAbEcdsaDerivationNormalSigning,
    )
  );
}

function existingRecordMatchesRequest(args: {
  existing: CurrentSealedSessionRecord;
  thresholdSessionId: string;
  transport: PasskeyWarmSessionSealTransportInput;
  metadata: PasskeySealedRecordAccountMetadata;
}): boolean {
  if (args.existing.curve !== args.transport.curve) return false;
  const requestedWalletId = String(args.transport.walletId || '').trim();
  if (requestedWalletId && requestedWalletId !== args.existing.walletId) return false;
  if (args.existing.curve === 'ed25519' && args.transport.curve === 'ed25519') {
    return args.existing.thresholdSessionIds.ed25519 === args.thresholdSessionId;
  }
  if (args.existing.curve !== 'ecdsa' || args.transport.curve !== 'ecdsa') return false;
  if (
    !thresholdEcdsaChainTargetsEqual(
      args.existing.ecdsaRestore.chainTarget,
      args.transport.chainTarget,
    )
  ) {
    return false;
  }
  if (
    args.existing.ecdsaRestore.roleLocalMaterialRef.materialActivation.activationId !==
    args.thresholdSessionId
  ) {
    return false;
  }
  const requestedRestore = args.metadata.ecdsaRestore;
  return requestedRestore
    ? ecdsaRestoreNamesSameMaterial(args.existing.ecdsaRestore, requestedRestore)
    : true;
}

function existingRecordMetadata(
  existing: CurrentSealedSessionRecord,
): PasskeySealedRecordAccountMetadata {
  return existing.curve === 'ecdsa'
    ? {
        walletId: existing.walletId,
        ecdsaRestore: existing.ecdsaRestore,
        ...(existing.ed25519Restore ? { ed25519Restore: existing.ed25519Restore } : {}),
      }
    : {
        walletId: existing.walletId,
        ...(existing.signingRootId ? { signingRootId: existing.signingRootId } : {}),
        ...(existing.signingRootVersion
          ? { signingRootVersion: existing.signingRootVersion }
          : {}),
        ...(existing.ecdsaRestore ? { ecdsaRestore: existing.ecdsaRestore } : {}),
        ed25519Restore: existing.ed25519Restore,
      };
}

function normalizedPasskeyTransport(
  transport: PasskeyWarmSessionSealTransportInput,
  groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID,
): PasskeyWarmSessionSealTransportInput {
  if (transport.curve === 'ecdsa') {
    return { ...transport, authMethod: 'passkey', groupId };
  }
  return { ...transport, authMethod: 'passkey', groupId };
}

export class PasskeyMpcSessionDurableState {
  constructor(private readonly deps: PasskeyMpcSessionDurableStateDeps) {}

  async persistSigningSessionSealForThresholdSession(args: {
    sessionId: string;
    transport: PasskeyWarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult> {
    if (this.deps.signingSessionPersistenceMode !== 'sealed_refresh_v1') {
      return {
        ok: false,
        code: 'not_enabled',
        message:
          'Passkey signing-session seal persistence requires signingSessionPersistenceMode="sealed_refresh_v1"',
      };
    }
    const thresholdSessionId = String(args.sessionId || '').trim();
    if (!thresholdSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
    }
    const signingGrantId = String(args.transport.signingGrantId || '').trim();
    const relayerUrl = String(args.transport.relayerUrl || '').trim();
    if (!signingGrantId || !relayerUrl) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Passkey seal persistence requires signingGrantId and relayerUrl',
      };
    }
    const metadata = buildPasskeySealedRecordAccountMetadata({
      thresholdSessionId,
      transport: args.transport,
    });
    const purpose = sealedRecordPurpose({ transport: args.transport });
    if (!purpose) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Passkey seal persistence requires one exact record purpose',
      };
    }
    const singleFlightKey = persistenceSingleFlightKey({
      thresholdSessionId,
      transport: args.transport,
    });
    const inFlight = signingSessionSealPersistSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = this.persistExactRecord({
      thresholdSessionId,
      transport: args.transport,
      metadata,
      purpose,
      signingGrantId,
      relayerUrl,
      diagnostics: args.diagnostics,
    }).finally(() => {
      signingSessionSealPersistSingleFlight.delete(singleFlightKey);
    });
    signingSessionSealPersistSingleFlight.set(singleFlightKey, task);
    return await task;
  }

  async recordPolicyResult(
    purpose: WarmSessionLanePurpose,
    result: WarmSessionStatusResult | WarmSessionClaimResult,
  ): Promise<void> {
    const existing = await this.readRecordForPurpose(purpose);
    if (!existing) return;
    if (result.ok) {
      await this.writePolicy(existing, result.expiresAtMs, Math.max(0, result.remainingUses));
      return;
    }
    if (result.code === 'exhausted') {
      await this.writePolicy(existing, existing.expiresAtMs, 0);
      return;
    }
    if (result.code === 'expired') {
      await this.writePolicy(
        existing,
        Math.min(existing.expiresAtMs, Date.now()),
        Math.max(0, existing.remainingUses),
      );
    }
  }

  async updatePersistedPolicy(args: {
    thresholdSessionId: string;
    purpose: Extract<WarmSessionLanePurpose, { curve: 'ecdsa' }>;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    const existing = await this.readRecordForPurpose(args.purpose);
    if (
      !existing ||
      existing.curve !== 'ecdsa' ||
      existing.thresholdSessionIds.ecdsa !== args.thresholdSessionId ||
      existing.ecdsaRestore.roleLocalMaterialRef.materialActivation.activationId !==
        args.thresholdSessionId
    ) {
      return;
    }
    await this.writePolicy(existing, args.expiresAtMs, args.remainingUses);
  }

  private async persistExactRecord(args: {
    thresholdSessionId: string;
    transport: PasskeyWarmSessionSealTransportInput;
    metadata: PasskeySealedRecordAccountMetadata;
    purpose: SigningSessionSealedRecordFilter;
    signingGrantId: string;
    relayerUrl: string;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult> {
    const existingReadStartedAt = performance.now();
    let existing: CurrentSealedSessionRecord | null;
    try {
      existing = await readExactSealedSession(args.thresholdSessionId, args.purpose);
    } catch (error) {
      recordDiagnosticDuration({
        diagnostics: args.diagnostics,
        bucket: 'sealed_record_existing_read',
        startedAt: existingReadStartedAt,
      });
      return {
        ok: false,
        code: 'local_persist_failed',
        message:
          error instanceof Error
            ? `Failed to read the existing sealed session: ${error.message}`
            : 'Failed to read the existing sealed session',
      };
    }
    recordDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'sealed_record_existing_read',
      startedAt: existingReadStartedAt,
    });
    if (existing) {
      if (
        !existingRecordMatchesRequest({
          existing,
          thresholdSessionId: args.thresholdSessionId,
          transport: args.transport,
          metadata: args.metadata,
        })
      ) {
        return {
          ok: false,
          code: 'binding_mismatch',
          message: 'Existing sealed session names different material',
        };
      }
      const policyReadStartedAt = performance.now();
      let policy: WarmSessionStatusResult;
      try {
        policy = await this.deps.readWarmSessionStatus({
          sessionId: args.thresholdSessionId,
        });
      } catch (error) {
        return {
          ok: false,
          code: 'worker_error',
          message:
            error instanceof Error
              ? `Failed to read warm-session policy: ${error.message}`
              : 'Failed to read warm-session policy',
        };
      }
      recordDiagnosticDuration({
        diagnostics: args.diagnostics,
        bucket: 'sealed_record_policy_read',
        startedAt: policyReadStartedAt,
      });
      const metadata = existingRecordMetadata(existing);
      const policyExpiresAtMs = policy.ok
        ? policy.expiresAtMs
        : policy.code === 'expired'
          ? Math.min(existing.expiresAtMs, Date.now())
          : existing.expiresAtMs;
      const policyRemainingUses = policy.ok
        ? policy.remainingUses
        : policy.code === 'exhausted'
          ? 0
          : existing.remainingUses;
      if (!policy.ok && policy.code !== 'expired' && policy.code !== 'exhausted') {
        return policy;
      }
      const registerStartedAt = performance.now();
      await writeCurrentRecord(
        buildCurrentRecordInput({
          thresholdSessionId: args.thresholdSessionId,
          transport: args.transport,
          metadata,
          sealedSecretB64u: existing.sealedSecretB64u,
          signingGrantId: args.signingGrantId,
          relayerUrl: existing.relayerUrl,
          keyVersion: existing.keyVersion,
          groupId: existing.groupId,
          issuedAtMs: existing.issuedAtMs,
          expiresAtMs: policyExpiresAtMs,
          remainingUses: policyRemainingUses,
          updatedAtMs: Date.now(),
          existing,
        }),
      );
      recordDiagnosticDuration({
        diagnostics: args.diagnostics,
        bucket: 'sealed_record_register',
        startedAt: registerStartedAt,
      });
      return {
        ok: true,
        sealedSecretB64u: existing.sealedSecretB64u,
        keyVersion: existing.keyVersion,
        remainingUses: policyRemainingUses,
        expiresAtMs: policyExpiresAtMs,
      };
    }

    if (args.transport.curve === 'ecdsa' && !args.metadata.ecdsaRestore) {
      return {
        ok: false,
        code: 'missing_restore_metadata',
        message: 'Passkey ECDSA seal persistence requires exact restore metadata',
      };
    }
    if (
      args.transport.curve === 'ecdsa' &&
      args.metadata.ecdsaRestore &&
      (!thresholdEcdsaChainTargetsEqual(
        args.transport.chainTarget,
        args.metadata.ecdsaRestore.chainTarget,
      ) ||
        args.metadata.ecdsaRestore.roleLocalMaterialRef.materialActivation.activationId !==
          args.thresholdSessionId)
    ) {
      return {
        ok: false,
        code: 'binding_mismatch',
        message: 'Passkey ECDSA seal transport and restore metadata name different material',
      };
    }
    if (args.transport.curve === 'ed25519' && !args.metadata.ed25519Restore) {
      return {
        ok: false,
        code: 'missing_restore_metadata',
        message: 'Passkey Ed25519 seal persistence requires exact restore metadata',
      };
    }

    const requestedGroupId = String(
      args.transport.groupId || SIGNING_SESSION_SEAL_GROUP_ID,
    ).trim();
    if (requestedGroupId !== SIGNING_SESSION_SEAL_GROUP_ID) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Unsupported groupId for Passkey signing-session seal persistence',
      };
    }
    const groupId = SIGNING_SESSION_SEAL_GROUP_ID;
    const sealStartedAt = performance.now();
    const sealed = await this.deps.sealAndPersistWarmSessionMaterial({
      sessionId: args.thresholdSessionId,
      transport: normalizedPasskeyTransport(args.transport, groupId),
    });
    recordDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'sealed_record_apply_server_seal',
      startedAt: sealStartedAt,
    });
    recordSealResultDiagnostics({
      diagnostics: args.diagnostics,
      resultDiagnostics: sealed.ok ? sealed.diagnostics : undefined,
    });
    if (!sealed.ok) return sealed;
    const keyVersion = String(sealed.keyVersion || '').trim();
    if (!keyVersion) {
      return {
        ok: false,
        code: 'invalid_key_version',
        message: 'Signing-session seal response did not include a key version',
      };
    }
    const persistedAtMs = Date.now();
    const registerStartedAt = performance.now();
    await writeCurrentRecord(
      buildCurrentRecordInput({
        thresholdSessionId: args.thresholdSessionId,
        transport: args.transport,
        metadata: args.metadata,
        sealedSecretB64u: sealed.sealedSecretB64u,
        signingGrantId: args.signingGrantId,
        relayerUrl: args.relayerUrl,
        keyVersion,
        groupId,
        issuedAtMs: persistedAtMs,
        expiresAtMs: sealed.expiresAtMs,
        remainingUses: sealed.remainingUses,
        updatedAtMs: persistedAtMs,
      }),
    );
    recordDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'sealed_record_register',
      startedAt: registerStartedAt,
    });
    const verifyReadStartedAt = performance.now();
    let persisted: CurrentSealedSessionRecord | null;
    try {
      persisted = await readExactSealedSession(args.thresholdSessionId, args.purpose);
    } catch {
      persisted = null;
    }
    recordDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'sealed_record_verify_read',
      startedAt: verifyReadStartedAt,
    });
    if (!persisted) {
      return {
        ok: false,
        code: 'local_persist_failed',
        message: 'Failed to persist sealed signing-session record locally',
      };
    }
    return sealed;
  }

  private async readRecordForPurpose(
    purpose: WarmSessionLanePurpose,
  ): Promise<CurrentSealedSessionRecord | null> {
    const filter: SigningSessionSealedRecordFilter =
      purpose.curve === 'ecdsa'
        ? {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget: purpose.chainTarget,
          }
        : { authMethod: 'passkey', curve: 'ed25519' };
    return await readExactSealedSession(purpose.thresholdSessionId, filter);
  }

  private async writePolicy(
    existing: CurrentSealedSessionRecord,
    expiresAtMs: number,
    remainingUses: number,
  ): Promise<void> {
    const filter: SigningSessionSealedRecordFilter =
      existing.curve === 'ecdsa'
        ? {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chainTarget: existing.ecdsaRestore.chainTarget,
          }
        : { authMethod: 'passkey', curve: 'ed25519' };
    await updateExactSealedSessionPolicy({
      thresholdSessionId:
        existing.curve === 'ecdsa'
          ? existing.thresholdSessionIds.ecdsa
          : existing.thresholdSessionIds.ed25519,
      filter,
      expiresAtMs: Math.max(1, Math.floor(expiresAtMs)),
      remainingUses: Math.max(0, Math.floor(remainingUses)),
      updatedAtMs: Date.now(),
    });
  }
}
