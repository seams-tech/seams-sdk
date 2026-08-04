import type {
  WarmSessionSealAndPersistDiagnostics,
  WarmSessionSealAndPersistResult,
} from '../../types/secure-confirm-worker';
import {
  buildCurrentSealedSessionRecord,
  readExactEd25519SealedSession,
  readExactSealedSession,
  updateExactEd25519SealedSessionPolicy,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
  type CurrentEd25519RestoreMetadata,
  type CurrentSealedSessionRecord,
  type SigningSessionSealedRecordFilter,
  type SigningSessionSealedStoreRecord,
} from '../session/persistence/sealedSessionStore';
import { thresholdEcdsaChainTargetKey } from '../interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetsEqual } from '../interfaces/ecdsaChainTarget';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
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
import {
  ed25519DurableMaterialLocator,
  materialActivationKey,
} from '../session/sealedRecovery/materialActivationKey';

type PasskeyMpcSessionDurableStateDeps = {
  signingSessionPersistenceMode: 'none' | 'sealed_refresh_v1';
  sealAndPersistWarmSessionMaterial(args: {
    thresholdSessionId: string;
    transport: PasskeyWarmSessionSealTransportInput;
  }): Promise<WarmSessionSealAndPersistResult>;
  readWarmSessionStatus(args: { thresholdSessionId: string }): Promise<WarmSessionStatusResult>;
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

function buildPasskeySealedRecordAccountMetadata(args: {
  transport: PasskeyWarmSessionSealTransportInput;
}): PasskeySealedRecordAccountMetadata {
  if (args.transport.curve === 'ecdsa') {
    const walletId = String(args.transport.walletId).trim();
    const restoreWalletId = String(args.transport.ecdsaRestore.authority.walletId).trim();
    if (!walletId || !restoreWalletId || walletId !== restoreWalletId) {
      throw new Error(
        'Passkey ECDSA seal transport wallet does not match restore metadata',
      );
    }
    return {
      walletId,
      ecdsaRestore: args.transport.ecdsaRestore,
    };
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(
    normalizeRuntimePolicyScope(args.transport.ed25519Restore.runtimePolicyScope),
  );
  return {
    walletId: args.transport.walletId,
    signingRootId: signingRoot.signingRootId,
    ...(signingRoot.signingRootVersion
      ? { signingRootVersion: signingRoot.signingRootVersion }
      : {}),
    ed25519Restore: args.transport.ed25519Restore,
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
    if (!material) {
      throw new Error('Passkey ECDSA persistence requires exact restore metadata');
    }
    return [
      'persist',
      'passkey',
      'ecdsa',
      thresholdEcdsaChainTargetKey(args.transport.chainTarget),
      material.materialActivation.activationId,
      material.materialActivation.capability,
      material.materialActivation.materialOwner,
      material.materialActivation.keyBinding,
      material.materialActivation.lifecycleBinding,
      material.materialActivation.signingWorker,
      material.durableMaterialRef,
      material.bindingDigest,
    ].join('|');
  }
  const locator = ed25519DurableMaterialLocator({
    authMethod: 'passkey',
    materialActivation: args.transport.ed25519Restore.materialActivation,
  });
  return [
    'persist',
    locator.kind,
    locator.authMethod,
    materialActivationKey(locator.materialActivation),
  ].join('|');
}

type BuildCurrentRecordInputArgs = {
  thresholdSessionId: string;
  metadata: PasskeySealedRecordAccountMetadata;
  sealedSecretB64u: string;
  relayerUrl: string;
  keyVersion: string;
  groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
  existing?: CurrentSealedSessionRecord;
} & (
  | {
      transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ed25519' }>;
    }
  | {
      transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ecdsa' }>;
    }
);

function isEd25519BuildCurrentRecordInputArgs(
  args: BuildCurrentRecordInputArgs,
): args is BuildCurrentRecordInputArgs & {
  transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ed25519' }>;
} {
  return args.transport.curve === 'ed25519';
}

function buildCurrentRecordInput(
  args: BuildCurrentRecordInputArgs,
): BuildCurrentSealedSessionRecordInput {
  if (!isEd25519BuildCurrentRecordInputArgs(args)) {
    const walletId = String(args.metadata.walletId || '').trim();
    if (!walletId || !args.metadata.ecdsaRestore) {
      throw new Error('[SigningSessionSealedStore] missing Passkey ECDSA seal metadata');
    }
    const thresholdSessionIds = {
      ...args.existing?.thresholdSessionIds,
      ecdsa: args.thresholdSessionId,
    };
    return {
      thresholdSessionId: args.thresholdSessionId,
      sealedSecretB64u: args.sealedSecretB64u,
      curve: 'ecdsa',
      authMethod: 'passkey',
      thresholdSessionIds,
      walletId,
      relayerUrl: args.relayerUrl,
      keyVersion: args.keyVersion,
      groupId: args.groupId,
      ecdsaRestore: args.metadata.ecdsaRestore,
      ...(args.metadata.ed25519Restore ? { ed25519Restore: args.metadata.ed25519Restore } : {}),
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
  const thresholdSessionIds = {
    ...args.existing?.thresholdSessionIds,
    ed25519: args.thresholdSessionId,
  };
  return {
    thresholdSessionId: args.thresholdSessionId,
    sealedSecretB64u: args.sealedSecretB64u,
    curve: 'ed25519',
    authMethod: 'passkey',
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

type PersistExactRecordArgs = {
  thresholdSessionId: string;
  metadata: PasskeySealedRecordAccountMetadata;
  purpose: SigningSessionSealedRecordFilter;
  relayerUrl: string;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
} & (
  | {
      transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ed25519' }>;
    }
  | {
      transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ecdsa' }>;
    }
);

function isEd25519PersistExactRecordArgs(
  args: PersistExactRecordArgs,
): args is PersistExactRecordArgs & {
  transport: Extract<PasskeyWarmSessionSealTransportInput, { curve: 'ed25519' }>;
} {
  return args.transport.curve === 'ed25519';
}

async function writeCurrentRecord(input: BuildCurrentSealedSessionRecordInput): Promise<void> {
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
    mpcMaterialActivationRefsEqual(
      left.roleLocalMaterialRef.materialActivation,
      right.roleLocalMaterialRef.materialActivation,
    ) &&
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
  transport: PasskeyWarmSessionSealTransportInput;
  metadata: PasskeySealedRecordAccountMetadata;
}): boolean {
  if (args.existing.curve !== args.transport.curve) return false;
  const requestedWalletId = String(args.transport.walletId).trim();
  if (!requestedWalletId || requestedWalletId !== args.existing.walletId) return false;
  if (args.existing.curve === 'ed25519' && args.transport.curve === 'ed25519') {
    return mpcMaterialActivationRefsEqual(
      args.existing.ed25519Restore.materialActivation,
      args.transport.ed25519Restore.materialActivation,
    );
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
        ...(existing.signingRootVersion ? { signingRootVersion: existing.signingRootVersion } : {}),
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

async function readExactPasskeyRecord(args: {
  thresholdSessionId: string;
  transport: PasskeyWarmSessionSealTransportInput;
  purpose: SigningSessionSealedRecordFilter;
}): Promise<CurrentSealedSessionRecord | null> {
  if (args.transport.curve === 'ed25519') {
    return await readExactEd25519SealedSession(
      ed25519DurableMaterialLocator({
        authMethod: 'passkey',
        materialActivation: args.transport.ed25519Restore.materialActivation,
      }),
    );
  }
  return await readExactSealedSession(args.thresholdSessionId, args.purpose);
}

export class PasskeyMpcSessionDurableState {
  constructor(private readonly deps: PasskeyMpcSessionDurableStateDeps) {}

  async persistSigningSessionSealForThresholdSession(args: {
    thresholdSessionId: string;
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
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
    }
    const relayerUrl = String(args.transport.relayerUrl || '').trim();
    if (!relayerUrl) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Passkey seal persistence requires relayerUrl',
      };
    }
    const metadata = buildPasskeySealedRecordAccountMetadata({
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

    let persistTask: Promise<WarmSessionSealAndPersistResult>;
    if (args.transport.curve === 'ed25519') {
      persistTask = this.persistExactRecord({
        thresholdSessionId,
        transport: args.transport,
        metadata,
        purpose,
        relayerUrl,
        diagnostics: args.diagnostics,
      });
    } else {
      persistTask = this.persistExactRecord({
        thresholdSessionId,
        transport: args.transport,
        metadata,
        purpose,
        relayerUrl,
        diagnostics: args.diagnostics,
      });
    }
    const task = persistTask.finally(() => {
      signingSessionSealPersistSingleFlight.delete(singleFlightKey);
    });
    signingSessionSealPersistSingleFlight.set(singleFlightKey, task);
    return await task;
  }

  async recordPolicyResult(
    purpose: WarmSessionLanePurpose,
    thresholdSessionId: string,
    result: WarmSessionStatusResult | WarmSessionClaimResult,
  ): Promise<void> {
    const existing = await this.readRecordForPurpose(purpose, thresholdSessionId);
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
    const existing = await this.readRecordForPurpose(args.purpose, args.thresholdSessionId);
    if (
      !existing ||
      existing.curve !== 'ecdsa' ||
      existing.thresholdSessionIds.ecdsa !== args.thresholdSessionId
    ) {
      return;
    }
    await this.writePolicy(existing, args.expiresAtMs, args.remainingUses);
  }

  private async persistExactRecord(
    args: PersistExactRecordArgs,
  ): Promise<WarmSessionSealAndPersistResult> {
    const existingReadStartedAt = performance.now();
    let existing: CurrentSealedSessionRecord | null;
    try {
      existing = await readExactPasskeyRecord(args);
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
          thresholdSessionId: args.thresholdSessionId,
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
      const currentRecordInput = isEd25519PersistExactRecordArgs(args)
        ? buildCurrentRecordInput({
            thresholdSessionId: args.thresholdSessionId,
            transport: args.transport,
            metadata,
            sealedSecretB64u: existing.sealedSecretB64u,
            relayerUrl: existing.relayerUrl,
            keyVersion: existing.keyVersion,
            groupId: existing.groupId,
            issuedAtMs: existing.issuedAtMs,
            expiresAtMs: policyExpiresAtMs,
            remainingUses: policyRemainingUses,
            updatedAtMs: Date.now(),
            existing,
          })
        : buildCurrentRecordInput({
            thresholdSessionId: args.thresholdSessionId,
            transport: args.transport,
            metadata,
            sealedSecretB64u: existing.sealedSecretB64u,
            relayerUrl: existing.relayerUrl,
            keyVersion: existing.keyVersion,
            groupId: existing.groupId,
            issuedAtMs: existing.issuedAtMs,
            expiresAtMs: policyExpiresAtMs,
            remainingUses: policyRemainingUses,
            updatedAtMs: Date.now(),
            existing,
          });
      await writeCurrentRecord(currentRecordInput);
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
      !thresholdEcdsaChainTargetsEqual(
        args.transport.chainTarget,
        args.metadata.ecdsaRestore.chainTarget,
      )
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

    const requestedGroupId = String(args.transport.groupId || SIGNING_SESSION_SEAL_GROUP_ID).trim();
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
      thresholdSessionId: args.thresholdSessionId,
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
    const currentRecordInput = isEd25519PersistExactRecordArgs(args)
      ? buildCurrentRecordInput({
          thresholdSessionId: args.thresholdSessionId,
          transport: args.transport,
          metadata: args.metadata,
          sealedSecretB64u: sealed.sealedSecretB64u,
          relayerUrl: args.relayerUrl,
          keyVersion,
          groupId,
          issuedAtMs: persistedAtMs,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: persistedAtMs,
        })
      : buildCurrentRecordInput({
          thresholdSessionId: args.thresholdSessionId,
          transport: args.transport,
          metadata: args.metadata,
          sealedSecretB64u: sealed.sealedSecretB64u,
          relayerUrl: args.relayerUrl,
          keyVersion,
          groupId,
          issuedAtMs: persistedAtMs,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: persistedAtMs,
        });
    await writeCurrentRecord(currentRecordInput);
    recordDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'sealed_record_register',
      startedAt: registerStartedAt,
    });
    const verifyReadStartedAt = performance.now();
    let persisted: CurrentSealedSessionRecord | null;
    try {
      persisted = await readExactPasskeyRecord(args);
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
    thresholdSessionId: string,
  ): Promise<CurrentSealedSessionRecord | null> {
    if (purpose.curve === 'ed25519') {
      return await readExactEd25519SealedSession(
        ed25519DurableMaterialLocator({
          authMethod: 'passkey',
          materialActivation: purpose.materialActivation,
        }),
      );
    }
    return await readExactSealedSession(thresholdSessionId, {
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: purpose.chainTarget,
    });
  }

  private async writePolicy(
    existing: CurrentSealedSessionRecord,
    expiresAtMs: number,
    remainingUses: number,
  ): Promise<void> {
    if (existing.curve === 'ed25519') {
      await updateExactEd25519SealedSessionPolicy({
        locator: ed25519DurableMaterialLocator({
          authMethod: 'passkey',
          materialActivation: existing.ed25519Restore.materialActivation,
        }),
        expiresAtMs: Math.max(1, Math.floor(expiresAtMs)),
        remainingUses: Math.max(0, Math.floor(remainingUses)),
        updatedAtMs: Date.now(),
      });
      return;
    }
    await updateExactSealedSessionPolicy({
      thresholdSessionId: existing.thresholdSessionIds.ecdsa,
      filter: {
        authMethod: 'passkey',
        curve: 'ecdsa',
        chainTarget: existing.ecdsaRestore.chainTarget,
      },
      expiresAtMs: Math.max(1, Math.floor(expiresAtMs)),
      remainingUses: Math.max(0, Math.floor(remainingUses)),
      updatedAtMs: Date.now(),
    });
  }
}
