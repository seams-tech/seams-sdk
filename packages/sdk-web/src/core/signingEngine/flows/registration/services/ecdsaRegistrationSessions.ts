import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { DurableRecordStore } from '@/core/platform';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  type WalletRegistrationEcdsaHssRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import { ecdsaRoleLocalReadyRecordStorageKeyFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { EcdsaRegistrationBootstrapService } from './ecdsaRegistrationBootstrap';
import type { WalletRegistrationEcdsaPreparedClientBootstrap } from './ecdsaRegistrationBootstrap';
import type { WarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

type WalletRegistrationEcdsaSessionBootstrap = Awaited<
  ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>
>;

export type FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket =
  | 'client_finalize'
  | 'client_material_store'
  | 'server_bootstrap'
  | 'passkey_bootstrap_store'
  | 'passkey_role_local_ready_record'
  | 'passkey_warm_session_hydration'
  | 'passkey_warm_session_worker_ready'
  | 'passkey_warm_session_worker_put'
  | 'passkey_warm_session_sealed_record_persist'
  | 'passkey_warm_session_sealed_record_resolve_transport'
  | 'passkey_warm_session_sealed_record_existing_read'
  | 'passkey_warm_session_sealed_record_policy_read'
  | 'passkey_warm_session_sealed_record_apply_server_seal'
  | 'passkey_warm_session_sealed_record_apply_runtime_setup'
  | 'passkey_warm_session_sealed_record_apply_client_seal'
  | 'passkey_warm_session_sealed_record_apply_server_route'
  | 'passkey_warm_session_sealed_record_apply_client_unseal'
  | 'passkey_warm_session_sealed_record_apply_policy_update'
  | 'passkey_warm_session_sealed_record_register'
  | 'passkey_warm_session_sealed_record_verify_read'
  | 'email_otp_session_commit';

export type FinalizeWalletRegistrationEcdsaSessionsDiagnostics = {
  recordDuration(
    bucket: FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket,
    durationMs: number,
  ): void;
};

export type FinalizeWalletRegistrationEcdsaSessionsInput = {
  walletId: string;
  relayerUrl: string;
  sessions: readonly {
    chainTarget: WalletRegistrationEcdsaWalletKey['chainTarget'];
    preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
    bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  }[];
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  auth:
    | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
    | { kind: 'email_otp'; emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext };
  diagnostics?: FinalizeWalletRegistrationEcdsaSessionsDiagnostics;
};

export type FinalizeWalletRegistrationEcdsaSessionsDeps = {
  registrationBootstrap: Pick<
    EcdsaRegistrationBootstrapService,
    'finalizeClientBootstrap' | 'storeClientSigningMaterial'
  >;
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  sessionStore: ThresholdEcdsaSessionStoreDeps;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
  commitEmailOtpEcdsaSession: (args: {
    walletId: WalletId;
    chainTarget: WalletRegistrationEcdsaWalletKey['chainTarget'];
    bootstrap: WalletRegistrationEcdsaSessionBootstrap;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<unknown>;
  signingSessionSeal: {
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    shamirPrimeB64u?: string;
  };
};

function registrationEcdsaSessionForWalletKey(input: {
  sessions: readonly FinalizeWalletRegistrationEcdsaSessionsInput['sessions'][number][];
  walletKey: WalletRegistrationEcdsaWalletKey;
}): FinalizeWalletRegistrationEcdsaSessionsInput['sessions'][number] {
  const targetKey = thresholdEcdsaChainTargetKey(input.walletKey.chainTarget);
  for (const session of input.sessions) {
    if (thresholdEcdsaChainTargetKey(session.chainTarget) === targetKey) {
      return session;
    }
  }
  throw new Error(`[SigningEngine] ECDSA registration missing bootstrap session for ${targetKey}`);
}

export async function finalizeWalletRegistrationEcdsaSessions(
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps,
  args: FinalizeWalletRegistrationEcdsaSessionsInput,
): Promise<void> {
  const walletId = toWalletId(args.walletId);
  const sessionBootstraps = await Promise.all(
    args.walletKeys.map((walletKey) =>
      prepareRegistrationEcdsaSessionBootstrap({
        deps,
        input: args,
        walletId,
        walletKey,
      }),
    ),
  );

  for (const { walletKey, bootstrap, preparedClientBootstrap } of sessionBootstraps) {
    if (args.auth.kind === 'email_otp') {
      const emailOtpCommitStartedAt = performance.now();
      await deps.commitEmailOtpEcdsaSession({
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.auth.emailOtpAuthContext,
      });
      recordRegistrationEcdsaSessionDiagnosticDuration({
        diagnostics: args.diagnostics,
        bucket: 'email_otp_session_commit',
        startedAt: emailOtpCommitStartedAt,
      });
      continue;
    }

    const bootstrapStoreStartedAt = performance.now();
    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: deps.bootstrapStore,
      walletId,
      chainTarget: walletKey.chainTarget,
      bootstrap,
      signerAuth: {
        authMethod: SIGNER_AUTH_METHODS.passkey,
        signerSource: SIGNER_SOURCES.passkeyRegistration,
      },
    });
    recordRegistrationEcdsaSessionDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'passkey_bootstrap_store',
      startedAt: bootstrapStoreStartedAt,
    });
    const record = upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
      walletId,
      chainTarget: walletKey.chainTarget,
      bootstrap,
      source: 'registration',
    });
    markRegistrationEcdsaBootstrapRuntimeValidated({ bootstrap, record });
    const roleLocalReadyRecordStartedAt = performance.now();
    await persistRegistrationEcdsaRoleLocalReadyRecord({
      persistEcdsaRoleLocalReadyRecord: deps.persistEcdsaRoleLocalReadyRecord,
      bootstrap,
    });
    recordRegistrationEcdsaSessionDiagnosticDuration({
      diagnostics: args.diagnostics,
      bucket: 'passkey_role_local_ready_record',
      startedAt: roleLocalReadyRecordStartedAt,
    });
    const passkeyWarmSessionHydrationStartedAt = performance.now();
    try {
      await hydratePasskeyRegistrationSession({
        walletId,
        relayerUrl: args.relayerUrl,
        walletKey,
        bootstrap,
        preparedClientBootstrap,
        signingSessionSeal: deps.signingSessionSeal,
        warmSessions: deps.warmSessions,
        diagnostics: args.diagnostics,
      });
    } finally {
      recordRegistrationEcdsaSessionDiagnosticDuration({
        diagnostics: args.diagnostics,
        bucket: 'passkey_warm_session_hydration',
        startedAt: passkeyWarmSessionHydrationStartedAt,
      });
    }
  }
}

async function prepareRegistrationEcdsaSessionBootstrap(args: {
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps;
  input: FinalizeWalletRegistrationEcdsaSessionsInput;
  walletId: WalletId;
  walletKey: WalletRegistrationEcdsaWalletKey;
}): Promise<{
  walletKey: WalletRegistrationEcdsaWalletKey;
  bootstrap: WalletRegistrationEcdsaSessionBootstrap;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
}> {
  const session = registrationEcdsaSessionForWalletKey({
    sessions: args.input.sessions,
    walletKey: args.walletKey,
  });
  const clientFinalizeStartedAt = performance.now();
  const finalized = await args.deps.registrationBootstrap.finalizeClientBootstrap({
    preparedClientBootstrap: session.preparedClientBootstrap,
    bootstrap: session.bootstrap,
  });
  recordRegistrationEcdsaSessionDiagnosticDuration({
    diagnostics: args.input.diagnostics,
    bucket: 'client_finalize',
    startedAt: clientFinalizeStartedAt,
  });
  const clientMaterialStoreStartedAt = performance.now();
  const signingMaterial = await args.deps.registrationBootstrap.storeClientSigningMaterial({
    finalized,
    bootstrap: session.bootstrap,
    chainTarget: args.walletKey.chainTarget,
  });
  recordRegistrationEcdsaSessionDiagnosticDuration({
    diagnostics: args.input.diagnostics,
    bucket: 'client_material_store',
    startedAt: clientMaterialStoreStartedAt,
  });
  const serverBootstrapStartedAt = performance.now();
  const bootstrap = await buildWalletRegistrationEcdsaSessionBootstrap({
    walletId: args.walletId,
    relayerUrl: args.input.relayerUrl,
    chainTarget: args.walletKey.chainTarget,
    keygenSessionId: session.preparedClientBootstrap.clientBootstrap.requestId,
    readyStateBlob: finalized.stateBlob,
    signingMaterialHandle: signingMaterial.handle,
    clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
    serverBootstrap: session.bootstrap,
    walletKey: args.walletKey,
    authMethod:
      args.input.auth.kind === 'email_otp'
        ? {
            kind: 'email_otp',
            providerUserId: emailOtpAuthContextProviderUserId(args.input.auth.emailOtpAuthContext),
          }
        : {
            kind: 'passkey',
            credentialIdB64u: args.input.auth.credentialIdB64u,
            rpId: args.input.auth.rpId,
          },
  });
  recordRegistrationEcdsaSessionDiagnosticDuration({
    diagnostics: args.input.diagnostics,
    bucket: 'server_bootstrap',
    startedAt: serverBootstrapStartedAt,
  });
  return {
    walletKey: args.walletKey,
    bootstrap,
    preparedClientBootstrap: session.preparedClientBootstrap,
  };
}

function recordRegistrationEcdsaSessionDiagnosticDuration(args: {
  diagnostics: FinalizeWalletRegistrationEcdsaSessionsDiagnostics | undefined;
  bucket: FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket;
  startedAt: number;
}): void {
  if (!args.diagnostics) return;
  args.diagnostics.recordDuration(
    args.bucket,
    roundRegistrationEcdsaSessionDurationMs(args.startedAt),
  );
}

function roundRegistrationEcdsaSessionDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

async function persistRegistrationEcdsaRoleLocalReadyRecord(args: {
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  bootstrap: Awaited<ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>>;
}): Promise<void> {
  const record = args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaRoleLocalReadyRecord;
  if (!record) {
    throw new Error(
      '[SigningEngine] ECDSA registration bootstrap is missing role-local ready record',
    );
  }
  const persisted = await args.persistEcdsaRoleLocalReadyRecord({
    record,
    storageKeyFacts: ecdsaRoleLocalReadyRecordStorageKeyFacts(record),
  });
  if (!persisted.ok) {
    throw new Error(
      `[SigningEngine] ECDSA registration role-local ready record persistence failed (${persisted.code}): ${persisted.message}`,
    );
  }
}

function markRegistrationEcdsaBootstrapRuntimeValidated(args: {
  bootstrap: Awaited<ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>>;
  record: ReturnType<typeof upsertThresholdEcdsaSessionFromBootstrap>;
}): void {
  if (
    args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind !== 'role_local_worker_handle'
  ) {
    return;
  }
  if (markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(args.record)) return;
  throw new Error(
    '[SigningEngine] ECDSA registration bootstrap returned worker material that could not be runtime-validated',
  );
}

async function hydratePasskeyRegistrationSession(args: {
  walletId: WalletId;
  relayerUrl: string;
  walletKey: WalletRegistrationEcdsaWalletKey;
  bootstrap: Awaited<ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>>;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  signingSessionSeal: {
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    shamirPrimeB64u?: string;
  };
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
  diagnostics: FinalizeWalletRegistrationEcdsaSessionsDiagnostics | undefined;
}): Promise<void> {
  if (args.preparedClientBootstrap.materialSource !== 'passkey_prf_first') {
    throw new Error('Passkey ECDSA registration persistence requires passkey PRF material');
  }
  const thresholdSessionId = String(args.bootstrap.session.thresholdSessionId || '').trim();
  const signingGrantId = String(
    args.bootstrap.session.signingGrantId ||
      args.bootstrap.thresholdEcdsaKeyRef.signingGrantId ||
      '',
  ).trim();
  const walletSessionJwt = String(args.bootstrap.session.jwt || '').trim();
  if (!walletSessionJwt) {
    throw new Error('Passkey ECDSA registration persistence requires Wallet Session JWT');
  }
  const transport: WarmSessionSealTransportInput = {
    curve: 'ecdsa',
    walletId: String(args.walletId),
    chainTarget: args.walletKey.chainTarget,
    relayerUrl: args.relayerUrl,
  };
  if (signingGrantId) {
    transport.signingGrantId = signingGrantId;
    transport.serverSealedSecretCacheScope = {
      kind: 'passkey_registration',
      walletId: String(args.walletId),
      credentialIdB64u: args.preparedClientBootstrap.credentialIdB64u,
      signingGrantId,
    };
  }
  transport.walletSessionJwt = walletSessionJwt;
  if (args.signingSessionSeal.signingSessionSealKeyVersion) {
    transport.signingSessionSealKeyVersion = args.signingSessionSeal.signingSessionSealKeyVersion;
  }
  const sealShamirPrimeB64u = String(args.signingSessionSeal.shamirPrimeB64u || '').trim();
  if (sealShamirPrimeB64u) {
    transport.shamirPrimeB64u = sealShamirPrimeB64u;
  }
  await args.warmSessions.hydrateSigningSession({
    sessionId: thresholdSessionId,
    prfFirstB64u: args.preparedClientBootstrap.passkeyPrfFirstB64u,
    expiresAtMs: Number(args.bootstrap.session.expiresAtMs),
    remainingUses: Number(args.bootstrap.session.remainingUses),
    transport,
    ...(args.diagnostics
      ? { diagnostics: new RegistrationEcdsaWarmSessionDiagnostics(args.diagnostics) }
      : {}),
  });
}

class RegistrationEcdsaWarmSessionDiagnostics implements WarmSessionMaterialWriteDiagnostics {
  constructor(private readonly diagnostics: FinalizeWalletRegistrationEcdsaSessionsDiagnostics) {}

  recordDuration(bucket: WarmSessionMaterialWriteDiagnosticBucket, durationMs: number): void {
    this.diagnostics.recordDuration(mapWarmSessionDiagnosticBucket(bucket), durationMs);
  }
}

function mapWarmSessionDiagnosticBucket(
  bucket: WarmSessionMaterialWriteDiagnosticBucket,
): FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket {
  switch (bucket) {
    case 'worker_ready':
      return 'passkey_warm_session_worker_ready';
    case 'worker_put':
      return 'passkey_warm_session_worker_put';
    case 'sealed_record_persist':
      return 'passkey_warm_session_sealed_record_persist';
    case 'sealed_record_resolve_transport':
      return 'passkey_warm_session_sealed_record_resolve_transport';
    case 'sealed_record_existing_read':
      return 'passkey_warm_session_sealed_record_existing_read';
    case 'sealed_record_policy_read':
      return 'passkey_warm_session_sealed_record_policy_read';
    case 'sealed_record_apply_server_seal':
      return 'passkey_warm_session_sealed_record_apply_server_seal';
    case 'sealed_record_apply_runtime_setup':
      return 'passkey_warm_session_sealed_record_apply_runtime_setup';
    case 'sealed_record_apply_client_seal':
      return 'passkey_warm_session_sealed_record_apply_client_seal';
    case 'sealed_record_apply_server_route':
      return 'passkey_warm_session_sealed_record_apply_server_route';
    case 'sealed_record_apply_client_unseal':
      return 'passkey_warm_session_sealed_record_apply_client_unseal';
    case 'sealed_record_apply_policy_update':
      return 'passkey_warm_session_sealed_record_apply_policy_update';
    case 'sealed_record_register':
      return 'passkey_warm_session_sealed_record_register';
    case 'sealed_record_verify_read':
      return 'passkey_warm_session_sealed_record_verify_read';
    default: {
      const exhaustive: never = bucket;
      return exhaustive;
    }
  }
}
