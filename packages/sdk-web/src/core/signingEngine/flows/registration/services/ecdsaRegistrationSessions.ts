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
import {
  ecdsaRoleLocalReadyRecordStorageKeyFacts,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { EcdsaRegistrationBootstrapService } from './ecdsaRegistrationBootstrap';
import type { WalletRegistrationEcdsaPreparedClientBootstrap } from './ecdsaRegistrationBootstrap';
import type { WarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

type WalletRegistrationEcdsaSessionBootstrap = Awaited<
  ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>
>;

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
  throw new Error(
    `[SigningEngine] ECDSA registration missing bootstrap session for ${targetKey}`,
  );
}

export async function finalizeWalletRegistrationEcdsaSessions(
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps,
  args: FinalizeWalletRegistrationEcdsaSessionsInput,
): Promise<void> {
  const walletId = toWalletId(args.walletId);
  const sessionBootstraps = await Promise.all(
    args.walletKeys.map(async (walletKey) => {
      const session = registrationEcdsaSessionForWalletKey({
        sessions: args.sessions,
        walletKey,
      });
      const finalized = await deps.registrationBootstrap.finalizeClientBootstrap({
        preparedClientBootstrap: session.preparedClientBootstrap,
        bootstrap: session.bootstrap,
      });
      const signingMaterial = await deps.registrationBootstrap.storeClientSigningMaterial({
        finalized,
        bootstrap: session.bootstrap,
        chainTarget: walletKey.chainTarget,
      });
      return {
        walletKey,
        bootstrap: await buildWalletRegistrationEcdsaSessionBootstrap({
          walletId,
          relayerUrl: args.relayerUrl,
          chainTarget: walletKey.chainTarget,
          keygenSessionId: session.preparedClientBootstrap.clientBootstrap.requestId,
          readyStateBlob: finalized.stateBlob,
          signingMaterialHandle: signingMaterial.handle,
          clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
          serverBootstrap: session.bootstrap,
          walletKey,
          authMethod:
            args.auth.kind === 'email_otp'
              ? {
                  kind: 'email_otp',
                  providerUserId: emailOtpAuthContextProviderUserId(
                    args.auth.emailOtpAuthContext,
                  ),
                }
              : {
                  kind: 'passkey',
                  credentialIdB64u: args.auth.credentialIdB64u,
                  rpId: args.auth.rpId,
                },
        }),
      };
    }),
  );

  for (const { walletKey, bootstrap } of sessionBootstraps) {
    if (args.auth.kind === 'email_otp') {
      await deps.commitEmailOtpEcdsaSession({
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.auth.emailOtpAuthContext,
      });
      continue;
    }

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
    const record = upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
      walletId,
      chainTarget: walletKey.chainTarget,
      bootstrap,
      source: 'registration',
    });
    markRegistrationEcdsaBootstrapRuntimeValidated({ bootstrap, record });
    await persistRegistrationEcdsaRoleLocalReadyRecord({
      persistEcdsaRoleLocalReadyRecord: deps.persistEcdsaRoleLocalReadyRecord,
      bootstrap,
    });
    await hydratePasskeyRegistrationSession({
      walletId,
      relayerUrl: args.relayerUrl,
      walletKey,
      bootstrap,
      preparedClientBootstrap: registrationEcdsaSessionForWalletKey({
        sessions: args.sessions,
        walletKey,
      }).preparedClientBootstrap,
      signingSessionSeal: deps.signingSessionSeal,
      warmSessions: deps.warmSessions,
    });
  }
}

async function persistRegistrationEcdsaRoleLocalReadyRecord(args: {
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  bootstrap: Awaited<ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>>;
}): Promise<void> {
  const record = args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.ecdsaRoleLocalReadyRecord;
  if (!record) {
    throw new Error('[SigningEngine] ECDSA registration bootstrap is missing role-local ready record');
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
  }
  transport.walletSessionJwt = walletSessionJwt;
  if (args.signingSessionSeal.signingSessionSealKeyVersion) {
    transport.signingSessionSealKeyVersion =
      args.signingSessionSeal.signingSessionSealKeyVersion;
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
  });
}
