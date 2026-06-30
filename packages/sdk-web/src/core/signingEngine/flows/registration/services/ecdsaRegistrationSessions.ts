import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  type WalletRegistrationEcdsaHssRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
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

export type FinalizeWalletRegistrationEcdsaSessionsInput = {
  walletId: string;
  relayerUrl: string;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  auth:
    | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
    | { kind: 'email_otp'; emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext };
};

export type EcdsaRegistrationSessionsService = {
  finalizeWalletRegistrationEcdsaSessions(
    input: FinalizeWalletRegistrationEcdsaSessionsInput,
  ): Promise<void>;
};

export function createEcdsaRegistrationSessionsService(deps: {
  registrationBootstrap: Pick<
    EcdsaRegistrationBootstrapService,
    'finalizeClientBootstrap' | 'storeClientSigningMaterial'
  >;
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  sessionStore: ThresholdEcdsaSessionStoreDeps;
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
  signingSessionSeal: {
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    shamirPrimeB64u?: string;
  };
}): EcdsaRegistrationSessionsService {
  return {
    finalizeWalletRegistrationEcdsaSessions: (input) =>
      finalizeWalletRegistrationEcdsaSessions(deps, input),
  };
}

export async function finalizeWalletRegistrationEcdsaSessions(
  deps: {
    registrationBootstrap: Pick<
      EcdsaRegistrationBootstrapService,
      'finalizeClientBootstrap' | 'storeClientSigningMaterial'
    >;
    bootstrapStore: ThresholdEcdsaBootstrapStorePort;
    sessionStore: ThresholdEcdsaSessionStoreDeps;
    warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
    signingSessionSeal: {
      signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
      shamirPrimeB64u?: string;
    };
  },
  args: FinalizeWalletRegistrationEcdsaSessionsInput,
): Promise<void> {
  const walletId = toWalletId(args.walletId);
  const finalized = await deps.registrationBootstrap.finalizeClientBootstrap({
    preparedClientBootstrap: args.preparedClientBootstrap,
    bootstrap: args.bootstrap,
  });
  const sessionBootstraps = await Promise.all(
    args.walletKeys.map(async (walletKey) => {
      const signingMaterial = await deps.registrationBootstrap.storeClientSigningMaterial({
        finalized,
        bootstrap: args.bootstrap,
        chainTarget: walletKey.chainTarget,
      });
      return {
        walletKey,
        bootstrap: await buildWalletRegistrationEcdsaSessionBootstrap({
          walletId,
          relayerUrl: args.relayerUrl,
          chainTarget: walletKey.chainTarget,
          keygenSessionId: args.preparedClientBootstrap.clientBootstrap.requestId,
          readyStateBlob: finalized.stateBlob,
          signingMaterialHandle: signingMaterial.handle,
          clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
          serverBootstrap: args.bootstrap,
          walletKey,
          authMethod:
            args.auth.kind === 'email_otp'
              ? {
                  kind: 'email_otp',
                  authSubjectId: args.auth.emailOtpAuthContext.authSubjectId,
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
    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: deps.bootstrapStore,
      walletId,
      chainTarget: walletKey.chainTarget,
      bootstrap,
      signerAuth:
        args.auth.kind === 'email_otp'
          ? {
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              signerSource: SIGNER_SOURCES.emailOtpRegistration,
            }
          : {
              authMethod: SIGNER_AUTH_METHODS.passkey,
              signerSource: SIGNER_SOURCES.passkeyRegistration,
            },
    });
    if (args.auth.kind === 'email_otp') {
      const record = upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.auth.emailOtpAuthContext,
      });
      markRegistrationEcdsaBootstrapRuntimeValidated({ bootstrap, record });
    } else {
      const record = upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'registration',
      });
      markRegistrationEcdsaBootstrapRuntimeValidated({ bootstrap, record });
      await hydratePasskeyRegistrationSession({
        walletId,
        relayerUrl: args.relayerUrl,
        walletKey,
        bootstrap,
        preparedClientBootstrap: args.preparedClientBootstrap,
        signingSessionSeal: deps.signingSessionSeal,
        warmSessions: deps.warmSessions,
      });
    }
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
  const walletSessionJwt = String(
    args.bootstrap.session.jwt || args.bootstrap.thresholdEcdsaKeyRef.walletSessionJwt || '',
  ).trim();
  const transport: WarmSessionSealTransportInput = {
    curve: 'ecdsa',
    walletId: String(args.walletId),
    chainTarget: args.walletKey.chainTarget,
    relayerUrl: args.relayerUrl,
  };
  if (signingGrantId) {
    transport.signingGrantId = signingGrantId;
  }
  if (walletSessionJwt) {
    transport.walletSessionJwt = walletSessionJwt;
  }
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
