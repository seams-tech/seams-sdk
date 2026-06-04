import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  type WalletRegistrationEcdsaHssRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { EcdsaRegistrationBootstrapService } from './ecdsaRegistrationBootstrap';
import type { WalletRegistrationEcdsaPreparedClientBootstrap } from './ecdsaRegistrationBootstrap';
import type { WarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

export type PersistWalletRegistrationEcdsaSessionsInput = {
  walletId: string;
  relayerUrl: string;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  auth:
    | { kind: 'passkey'; credentialIdB64u: string }
    | { kind: 'email_otp'; emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext };
};

export type EcdsaRegistrationSessionsService = {
  persistWalletRegistrationEcdsaSessions(
    input: PersistWalletRegistrationEcdsaSessionsInput,
  ): Promise<void>;
};

export function createEcdsaRegistrationSessionsService(deps: {
  registrationBootstrap: Pick<EcdsaRegistrationBootstrapService, 'finalizeClientBootstrap'>;
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  sessionStore: ThresholdEcdsaSessionStoreDeps;
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
  signingSessionSeal: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
}): EcdsaRegistrationSessionsService {
  return {
    persistWalletRegistrationEcdsaSessions: (input) =>
      persistWalletRegistrationEcdsaSessions(deps, input),
  };
}

async function persistWalletRegistrationEcdsaSessions(
  deps: {
    registrationBootstrap: Pick<EcdsaRegistrationBootstrapService, 'finalizeClientBootstrap'>;
    bootstrapStore: ThresholdEcdsaBootstrapStorePort;
    sessionStore: ThresholdEcdsaSessionStoreDeps;
    warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
    signingSessionSeal: {
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  },
  args: PersistWalletRegistrationEcdsaSessionsInput,
): Promise<void> {
  const walletId = toWalletId(args.walletId);
  const finalized = await deps.registrationBootstrap.finalizeClientBootstrap({
    preparedClientBootstrap: args.preparedClientBootstrap,
    bootstrap: args.bootstrap,
  });
  const sessionBootstraps = args.walletKeys.map((walletKey) => ({
    walletKey,
    bootstrap: buildWalletRegistrationEcdsaSessionBootstrap({
      walletId,
      relayerUrl: args.relayerUrl,
      chainTarget: walletKey.chainTarget,
      keygenSessionId: args.preparedClientBootstrap.clientBootstrap.requestId,
      readyStateBlob: finalized.stateBlob,
      clientVerifyingShareB64u: finalized.publicFacts.hssClientSharePublicKey33B64u,
      serverBootstrap: args.bootstrap,
      walletKey,
      authMethod:
        args.auth.kind === 'email_otp'
          ? {
              kind: 'email_otp',
              authSubjectId: args.auth.emailOtpAuthContext.authSubjectId,
            }
          : { kind: 'passkey', credentialIdB64u: args.auth.credentialIdB64u },
    }),
  }));

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
      upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.auth.emailOtpAuthContext,
      });
    } else {
      upsertThresholdEcdsaSessionFromBootstrap(deps.sessionStore, {
        walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'registration',
      });
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

async function hydratePasskeyRegistrationSession(args: {
  walletId: WalletId;
  relayerUrl: string;
  walletKey: WalletRegistrationEcdsaWalletKey;
  bootstrap: ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  signingSessionSeal: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
}): Promise<void> {
  if (args.preparedClientBootstrap.materialSource !== 'passkey_prf_first') {
    throw new Error('Passkey ECDSA registration persistence requires passkey PRF material');
  }
  const thresholdSessionId = String(args.bootstrap.session.sessionId || '').trim();
  const walletSigningSessionId = String(
    args.bootstrap.session.walletSigningSessionId ||
      args.bootstrap.thresholdEcdsaKeyRef.walletSigningSessionId ||
      '',
  ).trim();
  const thresholdSessionAuthToken = String(
    args.bootstrap.session.jwt || args.bootstrap.thresholdEcdsaKeyRef.thresholdSessionAuthToken || '',
  ).trim();
  const transport: WarmSessionSealTransportInput = {
    curve: 'ecdsa',
    walletId: String(args.walletId),
    chainTarget: args.walletKey.chainTarget,
    relayerUrl: args.relayerUrl,
  };
  if (walletSigningSessionId) {
    transport.walletSigningSessionId = walletSigningSessionId;
  }
  if (thresholdSessionAuthToken) {
    transport.thresholdSessionAuthToken = thresholdSessionAuthToken;
  }
  const sealKeyVersion = String(args.signingSessionSeal.keyVersion || '').trim();
  if (sealKeyVersion) {
    transport.keyVersion = sealKeyVersion;
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
