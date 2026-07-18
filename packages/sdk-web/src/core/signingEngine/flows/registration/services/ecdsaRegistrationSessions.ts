import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaRoleLocalWorkerShareHandle } from '@/core/signingEngine/interfaces/signing';
import type { FinalizeRouterAbEcdsaRegistrationActivationResultV1 } from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapSignerAuth,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

type WalletRegistrationEcdsaSessionBootstrap = Awaited<
  ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>
>;

export type FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket =
  | 'session_bootstrap'
  | 'public_anchor_persist'
  | 'runtime_session_commit';

export type FinalizeWalletRegistrationEcdsaSessionsDiagnostics = {
  recordDuration(
    bucket: FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket,
    durationMs: number,
  ): void;
};

export type FinalizeWalletRegistrationEcdsaFamilySession = {
  chainTargets: readonly [
    WalletRegistrationEcdsaWalletKey['chainTarget'],
    ...WalletRegistrationEcdsaWalletKey['chainTarget'][],
  ];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  clientPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  publicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
};

export type FinalizeWalletRegistrationEcdsaSessionsInput = {
  walletId: string;
  relayerUrl: string;
  session: FinalizeWalletRegistrationEcdsaFamilySession;
  walletKeys: readonly [WalletRegistrationEcdsaWalletKey, ...WalletRegistrationEcdsaWalletKey[]];
  auth:
    | {
        kind: 'passkey';
        credentialIdB64u: string;
        rpId: string;
        emailOtpAuthContext?: never;
      }
    | {
        kind: 'email_otp';
        emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
        credentialIdB64u?: never;
        rpId?: never;
      };
  diagnostics?: FinalizeWalletRegistrationEcdsaSessionsDiagnostics;
};

export type FinalizeWalletRegistrationEcdsaSessionsDeps = {
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  sessionStore: ThresholdEcdsaSessionStoreDeps;
  persistActivePasskeyEcdsaReauthAnchor: (record: ThresholdEcdsaSessionRecord) => Promise<void>;
};

function roleLocalWorkerShareHandle(
  roleLocalMaterial: FinalizeWalletRegistrationEcdsaFamilySession['roleLocalMaterial'],
): ThresholdEcdsaRoleLocalWorkerShareHandle {
  return {
    kind: 'role_local_worker_session',
    materialHandle: roleLocalMaterial.materialHandle,
    bindingDigest: roleLocalMaterial.bindingDigest,
    durableMaterialRef: roleLocalMaterial.durableMaterialRef,
  };
}

function bootstrapAuthMethod(
  auth: FinalizeWalletRegistrationEcdsaSessionsInput['auth'],
):
  | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
  | { kind: 'email_otp'; providerUserId: string } {
  switch (auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: auth.credentialIdB64u,
        rpId: auth.rpId,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerUserId: emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
      };
  }
}

function bootstrapSignerAuth(
  auth: FinalizeWalletRegistrationEcdsaSessionsInput['auth'],
): ThresholdEcdsaBootstrapSignerAuth {
  switch (auth.kind) {
    case 'passkey':
      return {
        authMethod: SIGNER_AUTH_METHODS.passkey,
        signerSource: SIGNER_SOURCES.passkeyRegistration,
      };
    case 'email_otp':
      return {
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        signerSource: SIGNER_SOURCES.emailOtpRegistration,
      };
  }
}

function sessionTargetsMatchWalletKeys(args: {
  session: FinalizeWalletRegistrationEcdsaFamilySession;
  walletKeys: FinalizeWalletRegistrationEcdsaSessionsInput['walletKeys'];
}): boolean {
  if (args.session.chainTargets.length !== args.walletKeys.length) return false;
  for (let index = 0; index < args.walletKeys.length; index += 1) {
    const sessionTarget = args.session.chainTargets[index];
    const walletKey = args.walletKeys[index];
    if (!sessionTarget || !walletKey) return false;
    if (
      thresholdEcdsaChainTargetKey(sessionTarget) !==
      thresholdEcdsaChainTargetKey(walletKey.chainTarget)
    ) {
      return false;
    }
  }
  return true;
}

function commitRegistrationRuntimeSession(args: {
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps;
  input: FinalizeWalletRegistrationEcdsaSessionsInput;
  walletId: WalletId;
  walletKey: WalletRegistrationEcdsaWalletKey;
  bootstrap: WalletRegistrationEcdsaSessionBootstrap;
}): ThresholdEcdsaSessionRecord {
  switch (args.input.auth.kind) {
    case 'passkey':
      return upsertThresholdEcdsaSessionFromBootstrap(args.deps.sessionStore, {
        purpose: 'transaction_signing',
        walletId: args.walletId,
        chainTarget: args.walletKey.chainTarget,
        bootstrap: args.bootstrap,
        source: 'registration',
      });
    case 'email_otp':
      return upsertThresholdEcdsaSessionFromBootstrap(args.deps.sessionStore, {
        purpose: 'transaction_signing',
        walletId: args.walletId,
        chainTarget: args.walletKey.chainTarget,
        bootstrap: args.bootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.input.auth.emailOtpAuthContext,
      });
  }
}

function markRegistrationRuntimeSessionValidated(record: ThresholdEcdsaSessionRecord): void {
  if (markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) return;
  throw new Error(
    '[SigningEngine] strict ECDSA registration worker material could not be runtime-validated',
  );
}

function recordDiagnosticDuration(args: {
  diagnostics: FinalizeWalletRegistrationEcdsaSessionsDiagnostics | undefined;
  bucket: FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket;
  startedAt: number;
}): void {
  if (!args.diagnostics) return;
  args.diagnostics.recordDuration(
    args.bucket,
    Math.max(0, Math.round(performance.now() - args.startedAt)),
  );
}

export async function finalizeWalletRegistrationEcdsaSessions(
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps,
  input: FinalizeWalletRegistrationEcdsaSessionsInput,
): Promise<void> {
  if (!sessionTargetsMatchWalletKeys({ session: input.session, walletKeys: input.walletKeys })) {
    throw new Error(
      '[SigningEngine] strict ECDSA registration requires one family session projected to every wallet target',
    );
  }
  const walletId = toWalletId(input.walletId);
  const authMethod = bootstrapAuthMethod(input.auth);
  const signerAuth = bootstrapSignerAuth(input.auth);
  const workerHandle = roleLocalWorkerShareHandle(input.session.roleLocalMaterial);

  for (const walletKey of input.walletKeys) {
    const bootstrapStartedAt = performance.now();
    const publicFacts = buildEcdsaRoleLocalPublicFacts({
      walletId,
      evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
      chainTarget: walletKey.chainTarget,
      keyHandle: walletKey.keyHandle,
      ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
      signingRootId: walletKey.signingRootId,
      signingRootVersion: walletKey.signingRootVersion,
      applicationBindingDigestB64u: input.session.bootstrap.applicationBindingDigestB64u,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: input.session.bootstrap.participantIds,
      contextBinding32B64u: input.session.clientPublicFacts.contextBinding32B64u,
      derivationClientSharePublicKey33B64u:
        input.session.clientPublicFacts.derivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: input.session.clientPublicFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: input.session.clientPublicFacts.groupPublicKey33B64u,
      ethereumAddress: input.session.clientPublicFacts.ethereumAddress,
      publicCapability: input.session.publicCapability,
    });
    const bootstrap = await buildWalletRegistrationEcdsaSessionBootstrap({
      walletId,
      relayerUrl: input.relayerUrl,
      chainTarget: walletKey.chainTarget,
      keygenSessionId: input.session.clientBootstrap.requestId,
      clientVerifyingShareB64u:
        input.session.clientPublicFacts.derivationClientSharePublicKey33B64u,
      serverBootstrap: input.session.bootstrap,
      walletKey,
      publicCapability: input.session.publicCapability,
      authMethod,
      material: {
        kind: 'worker_handle',
        handle: workerHandle,
        publicFacts,
      },
    });
    recordDiagnosticDuration({
      diagnostics: input.diagnostics,
      bucket: 'session_bootstrap',
      startedAt: bootstrapStartedAt,
    });

    const publicAnchorStartedAt = performance.now();
    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: deps.bootstrapStore,
      walletId,
      chainTarget: walletKey.chainTarget,
      bootstrap,
      signerAuth,
    });
    recordDiagnosticDuration({
      diagnostics: input.diagnostics,
      bucket: 'public_anchor_persist',
      startedAt: publicAnchorStartedAt,
    });

    const runtimeCommitStartedAt = performance.now();
    const record = commitRegistrationRuntimeSession({
      deps,
      input,
      walletId,
      walletKey,
      bootstrap,
    });
    markRegistrationRuntimeSessionValidated(record);
    if (input.auth.kind === 'passkey') {
      await deps.persistActivePasskeyEcdsaReauthAnchor(record);
    }
    recordDiagnosticDuration({
      diagnostics: input.diagnostics,
      bucket: 'runtime_session_commit',
      startedAt: runtimeCommitStartedAt,
    });
  }
}
