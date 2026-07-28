import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { FinalizeRouterAbEcdsaRegistrationActivationResultV1 } from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapSignerAuth,
  type ThresholdEcdsaBootstrapStorePort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
  type SigningSessionSealKeyVersion,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type { WarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import {
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import type { StoreWalletEcdsaWalletKey } from '../accountLifecycle';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { persistActiveWalletSessionAuthorizationFromEcdsaBootstrap } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';

type WalletRegistrationEcdsaSessionBootstrap = Awaited<
  ReturnType<typeof buildWalletRegistrationEcdsaSessionBootstrap>
>;

export type FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket =
  | 'session_bootstrap'
  | 'public_anchor_persist'
  | 'runtime_session_commit'
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
  | 'passkey_warm_session_sealed_record_verify_read';

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
  authority: FinalizeRouterAbEcdsaRegistrationActivationResultV1['authority'];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  materialActivation: FinalizeRouterAbEcdsaRegistrationActivationResultV1['materialActivation'];
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
        passkeyPrfFirstB64u: string;
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
  warmSessions: Pick<WarmSessionHydrationService, 'hydrateSigningSession'>;
  signingSessionSeal: {
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    shamirPrimeB64u?: string;
  };
};

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

function storeWalletEcdsaKeyWithRoleLocalMaterial(args: {
  walletKey: WalletRegistrationEcdsaWalletKey;
  publicFacts: ReturnType<typeof buildEcdsaRoleLocalPublicFacts>;
  materialRef: EcdsaRoleLocalPersistedMaterialRef;
}): StoreWalletEcdsaWalletKey {
  const walletKey = args.walletKey;
  return {
    keyScope: walletKey.keyScope,
    chainTarget: walletKey.chainTarget,
    walletId: walletKey.walletId,
    evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
    keyHandle: walletKey.keyHandle,
    ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
    signingRootId: walletKey.signingRootId,
    signingRootVersion: walletKey.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: walletKey.thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress: walletKey.thresholdOwnerAddress,
    relayerKeyId: walletKey.relayerKeyId,
    relayerVerifyingShareB64u: walletKey.relayerVerifyingShareB64u,
    participantIds: walletKey.participantIds,
    publicCapability: walletKey.publicCapability,
    roleLocalMaterialRef: args.materialRef,
    ecdsaRoleLocalPublicFacts: args.publicFacts,
  };
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
  }
}

async function hydratePasskeyRegistrationSession(args: {
  deps: FinalizeWalletRegistrationEcdsaSessionsDeps;
  relayerUrl: string;
  auth: Extract<FinalizeWalletRegistrationEcdsaSessionsInput['auth'], { kind: 'passkey' }>;
  diagnostics: FinalizeWalletRegistrationEcdsaSessionsDiagnostics | undefined;
  walletId: WalletId;
  walletKey: WalletRegistrationEcdsaWalletKey;
  bootstrap: WalletRegistrationEcdsaSessionBootstrap;
  authority: WalletAuthAuthorityRef;
  materialRef: EcdsaRoleLocalPersistedMaterialRef;
  publicFacts: ReturnType<typeof buildEcdsaRoleLocalPublicFacts>;
  runtimePolicyScope: WalletRegistrationEcdsaClientBootstrap['runtimePolicyScope'];
  normalSigning: WalletRegistrationEcdsaDerivationRespondBootstrap['routerAbEcdsaDerivationNormalSigning'];
}): Promise<void> {
  const thresholdSessionId = String(args.bootstrap.session.thresholdSessionId).trim();
  const signingGrantId = String(args.bootstrap.session.signingGrantId).trim();
  const walletSessionJwt = String(args.bootstrap.session.jwt).trim();
  const passkeyPrfFirstB64u = String(args.auth.passkeyPrfFirstB64u).trim();
  if (!thresholdSessionId || !signingGrantId || !walletSessionJwt || !passkeyPrfFirstB64u) {
    throw new Error(
      '[SigningEngine] passkey ECDSA registration requires exact warm-session material',
    );
  }
  const ecdsaRestore: Exclude<
    SealedSigningSessionEcdsaRestoreMetadata,
    { source: 'email_otp' }
  > = {
    chainTarget: args.walletKey.chainTarget,
    signingRootId: args.walletKey.signingRootId,
    signingRootVersion: args.walletKey.signingRootVersion,
    source: 'registration',
    authority: args.authority,
    roleLocalMaterialRef: args.materialRef,
    rpId: args.auth.rpId,
    credentialIdB64u: args.auth.credentialIdB64u,
    sessionKind: 'jwt',
    walletSessionJwt,
    keyHandle: args.walletKey.keyHandle,
    ecdsaThresholdKeyId: args.walletKey.ecdsaThresholdKeyId,
    ethereumAddress: args.walletKey.thresholdOwnerAddress,
    relayerKeyId: args.walletKey.relayerKeyId,
    clientVerifyingShareB64u: args.walletKey.derivationClientSharePublicKey33B64u,
    thresholdEcdsaPublicKeyB64u: args.walletKey.thresholdEcdsaPublicKeyB64u,
    participantIds: [...args.walletKey.participantIds],
    runtimePolicyScope: args.runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: args.normalSigning,
    publicCapability: args.publicFacts.publicCapability,
  };
  const transport: WarmSessionSealTransportInput = {
    curve: 'ecdsa',
    authMethod: 'passkey',
    walletId: String(args.walletId),
    chainTarget: args.walletKey.chainTarget,
    relayerUrl: args.relayerUrl,
    signingGrantId,
    walletSessionJwt,
    ecdsaRestore,
    serverSealedSecretCacheScope: {
      kind: 'passkey_registration',
      walletId: String(args.walletId),
      credentialIdB64u: args.auth.credentialIdB64u,
      signingGrantId,
    },
    ...(args.deps.signingSessionSeal.signingSessionSealKeyVersion
      ? {
          signingSessionSealKeyVersion: args.deps.signingSessionSeal.signingSessionSealKeyVersion,
        }
      : {}),
    ...(args.deps.signingSessionSeal.shamirPrimeB64u
      ? { shamirPrimeB64u: args.deps.signingSessionSeal.shamirPrimeB64u }
      : {}),
  };
  await args.deps.warmSessions.hydrateSigningSession({
    sessionId: thresholdSessionId,
    prfFirstB64u: passkeyPrfFirstB64u,
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    transport,
    ...(args.diagnostics
      ? { diagnostics: new RegistrationEcdsaWarmSessionDiagnostics(args.diagnostics) }
      : {}),
  });
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
): Promise<readonly [StoreWalletEcdsaWalletKey, ...StoreWalletEcdsaWalletKey[]]> {
  if (!sessionTargetsMatchWalletKeys({ session: input.session, walletKeys: input.walletKeys })) {
    throw new Error(
      '[SigningEngine] strict ECDSA registration requires one family session projected to every wallet target',
    );
  }
  const walletId = toWalletId(input.walletId);
  if (input.session.authority.walletId !== walletId) {
    throw new Error(
      '[SigningEngine] strict ECDSA registration authority does not match the target wallet',
    );
  }
  const authMethod = bootstrapAuthMethod(input.auth);
  const signerAuth = bootstrapSignerAuth(input.auth);
  const workerHandle = input.session.roleLocalMaterial;
  const materialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: workerHandle.durableMaterialRef,
    bindingDigest: workerHandle.bindingDigest,
    materialActivation: input.session.materialActivation,
  });
  const storedWalletKeys: StoreWalletEcdsaWalletKey[] = [];

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
        materialRef,
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
    await persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(
      walletSessionAuthorizations,
      {
        walletId,
        authority: input.session.authority,
        authMethod: signerAuth.authMethod,
        bootstrap,
      },
    );
    recordDiagnosticDuration({
      diagnostics: input.diagnostics,
      bucket: 'public_anchor_persist',
      startedAt: publicAnchorStartedAt,
    });

    const runtimeCommitStartedAt = performance.now();
    switch (input.auth.kind) {
      case 'passkey': {
        const warmSessionStartedAt = performance.now();
        try {
          await hydratePasskeyRegistrationSession({
            deps,
            relayerUrl: input.relayerUrl,
            auth: input.auth,
            diagnostics: input.diagnostics,
            walletId,
            walletKey,
            bootstrap,
            authority: input.session.authority,
            materialRef,
            publicFacts,
            runtimePolicyScope: input.session.clientBootstrap.runtimePolicyScope,
            normalSigning: input.session.bootstrap.routerAbEcdsaDerivationNormalSigning,
          });
        } finally {
          recordDiagnosticDuration({
            diagnostics: input.diagnostics,
            bucket: 'passkey_warm_session_hydration',
            startedAt: warmSessionStartedAt,
          });
        }
        break;
      }
      case 'email_otp':
        break;
    }
    storedWalletKeys.push(
      storeWalletEcdsaKeyWithRoleLocalMaterial({
        walletKey,
        publicFacts,
        materialRef,
      }),
    );
    recordDiagnosticDuration({
      diagnostics: input.diagnostics,
      bucket: 'runtime_session_commit',
      startedAt: runtimeCommitStartedAt,
    });
  }
  const [firstStoredWalletKey, ...remainingStoredWalletKeys] = storedWalletKeys;
  if (!firstStoredWalletKey) {
    throw new Error('[SigningEngine] strict ECDSA registration did not persist any wallet keys');
  }
  return [firstStoredWalletKey, ...remainingStoredWalletKeys];
}
