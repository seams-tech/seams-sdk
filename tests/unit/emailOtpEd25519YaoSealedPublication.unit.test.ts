import { expect, test } from '@playwright/test';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentSealedSessionRecordInput,
  type CurrentEd25519SealedSessionRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  persistEmailOtpEd25519YaoCapabilityForRefresh,
  type EmailOtpEd25519YaoPublicationPorts,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoPublication';
import {
  buildRouterAbEd25519WalletSessionStateFromExactRuntime,
  nearEd25519YaoOperationMaterialFacts,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import {
  resolveEmailOtpEd25519YaoHydrationPlanForSigningV1,
  type EmailOtpEd25519YaoPublicLocatorObservationV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery';
import type {
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoActiveClientMetadataV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  buildEmailOtpEd25519YaoActiveClientMetadataFixture,
  buildEmailOtpEd25519AuthorizationProjectionFixture,
  buildEmailOtpEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

function buildActiveClient(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): RouterAbEd25519YaoActiveClientV1 {
  return {
    createSigningShare: async () => {
      throw new Error('unused in sealed-publication test');
    },
    metadata: () => metadata,
    status: () => ({ kind: 'active' }),
    dispose: () => undefined,
  };
}

class SealingWorkerFixture implements WorkerOperationContext {
  constructor(private readonly record: CurrentEd25519SealedSessionRecord) {}

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  async requestWorkerOperation(): Promise<unknown> {
    return {
      ok: true,
      sealedSecretB64u: 'email-otp-sealed-refresh-secret',
      keyVersion: 'email-otp-sealed-refresh-kek',
      remainingUses: this.record.remainingUses,
      expiresAtMs: this.record.expiresAtMs,
      materialKind: 'ed25519_yao',
      materialActivation: this.record.ed25519Restore.materialActivation,
    };
  }
}

function enabledConfigs(): SeamsConfigsReadonly {
  return {
    ...PASSKEY_MANAGER_DEFAULT_CONFIGS,
    signing: {
      ...PASSKEY_MANAGER_DEFAULT_CONFIGS.signing,
      sessionPersistenceMode: 'sealed_refresh_v1',
    },
  };
}

test('persists OTP Ed25519 signing roots so exact runtime read-back remains valid', async () => {
  const source = buildEmailOtpEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(source);
  if (!runtime) throw new Error('failed to parse the Email OTP Ed25519 fixture runtime');
  const authorization = buildEmailOtpEd25519AuthorizationProjectionFixture(source);
  const walletSessionState = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: authorization.walletSessionTokens.ed25519.walletSessionJwt,
    authority: authorization.authority,
    nowMs: source.expiresAtMs - 1,
  });
  const metadata = buildEmailOtpEd25519YaoActiveClientMetadataFixture(source);
  const material = {
    activeClient: buildActiveClient(metadata),
    facts: nearEd25519YaoOperationMaterialFacts(walletSessionState),
  };
  const worker = new SealingWorkerFixture(source);
  let registered: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ed25519' }> | undefined;
  const ports: EmailOtpEd25519YaoPublicationPorts = {
    configs: enabledConfigs(),
    getSignerWorkerContext: () => worker,
    registerSigningSession: async (record) => {
      registered = record;
    },
    readExactEd25519SealedSession: async () => {
      if (!registered) return null;
      const persisted = buildCurrentSealedSessionRecord(registered);
      if (!persisted || persisted.curve !== 'ed25519') {
        throw new Error('failed to build the captured Email OTP Ed25519 record');
      }
      return persisted;
    },
  };

  if (!('provider' in source.ed25519Restore)) {
    throw new Error('Email OTP fixture requires provider restore metadata');
  }
  await persistEmailOtpEd25519YaoCapabilityForRefresh(
    {
      material,
      walletSessionState,
      publicationContext: {
        rpId: source.ed25519Restore.rpId,
        provider: source.ed25519Restore.provider,
        providerSubjectId: source.ed25519Restore.providerSubjectId,
        emailHashHex: source.ed25519Restore.emailHashHex,
        materialActivation: source.ed25519Restore.materialActivation,
      },
    },
    ports,
  );

  expect(registered).toMatchObject({
    signingRootId: source.signingRootId,
    signingRootVersion: source.signingRootVersion,
  });
  if (!registered) throw new Error('Email OTP publication did not register a record');
  const persisted = buildCurrentSealedSessionRecord(registered);
  if (!persisted || persisted.curve !== 'ed25519') {
    throw new Error('failed to build the persisted Email OTP Ed25519 record');
  }
  expect(parseExactEd25519SealedSessionRuntime(persisted)?.signingRootId).toBe(
    source.signingRootId,
  );
});

test('builds an exact OTP Ed25519 rehydration plan after page refresh', async () => {
  const source = buildEmailOtpEd25519SealedSessionRecordFixture();
  const restore = source.ed25519Restore;
  if (!('provider' in restore)) {
    throw new Error('Email OTP fixture requires provider restore metadata');
  }
  let readLocator: unknown;
  const publicLocator: EmailOtpEd25519YaoPublicLocatorObservationV1 = {
    kind: 'available',
    walletId: source.walletId,
    nearAccountId: restore.nearAccountId,
    signerSlot: restore.signerSlot,
    materialActivation: restore.materialActivation,
  };
  const plan = await resolveEmailOtpEd25519YaoHydrationPlanForSigningV1({
    subject: {
      walletId: source.walletId,
      nearAccountId: restore.nearAccountId,
      signerSlot: restore.signerSlot,
      thresholdSessionId: source.thresholdSessionIds.ed25519,
    },
    publicLocator,
    runtime: { kind: 'absent' },
    readExactEd25519SealedSession: async (locator) => {
      readLocator = locator;
      return source;
    },
  });

  expect(readLocator).toEqual({
    kind: 'ed25519_durable_material',
    authMethod: 'email_otp',
    materialActivation: restore.materialActivation,
  });
  expect(plan).toMatchObject({
    kind: 'rehydrate_material_activation',
    materialActivation: restore.materialActivation,
  });
});
