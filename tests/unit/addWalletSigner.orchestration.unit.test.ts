import { expect, test } from '@playwright/test';
import {
  addWalletSigner,
  registerWallet,
  registerWalletWithStartedPrecompute,
} from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { createEvmSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/evm';
import { createNearSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/near';
import { IndexedDBManager } from '../../packages/sdk-web/src/core/indexedDB';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { UserVerificationPolicy } from '../../packages/sdk-web/src/core/types/authenticatorOptions';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  persistStoredThresholdEd25519SessionMaterialHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { emailOtpRecoveryCodeBackupRepository } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';
import { markRouterAbEd25519WorkerMaterialRuntimeValidated } from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';
import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  normalizeRegistrationSignerPlan,
  nearEd25519SigningKeyIdFromString,
  registrationSignerSetSelectionFromPlan,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '../../packages/shared-ts/src/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  computeSdkEcdsaHssApplicationBindingDigestB64u,
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
  parseSdkEcdsaHssThresholdKeyId,
  type EcdsaHssClientSharePublicKey33B64u,
  type EcdsaRelayerHssPublicKey33B64u,
} from '../../packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap';
import { computeSdkEd25519HssApplicationBindingDigestB64u } from '../../packages/shared-ts/src/threshold/ed25519HssBinding';

const RELAYER_URL = 'https://relay.example.test';
const WALLET_SUBJECT_ID = walletIdFromString('wallet-matrix.testnet');

function unwrapFixture<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid fixture value');
  return result.value;
}

const RP_ID = unwrapFixture(parseWebAuthnRpId('wallet.example.test'));
const AUTHENTICATION_PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const REGISTRATION_PRF_FIRST_B64U = Buffer.alloc(32, 12).toString('base64url');
const CLIENT_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const MISMATCHED_CLIENT_PUBLIC_KEY_B64U =
  'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U =
  'AwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB' as EcdsaRelayerHssPublicKey33B64u;
const GROUP_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const CONTEXT_BINDING_32_B64U = 'DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org_matrix',
  projectId: 'project_matrix',
  envId: 'dev',
  signingRootVersion: 'root_v1',
} as const;
const ECDSA_THRESHOLD_KEY_ID = parseSdkEcdsaHssThresholdKeyId('ecdsa-threshold-key-id');
const ECDSA_SIGNING_ROOT_ID = parseSdkEcdsaHssSigningRootId('project_matrix:dev');
const ECDSA_SIGNING_ROOT_VERSION = parseSdkEcdsaHssSigningRootVersion(
  RUNTIME_POLICY_SCOPE.signingRootVersion,
);
const ROUTER_AB_NORMAL_SIGNING = {
  kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  signingWorkerId: 'signing-worker-test',
} as const;

async function ecdsaApplicationBindingDigestB64u(walletId: unknown): Promise<string> {
  return await computeSdkEcdsaHssApplicationBindingDigestB64u({
    walletId: walletIdFromString(String(walletId)),
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: ECDSA_SIGNING_ROOT_ID,
    signingRootVersion: ECDSA_SIGNING_ROOT_VERSION,
  });
}

function namedProvisioning(accountId: string) {
  const parsed = parseNamedNearAccountId(accountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return {
    kind: 'sponsored_named_account' as const,
    requestedAccountId: parsed.value,
    sponsor: 'relayer' as const,
  };
}

function mockedRegistrationRequestedAccountId(selection: any): string | null {
  const provisioning = mockedRegistrationNearEd25519Signer(selection)?.accountProvisioning;
  return provisioning?.kind === 'sponsored_named_account'
    ? String(provisioning.requestedAccountId)
    : null;
}

function mockedRegistrationIntentSignerSelection(raw: unknown) {
  const plan = normalizeRegistrationSignerPlan(raw);
  if (!plan.ok) throw new Error(plan.message);
  const selection = registrationSignerSetSelectionFromPlan(plan.value);
  if (!selection.ok) throw new Error(selection.message);
  return selection.value;
}

function mockedRegistrationNearEd25519Signer(selection: any): any | null {
  const signers = Array.isArray(selection?.signers) ? selection.signers : [];
  return signers.find((signer: any) => signer?.kind === 'near_ed25519') || null;
}

function mockedRegistrationEvmFamilyEcdsaSigner(selection: any): any | null {
  const signers = Array.isArray(selection?.signers) ? selection.signers : [];
  return signers.find((signer: any) => signer?.kind === 'evm_family_ecdsa') || null;
}

function mockedRegistrationHasSignerKind(selection: any, kind: string): boolean {
  const signers = Array.isArray(selection?.signers) ? selection.signers : [];
  return signers.some((signer: any) => signer?.kind === kind);
}

function nearRegistrationSigner(accountId: string) {
  return {
    kind: 'near_ed25519' as const,
    accountProvisioning: namedProvisioning(accountId),
    signerSlot: 1,
    participantIds: [1, 2],
    derivationVersion: 1,
  };
}

function evmFamilyRegistrationSigner(chainTargets: readonly unknown[]) {
  return {
    kind: 'evm_family_ecdsa' as const,
    chainTargets: [...chainTargets],
    participantIds: [1, 2],
  };
}

function registrationSignerSet(...signers: readonly unknown[]) {
  return {
    kind: 'signer_set' as const,
    signers,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function consolePayloadsForLabel(
  calls: readonly unknown[][],
  label: string,
): Record<string, unknown>[] {
  const payloads: Record<string, unknown>[] = [];
  for (const call of calls) {
    if (call[0] === label && isRecord(call[1])) {
      payloads.push(call[1]);
    }
  }
  return payloads;
}

function registrationProgressEvents(
  calls: readonly unknown[][],
  stage: string,
): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  for (const payload of consolePayloadsForLabel(calls, '[Registration] progress')) {
    if (payload.stage === stage) {
      events.push(payload);
    }
  }
  return events;
}

function mockedRegistrationWalletId(body: any): ReturnType<typeof walletIdFromString> {
  const signerSelection = mockedRegistrationIntentSignerSelection(body.signerSelection);
  if (body.wallet?.kind === 'provided') return walletIdFromString(String(body.wallet.walletId));
  return walletIdFromString(
    mockedRegistrationRequestedAccountId(signerSelection) || String(WALLET_SUBJECT_ID),
  );
}

function createLocalEvmCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createEvmSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: () =>
      ({
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('local EVM capability test should not require wallet iframe router');
        },
      }) as any,
  } as any);
}

function createLocalNearCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createNearSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: () =>
      ({
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('local NEAR capability test should not require wallet iframe router');
        },
      }) as any,
  } as any);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtWithPayload(payload: Record<string, unknown>): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u(payload)}.sig`;
}

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function ecdsaWalletSessionJwtForBootstrap(bootstrap: Record<string, unknown>): string {
  const publicIdentity = bootstrap.publicIdentity as Record<string, unknown>;
  const sessionId = String(bootstrap.sessionId || bootstrap.thresholdSessionId || '').trim();
  const signingGrantId = String(bootstrap.signingGrantId || '').trim();
  const walletId = String(bootstrap.walletId || '').trim();
  const evmFamilySigningKeySlotId = String(bootstrap.evmFamilySigningKeySlotId || '').trim();
  const applicationBindingDigestB64u = String(bootstrap.applicationBindingDigestB64u || '').trim();
  const ecdsaThresholdKeyId = String(bootstrap.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(bootstrap.signingRootId || '').trim();
  const signingRootVersion = String(bootstrap.signingRootVersion || '').trim();
  const keyHandle = String(bootstrap.keyHandle || '').trim();
  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  const expiresAtMs = Number(bootstrap.expiresAtMs);
  const participantIds = Array.isArray(bootstrap.participantIds) ? bootstrap.participantIds : [];
  return jwtWithPayload({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: walletId,
    walletId,
    evmFamilySigningKeySlotId,
    thresholdSessionId: sessionId,
    signingGrantId,
    keyScope: 'evm-family',
    keyHandle,
    relayerKeyId,
    rpId: RP_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: expiresAtMs,
    participantIds,
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        wallet_id: walletId,
        wallet_key_id: evmFamilySigningKeySlotId,
        ecdsa_threshold_key_id: ecdsaThresholdKeyId,
        signing_root_id: signingRootId,
        signing_root_version: signingRootVersion,
        context: {
          application_binding_digest_b64u: applicationBindingDigestB64u,
        },
        public_identity: {
          context_binding_b64u: String(bootstrap.contextBinding32B64u || '').trim(),
          client_public_key33_b64u: String(
            publicIdentity.hssClientSharePublicKey33B64u || '',
          ).trim(),
          server_public_key33_b64u: String(publicIdentity.relayerPublicKey33B64u || '').trim(),
          threshold_public_key33_b64u: String(publicIdentity.groupPublicKey33B64u || '').trim(),
          ethereum_address20_b64u: ethereumAddress20B64u(
            String(publicIdentity.ethereumAddress || bootstrap.ethereumAddress || ''),
          ),
          client_share_retry_counter: Number(bootstrap.clientShareRetryCounter),
          server_share_retry_counter: Number(bootstrap.relayerShareRetryCounter),
        },
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'worker-epoch-test',
          recipient_encryption_key:
            'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
        activation_epoch: sessionId,
      },
    },
  });
}

function plannedEcdsaWalletKeyId(walletId: unknown): string {
  return String(
    deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
      walletId,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    }),
  );
}

function staleWalletPrecomputeHandle(readState: { called: boolean }): any {
  return {
    kind: 'wallet_registration_precompute_handle_v1',
    handleId: 'stale-precompute-handle',
    scope: {
      authMethodKind: 'passkey',
      walletScopeKey: 'provided:stale-wallet.testnet',
      authorityScopeKey: JSON.stringify({ kind: 'passkey', rpId: RP_ID }),
      signerSetScopeKey: 'stale-signer-set',
      accountProvisioningScopeKey: 'stale-provisioning',
    },
    read: async () => {
      readState.called = true;
      throw new Error('stale precompute should fail before read');
    },
    snapshot: () => ({}),
    routeDiagnosticsSnapshot: () => [],
    dispose: () => undefined,
  };
}

function ed25519WalletSessionJwt(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  sessionId: string;
  signingGrantId: string;
  relayerKeyId: string;
  expiresAtMs: number;
  participantIds: readonly number[];
}): string {
  return jwtWithPayload({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: args.relayerKeyId,
    rpId: RP_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: args.expiresAtMs,
    participantIds: args.participantIds,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
  });
}

function credentialWithPrf() {
  return {
    id: 'credential-id',
    rawId: 'credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: AUTHENTICATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function registrationCredentialWithPrf() {
  return {
    id: 'registration-credential-id',
    rawId: 'registration-credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      attestationObject: 'attestation-object',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: REGISTRATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function incrementCaptureCounter(captures: Record<string, unknown>, key: string): void {
  captures[key] = Number(captures[key] || 0) + 1;
}

function expectSingleRegistrationTouchIdPrompt(captures: Record<string, unknown>): void {
  expect(captures.registrationCredentialPrompts).toBe(1);
  expect(captures.authenticationCredentialPrompts || 0).toBe(0);
}

function expectRegistrationSuccess(result: { success: boolean; error?: unknown }): void {
  if (!result.success) {
    throw new Error(String(result.error || 'registration returned success:false'));
  }
}

type DeferredPromise<T> = {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
};

function createDeferredPromise<T>(): DeferredPromise<T> {
  let resolve: (value: T) => void = () => undefined;
  let reject: (error: unknown) => void = () => undefined;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function waitForTestCondition(input: {
  label: string;
  predicate(): boolean;
}): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (input.predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`Timed out waiting for ${input.label}`);
}

function registrationEvents(captures: Record<string, unknown>): string[] | null {
  return Array.isArray(captures.registrationEvents)
    ? (captures.registrationEvents as string[])
    : null;
}

function emailOtpRegistrationEnrollmentMaterial(args: {
  walletId: string;
  userId: string;
}): Record<string, unknown> {
  return {
    thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
    thresholdEd25519RecoveryCodeSecret32B64u: REGISTRATION_PRF_FIRST_B64U,
    recoveryKeys: [
      '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
      '123456789ABCDEFGHJKMNPQRSTVWXYZ0',
      '23456789ABCDEFGHJKMNPQRSTVWXYZ01',
      '3456789ABCDEFGHJKMNPQRSTVWXYZ012',
      '456789ABCDEFGHJKMNPQRSTVWXYZ0123',
      '56789ABCDEFGHJKMNPQRSTVWXYZ01234',
      '6789ABCDEFGHJKMNPQRSTVWXYZ012345',
      '789ABCDEFGHJKMNPQRSTVWXYZ0123456',
      '89ABCDEFGHJKMNPQRSTVWXYZ01234567',
      '9ABCDEFGHJKMNPQRSTVWXYZ012345678',
    ],
    recoveryCodesIssuedAtMs: 1_700_000_000_000,
    otpChannel: 'email_otp',
    enrollmentId: `email-otp-enrollment-${args.walletId}`,
    enrollmentSealKeyVersion: 'email-otp-v1',
    clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
    unlockKeyVersion: 'email-otp-unlock-v1',
    clientRootShareHandle: {
      kind: 'available',
      handles: [
        {
          kind: 'email_otp_worker_session_handle_v1',
          sessionId: `email-otp-client-root-${args.walletId}`,
          walletId: args.walletId,
          evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(args.walletId),
          authSubjectId: args.userId,
          action: 'wallet_registration_ecdsa_prepare',
          operation: 'registration',
          keyScope: 'evm-family',
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' },
        },
      ],
    },
    emailOtpEnrollment: {
      recoveryWrappedEnrollmentEscrows: [
        {
          enrollmentId: `email-otp-enrollment-${args.walletId}`,
        },
      ],
      enrollmentSealKeyVersion: 'email-otp-v1',
      clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
    },
  };
}

function createContext(captures: Record<string, unknown>): any {
  const prepareWalletRegistrationEcdsaPreparedClientBootstrap = async (
    args: Record<string, unknown>,
  ) => {
    registrationEvents(captures)?.push('ecdsaClientBootstrapStarted');
    captures.ecdsaClientBootstrapArgs = args;
    const clientBootstrap = {
      ...(args.prepare as Record<string, unknown>),
      hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    };
    return {
      materialSource: 'passkey_prf_first',
      clientBootstrap,
      pendingStateBlob: {
        kind: 'ecdsa_role_local_pending_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'pending-state',
      },
      preparePublicFacts: {
        hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
      },
      passkeyPrfFirstB64u: String(args.passkeyPrfFirstB64u || ''),
      credentialIdB64u: String(args.credentialIdB64u || ''),
    };
  };
  const prepareEmailOtpRegistrationEnrollmentMaterialInternal = async (
    args: Record<string, unknown>,
  ) => {
    registrationEvents(captures)?.push('emailOtpEnrollmentMaterialStarted');
    captures.emailOtpEnrollmentMaterialArgs = args;
    const deferred = captures.deferredEmailOtpEnrollmentMaterial as
      | DeferredPromise<Record<string, unknown>>
      | undefined;
    const material = deferred
      ? await deferred.promise
      : emailOtpRegistrationEnrollmentMaterial({
          walletId: String(args.walletId),
          userId: String(args.userId),
        });
    registrationEvents(captures)?.push('emailOtpEnrollmentMaterialResolved');
    return material;
  };
  const thresholdEcdsaSessionStore = { recordsByLane: new Map() };
  const ecdsaRegistrationBootstrap = {
    preparePasskeyClientBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
    finalizeClientBootstrap: async () => ({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1' as const,
        curve: 'secp256k1' as const,
        encoding: 'base64url' as const,
        producer: 'signer_core' as const,
        stateBlobB64u: 'ready-state',
      },
      publicFacts: {
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereumAddress: '0x3333333333333333333333333333333333333333' as `0x${string}`,
      },
    }),
    storeClientSigningMaterial: async () => ({
      handle: {
        kind: 'role_local_worker_session' as const,
        materialHandle: 'registration-ecdsa-role-local-material',
        bindingDigest: 'registration-ecdsa-role-local-binding',
      },
    }),
  };
  const hydrateSigningSession = async (input: Record<string, unknown>) => {
    captures.hydratedSession = input;
    const transport = input.transport as Record<string, unknown> | undefined;
    if (transport?.curve !== 'ed25519') return;
    const record = persistStoredThresholdEd25519SessionMaterialHandle({
      thresholdSessionId: String(input.sessionId || ''),
      ed25519WorkerMaterialHandle: 'registration-ed25519-worker-material',
      materialKeyId: 'registration-ed25519-material-key',
      ed25519WorkerMaterialBindingDigest: 'registration-ed25519-worker-binding',
      clientVerifyingShareB64u: 'registration-ed25519-client-verifying-share',
      sealedWorkerMaterialRef: 'registration-ed25519-sealed-ref',
      sealedWorkerMaterialB64u: 'registration-ed25519-sealed-blob',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialCreatedAtMs: 1_700_000_000_000,
      signerSlot: 1,
      keyVersion: 'threshold-ed25519-hss-v1',
    });
    if (record) {
      markRouterAbEd25519WorkerMaterialRuntimeValidated(record);
    }
  };
  const finalizeWalletRegistrationEcdsaSessionsForTest = async (input: Record<string, unknown>) => {
    await finalizeWalletRegistrationEcdsaSessionsOperation(
      {
        registrationBootstrap: ecdsaRegistrationBootstrap,
        bootstrapStore: {
          upsertProfile: async () => undefined,
          activateAccountSigner: async (activationInput: any) => ({
            signer: activationInput.signer,
            signerSlot: 1,
          }),
        },
        sessionStore: thresholdEcdsaSessionStore,
        persistEcdsaRoleLocalReadyRecord: async (input: Record<string, unknown>) => {
          captures.persistedEcdsaRoleLocalReadyRecord = input;
          return { ok: true };
        },
        warmSessions: { hydrateSigningSession },
        commitEmailOtpEcdsaSession: async (input: Record<string, unknown>) => {
          captures.committedEmailOtpEcdsaSession = input;
          return undefined;
        },
        signingSessionSeal: {},
      },
      input as any,
    );
    captures.persistedEcdsaSessions = input;
  };
  return {
    configs: {
      network: {
        chains: [
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://tempo.example.test',
            explorerUrl: 'https://tempo.explorer.test',
            chainId: 42431,
          },
          {
            network: 'arc-testnet',
            rpcUrl: 'https://arc.example.test',
            explorerUrl: 'https://arc.explorer.test',
            chainId: 5042002,
          },
        ],
        relayer: {
          url: RELAYER_URL,
        },
      },
      registration: {
        mode: 'managed',
        projectEnvironmentId: 'project_matrix:dev',
        publishableKey: 'pk_matrix',
      },
      signing: {
        emailOtp: {
          authPolicy: 'session',
        },
        routerAb: {
          normalSigning: { mode: 'enabled', signingWorkerId: 'signing-worker-test' },
        },
        sessionDefaults: {
          ttlMs: 600_000,
          remainingUses: 1,
        },
        thresholdEcdsa: {
          provisioningDefaults: {
            tempo: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
            evm: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
          },
        },
      },
      webauthn: {
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      },
    },
    signingRuntime: {
      services: {
        ecdsaRegistrationBootstrap,
        ecdsaWalletRecords: {
          storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
        },
        ecdsaRegistrationSessions: {
          finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
        },
        warmSessions: {
          hydrateSigningSession,
        },
        registrationAccounts: {
          storeWalletEd25519RegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEd25519Registration = input;
            return { signerSlot: input.signerSlot };
          },
          storeWalletEmailOtpEd25519RegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEd25519Registration = input;
            return { signerSlot: input.signerSlot };
          },
          finalizeWalletEd25519SignerRegistration: async (input: Record<string, unknown>) => {
            captures.storedEd25519 = input;
            return { signerSlot: input.signerSlot };
          },
          getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
            nearAccountId,
            signerSlot,
          }),
          activateAuthenticatedWalletState: async () => undefined,
          rollbackUserRegistration: async () => undefined,
        },
      },
    },
    signingEngine: {
      getRpId: () => RP_ID,
      requestRegistrationCredentialConfirmation: async (args: Record<string, unknown>) => {
        incrementCaptureCounter(captures, 'registrationCredentialPrompts');
        captures.registrationCredentialArgs = args;
        return {
          credential: registrationCredentialWithPrf(),
        };
      },
      getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
        incrementCaptureCounter(captures, 'authenticationCredentialPrompts');
        captures.authenticationArgs = args;
        return credentialWithPrf();
      },
      storeWalletEd25519RegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEd25519Registration = input;
        return { signerSlot: input.signerSlot };
      },
      storeWalletEmailOtpEd25519RegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEd25519Registration = input;
        return { signerSlot: input.signerSlot };
      },
      preparePasskeyEcdsaBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
      prepareEmailOtpEcdsaBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
      prepareEmailOtpRegistrationEnrollmentMaterialInternal,
      finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
      finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },
      prepareThresholdEd25519HssClientCeremonyFromCredential: async (
        input: Record<string, unknown>,
      ) => {
        captures.ed25519MaterialArgs = input;
        const hssBindingFacts = input.hssBindingFacts as {
          nearEd25519SigningKeyId: string;
          signingRootId: string;
          signingRootVersion: string;
        };
        return {
          ok: true,
          hssContext: {
            applicationBindingDigestB64u:
              await computeSdkEd25519HssApplicationBindingDigestB64u({
                nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
                  hssBindingFacts.nearEd25519SigningKeyId,
                ),
                signingRootId: parseSdkEcdsaHssSigningRootId(hssBindingFacts.signingRootId),
                signingRootVersion: parseSdkEcdsaHssSigningRootVersion(
                  hssBindingFacts.signingRootVersion,
                ),
              }),
            participantIds: [1, 2],
          },
          contextBindingB64u: 'client-context-binding',
          yClientB64u: 'y-client',
          tauClientB64u: 'tau-client',
        };
      },
      prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization: async (
        input: Record<string, unknown>,
      ) => {
        captures.ed25519SealAuthorizationArgs = input;
        return {
          ok: true,
          materialKeyId: 'registration-ed25519-material-key',
          remainingUses: 1,
          sealAuthorization: {
            kind: 'passkey_prf_material_seal_authorization_handle_v1',
            handle: 'registration-ed25519-seal-authorization',
            rpId: RP_ID,
            credentialIdB64u: 'registration-credential-id',
            materialKeyId: 'registration-ed25519-material-key',
            expiresAtMs: 0,
          },
        };
      },
      prepareThresholdEd25519HssClientOutputMaskHandle: async (input: Record<string, unknown>) => {
        captures.ed25519MaskArgs = input;
        const context = (input.context || {}) as Record<string, unknown>;
        return {
          clientOutputMaskHandle: 'client-output-mask-handle',
          contextBindingB64u: String(context.contextBindingB64u || ''),
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
        };
      },
      prepareThresholdEd25519HssClientRequest: async (input: Record<string, unknown>) => {
        captures.ed25519RequestArgs = input;
        return { clientRequestMessageB64u: 'client-request' };
      },
      runThresholdEd25519HssCeremonyWithMaterialHandle: async (input: Record<string, unknown>) => {
        captures.ed25519MaterialHandleCeremonyArgs = input;
        return {
          ok: true,
          signingMaterial: {
            materialHandle: 'registration-ed25519-worker-material',
            materialBindingDigest: 'registration-ed25519-worker-binding',
            sealedWorkerMaterialRef: 'registration-ed25519-sealed-worker-material',
            sealedWorkerMaterialB64u: 'registration-ed25519-sealed-worker-material-b64u',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: 'registration-ed25519-material-key',
            clientVerifyingShareB64u: 'registration-ed25519-client-verifying-share',
            signerSlot: 1,
          },
        };
      },
      buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle: async (
        input: Record<string, unknown>,
      ) => {
        captures.ed25519ArtifactArgs = input;
        return {
          contextBindingB64u: 'context-binding',
          stagedEvaluatorArtifactB64u: 'staged-artifact',
          addStageRequestMessageB64u: 'add-stage-request',
        };
      },
      finalizeWalletEd25519SignerRegistration: async (input: Record<string, unknown>) => {
        captures.storedEd25519 = input;
        return { signerSlot: input.signerSlot };
      },
      hydrateSigningSession,
      persistSigningSessionSealForThresholdSession: async (input: Record<string, unknown>) => {
        captures.persistedSigningSessionSeal = input;
        return {
          ok: true,
          sealedSecretB64u: 'sealed-registration-session',
          keyVersion: 'test-signing-session-seal-key',
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        };
      },
      getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
        nearAccountId,
        signerSlot,
      }),
      activateAuthenticatedWalletState: async () => undefined,
    },
    nearClient: {
      viewAccount: async () => {
        throw new Error('does not exist');
      },
    },
  };
}

function installRegisterWalletFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    registrationEvents(captures)?.push(`fetch:${path}`);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/router-ab/keyset') {
      return jsonResponse({
        keyset_version: 'router_ab_keyset_v2',
        signer_envelope_hpke: {
          current: {
            deriver_a: {
              role: 'signer_a',
              key_epoch: 'epoch-a',
              public_key: 'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            },
            deriver_b: {
              role: 'signer_b',
              key_epoch: 'epoch-b',
              public_key: 'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          },
        },
        signer_peer_verifying_keys: {
          deriver_a: {
            role: 'signer_a',
            verifying_key_hex: '1111111111111111111111111111111111111111111111111111111111111111',
          },
          deriver_b: {
            role: 'signer_b',
            verifying_key_hex: '2222222222222222222222222222222222222222222222222222222222222222',
          },
        },
        signing_worker_server_output_hpke: {
          key_epoch: 'epoch-signing-worker',
          public_key: 'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
      });
    }
    if (path === '/v1/registration/bootstrap-grants') {
      captures.bootstrapGrantBody = body;
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === '/wallets/register/intent') {
      captures.intentRequestBody = body;
      const selection = mockedRegistrationIntentSignerSelection(body.signerSelection);
      const walletId = mockedRegistrationWalletId(body);
      const intent = {
        version: 'registration_intent_v1' as const,
        walletId,
        authMethod: body.authMethod,
        signerSelection: selection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'registration-nonce',
      };
      const digest = await computeRegistrationIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        registrationIntentDigestB64u: digest,
        registrationIntentGrant: 'registration-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === '/wallets/register/prepare') {
      captures.prepareBody = body;
      return jsonResponse({
        ok: true,
        state: 'prepared',
        registrationPreparationId: 'registration-preparation-id',
        expiresAtMs: Date.now() + 60_000,
        ed25519: {
          ceremonyHandle: 'registration-ed25519-handle',
          preparedSession: {
            contextBindingB64u: 'prepared-context-binding',
            evaluatorDriverStateB64u: 'evaluator-driver-state',
          },
          clientOtOfferMessageB64u: 'client-ot-offer',
        },
      });
    }
    if (path === '/wallets/register/start') {
      captures.startBody = body;
      const hasEd25519 = mockedRegistrationHasSignerKind(
        body.intent.signerSelection,
        'near_ed25519',
      );
      const ecdsaSigner = mockedRegistrationEvmFamilyEcdsaSigner(body.intent.signerSelection);
      return jsonResponse({
        ok: true,
        registrationCeremonyId: 'registration-ceremony',
        intent: body.intent,
        ...(hasEd25519
          ? {
              ed25519: {
                ceremonyHandle: 'registration-ed25519-handle',
                preparedSession: {
                  contextBindingB64u: 'prepared-context-binding',
                  evaluatorDriverStateB64u: 'evaluator-driver-state',
                },
                clientOtOfferMessageB64u: 'client-ot-offer',
              },
            }
          : {}),
        ...(ecdsaSigner
          ? {
              ecdsa: {
                kind: 'evm_family_ecdsa_keygen',
                chainTargets: ecdsaSigner.chainTargets,
                prepare: {
                  formatVersion: 'ecdsa-hss-role-local',
                  walletSessionUserId: String(body.intent.walletId),
                  walletId: String(body.intent.walletId),
                  evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(body.intent.walletId),
                  rpId: RP_ID,
                  subjectId: String(body.intent.walletId),
                  ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                  signingRootId: 'project_matrix:dev',
                  signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                  applicationBindingDigestB64u: await ecdsaApplicationBindingDigestB64u(
                    body.intent.walletId,
                  ),
                  keyScope: 'evm-family',
                  relayerKeyId: 'relayer-ecdsa',
                  registrationPreparationId: body.registrationPreparationId,
                  requestId: 'request-ecdsa',
                  thresholdSessionId: 'session-ecdsa',
                  signingGrantId: 'wallet-session-ecdsa',
                  ttlMs: 600_000,
                  remainingUses: 1,
                  participantIds: [1, 2],
                  runtimePolicyScope: RUNTIME_POLICY_SCOPE,
                },
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/hss/respond') {
      captures.respondBody = body;
      const registrationEcdsaExpiresAtMs = Date.now() + 60_000;
      let ecdsaBootstrap = body.ecdsa
        ? ({
            ...body.ecdsa.clientBootstrap,
            publicIdentity: {
              hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
              relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
              groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
            },
            publicTranscriptDigest32B64u: 'transcript-digest',
            keyHandle: 'ehss-registration-key',
            relayerShareRetryCounter: 1,
            thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x3333333333333333333333333333333333333333',
            relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
            thresholdSessionId: String(body.ecdsa.clientBootstrap.thresholdSessionId || ''),
            expiresAtMs: registrationEcdsaExpiresAtMs,
            expiresAt: new Date(registrationEcdsaExpiresAtMs).toISOString(),
          } as Record<string, unknown>)
        : null;
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (ecdsaBootstrap && patchRegistrationBootstrap) {
        ecdsaBootstrap = patchRegistrationBootstrap(ecdsaBootstrap);
      }
      if (ecdsaBootstrap) {
        ecdsaBootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(ecdsaBootstrap);
      }
      return jsonResponse({
        ok: true,
        registrationCeremonyId: body.registrationCeremonyId,
        ...(body.ed25519
          ? {
              ed25519: {
                contextBindingB64u: 'server-context-binding',
                serverInputDeliveryB64u: 'server-input-delivery',
              },
            }
          : {}),
        ...(body.ecdsa
          ? {
              ecdsa: {
                bootstrap: ecdsaBootstrap,
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/finalize') {
      captures.finalizeBody = body;
      const sessionPolicy = body.ed25519?.sessionPolicy;
      const responseWalletId = String((captures.intent as any)?.walletId || WALLET_SUBJECT_ID);
      const responseBody: Record<string, unknown> = {
        ok: true,
        walletId: responseWalletId,
        rpId: RP_ID,
        authMethod: {
          kind: 'passkey',
          credentialIdB64u: 'registration-credential-id',
          credentialPublicKeyB64u: 'registration-credential-public-key',
          counter: 0,
        },
      };
      if (body.ed25519) {
        const nearAccountId =
          mockedRegistrationRequestedAccountId((captures.intent as any)?.signerSelection) ||
          'combined.testnet';
        const nearEd25519SigningKeyId = responseWalletId;
        responseBody.accountProvisioning = namedProvisioning(nearAccountId);
        responseBody.resolvedAccount = {
          kind: 'sponsored_named_account',
          nearAccountId,
          nearEd25519SigningKeyId,
          transactionHash: 'create-account-tx',
        };
        const thresholdSessionId = String(
          sessionPolicy.thresholdSessionId || sessionPolicy.sessionId || '',
        );
        const signingGrantId = String(sessionPolicy.signingGrantId || '');
        const ed25519SessionExpiresAtMs = Date.now() + 60_000;
        responseBody.ed25519 = {
          nearAccountId,
          nearEd25519SigningKeyId,
          publicKey: 'ed25519:public-key',
          relayerKeyId: 'relayer-ed25519',
          keyVersion: 'threshold-ed25519-hss-v1',
          recoveryExportCapable: true,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
          session: {
            sessionKind: 'jwt',
            walletId: responseWalletId,
            nearAccountId,
            nearEd25519SigningKeyId,
            thresholdSessionId,
            signingGrantId,
            expiresAtMs: ed25519SessionExpiresAtMs,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
            jwt: ed25519WalletSessionJwt({
              walletId: responseWalletId,
              nearAccountId,
              nearEd25519SigningKeyId,
              sessionId: thresholdSessionId,
              signingGrantId,
              relayerKeyId: 'relayer-ed25519',
              expiresAtMs: ed25519SessionExpiresAtMs,
              participantIds: [1, 2],
            }),
          },
        };
      }
      if (body.ecdsa) {
        const chainTargets = mockedRegistrationEvmFamilyEcdsaSigner(
          (captures.intent as any)?.signerSelection,
        )?.chainTargets || [{ kind: 'evm', namespace: 'eip155', chainId: 1 }];
        const patchRegistrationWalletKey = captures.patchRegistrationWalletKey as
          | ((walletKey: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        responseBody.ecdsa = {
          walletKeys: chainTargets.map((chainTarget: unknown) => {
            const walletKey = {
              keyScope: 'evm-family',
              chainTarget,
              walletSessionUserId: responseWalletId,
              walletId: responseWalletId,
              evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(responseWalletId),
              rpId: RP_ID,
              subjectId: responseWalletId,
              keyHandle: 'ehss-registration-key',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
              thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
              relayerKeyId: 'relayer-ecdsa',
              relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
              participantIds: [1, 2],
            };
            return patchRegistrationWalletKey ? patchRegistrationWalletKey(walletKey) : walletKey;
          }),
        };
      }
      return jsonResponse(responseBody);
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

async function withMockedIndexedDb<T>(run: () => Promise<T>): Promise<T> {
  clearAllStoredThresholdEd25519SessionRecords();
  clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  const indexedDB = IndexedDBManager as unknown as Record<string, unknown>;
  const originalListProfileAuthenticators = indexedDB.listProfileAuthenticators;
  const originalResolveProfileAccountContext = indexedDB.resolveProfileAccountContext;
  const originalGetKeyMaterial = IndexedDBManager.getKeyMaterial;
  const originalStoreKeyMaterial = IndexedDBManager.storeKeyMaterial;
  const keyMaterialWrites: unknown[] = [];
  indexedDB.listProfileAuthenticators = async () => [
    {
      credentialId: 'credential-id',
      transports: ['internal'],
    },
  ];
  indexedDB.resolveProfileAccountContext = async (accountRef: unknown) => ({
    profileId: 'near-profile:later.testnet',
    accountRef,
  });
  (IndexedDBManager as any).getKeyMaterial = async () => null;
  (IndexedDBManager as any).storeKeyMaterial = async (record: unknown) => {
    keyMaterialWrites.push(record);
  };
  try {
    return await run();
  } finally {
    indexedDB.listProfileAuthenticators = originalListProfileAuthenticators;
    indexedDB.resolveProfileAccountContext = originalResolveProfileAccountContext;
    (IndexedDBManager as any).getKeyMaterial = originalGetKeyMaterial;
    (IndexedDBManager as any).storeKeyMaterial = originalStoreKeyMaterial;
    clearAllStoredThresholdEd25519SessionRecords();
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  }
}

test('near.registerNearWallet wraps combined registration for configured ECDSA targets', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const signer = createLocalNearCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerNearWallet({
        accountProvisioning: namedProvisioning('wrapper.testnet'),
        wallet: { kind: 'provided', walletId: walletIdFromString('wrapper.testnet') },
        options: {},
      }),
    );
    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'wrapper.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect((captures.intentRequestBody as any)?.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: namedProvisioning('wrapper.testnet'),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
        {
          kind: 'evm_family_ecdsa',
          participantIds: [1, 2],
          chainTargets: [
            { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
            { kind: 'evm', namespace: 'eip155', chainId: 5042002, networkSlug: 'arc-testnet' },
          ],
        },
      ],
    });
    expect((captures.intent as any)?.signerSelection).toEqual(
      (captures.intentRequestBody as any)?.signerSelection,
    );
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.bootstrapGrantBody).toMatchObject({
      newAccountId: 'wrapper.testnet',
    });
    expect((captures.storedEcdsa as any)?.walletKeys).toMatchObject([
      {
        chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
        thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
      },
      {
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        },
        thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
      },
    ]);
  } finally {
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

test('near.registerNearWallet respects per-call disabled ECDSA provisioning', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const signer = createLocalNearCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerNearWallet({
        accountProvisioning: namedProvisioning('ed-only-wrapper.testnet'),
        wallet: { kind: 'provided', walletId: walletIdFromString('ed-only-wrapper.testnet') },
        options: {
          signerOptions: {
            tempo: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
            evm: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
          },
        },
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'ed-only-wrapper.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect((captures.intentRequestBody as any)?.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: namedProvisioning('ed-only-wrapper.testnet'),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    });
    expect((captures.intent as any)?.signerSelection).toEqual(
      (captures.intentRequestBody as any)?.signerSelection,
    );
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(fetchMock.paths).not.toContain('/router-ab/keyset');
    expect(captures.ecdsaClientBootstrapArgs).toBeUndefined();
  } finally {
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

test('registerWalletWithStartedPrecompute fails closed with scope mismatch diagnostics', async () => {
  const captures: Record<string, unknown> = {};
  const readState = { called: false };
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const result = await withMockedIndexedDb(() =>
      registerWalletWithStartedPrecompute({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'provided', walletId: walletIdFromString('scope-current.testnet') },
        signerSelection: registrationSignerSet(nearRegistrationSigner('scope-current.testnet')),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
        precompute: staleWalletPrecomputeHandle(readState),
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringContaining('Started wallet registration precompute scope mismatch'),
    });
    expect(String(result.error || '')).toContain('walletScopeKey');
    expect(readState.called).toBe(false);
  } finally {
    (globalThis as any).window = originalWindow;
  }
});

test('evm.registerEvmWallet wraps ECDSA-only wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const signer = createLocalEvmCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerEvmWallet({
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
        participantIds: [1, 2],
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect((captures.intentRequestBody as any)?.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'evm_family_ecdsa',
          chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
          participantIds: [1, 2],
        },
      ],
    });
    expect((captures.intent as any)?.signerSelection).toEqual(
      (captures.intentRequestBody as any)?.signerSelection,
    );
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.bootstrapGrantBody).toMatchObject({
      authority: {
        kind: 'passkey_rp',
        rpId: RP_ID,
      },
    });
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet orchestrates ECDSA-only wallet registration without NEAR profile work', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/start',
      '/wallets/register/hss/respond',
      '/wallets/register/finalize',
    ]);
    expect(captures.bootstrapGrantBody).not.toHaveProperty('newAccountId');
    expect(captures.registrationCredentialArgs).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      challengeB64u: captures.digest,
    });
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.ecdsaClientBootstrapArgs).toMatchObject({
      passkeyPrfFirstB64u: REGISTRATION_PRF_FIRST_B64U,
      credentialIdB64u: 'registration-credential-id',
    });
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        expectedKeyHandles: ['ehss-registration-key'],
      },
    });
    expect(captures.storedEcdsaRegistration).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      walletKeys: [
        {
          keyHandle: 'ehss-registration-key',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'registration-credential-id' },
    });
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet overlaps Email OTP enrollment material with ECDSA-only registration start', async () => {
  const events: string[] = [];
  const deferredEmailOtpEnrollmentMaterial = createDeferredPromise<Record<string, unknown>>();
  const captures: Record<string, unknown> = {
    registrationEvents: events,
    deferredEmailOtpEnrollmentMaterial,
  };
  const fetchMock = installRegisterWalletFetch(captures);
  const backupRepository = emailOtpRecoveryCodeBackupRepository as unknown as {
    write: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
    readMatching: (input: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
  };
  const originalBackupWrite = backupRepository.write;
  const originalBackupReadMatching = backupRepository.readMatching;
  const walletId = walletIdFromString('email-otp-ecdsa.testnet');
  const appSessionJwt = jwtWithPayload({
    providerSubject: 'google:registration-subject',
    appSessionVersion: 'app-session-v1',
  });
  try {
    backupRepository.write = async (input) => {
      captures.recoveryCodeBackupWrite = input;
      const record = {
        v: 1,
        secretKind: 'email_otp_recovery_codes_backup',
        storageScope: input.storageScope,
        status: 'stored',
        walletId: input.walletId,
        enrollmentId: input.enrollmentId,
        enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
        recoveryCodesIssuedAtMs: input.recoveryCodesIssuedAtMs,
        recoveryKeys: input.recoveryKeys,
        createdAtMs: 1_700_000_000_100,
        lastDisplayedAtMs: null,
        lastDownloadedAtMs: null,
      };
      captures.recoveryCodeBackupRecord = record;
      return record;
    };
    backupRepository.readMatching = async () =>
      (captures.recoveryCodeBackupRecord as Record<string, unknown> | undefined) || null;
    const registration = withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email: 'ALICE@EXAMPLE.COM',
          appSessionJwt,
          googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
          googleEmailOtpRegistrationOfferId: 'registration-offer-1',
          googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
        },
        wallet: { kind: 'provided', walletId },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    await waitForTestCondition({
      label: 'registration start before Email OTP enrollment material resolves',
      predicate: () => fetchMock.paths.includes('/wallets/register/start'),
    });

    expect(events).toContain('emailOtpEnrollmentMaterialStarted');
    expect(fetchMock.paths).toContain('/wallets/register/start');
    expect(fetchMock.paths).not.toContain('/wallets/register/hss/respond');
    expect(fetchMock.paths).not.toContain('/wallets/register/finalize');
    expect(captures.ecdsaClientBootstrapArgs).toBeUndefined();

    deferredEmailOtpEnrollmentMaterial.resolve(
      emailOtpRegistrationEnrollmentMaterial({
        walletId: String(walletId),
        userId: 'google:registration-subject',
      }),
    );
    const result = await registration;

    expectRegistrationSuccess(result);
    expect(events).toEqual(
      expect.arrayContaining([
        'emailOtpEnrollmentMaterialStarted',
        'fetch:/wallets/register/start',
        'emailOtpEnrollmentMaterialResolved',
        'ecdsaClientBootstrapStarted',
        'fetch:/wallets/register/hss/respond',
        'fetch:/wallets/register/finalize',
      ]),
    );
    expect(events.indexOf('fetch:/wallets/register/start')).toBeLessThan(
      events.indexOf('emailOtpEnrollmentMaterialResolved'),
    );
    expect(events.indexOf('emailOtpEnrollmentMaterialResolved')).toBeLessThan(
      events.indexOf('ecdsaClientBootstrapStarted'),
    );
    expect(events.indexOf('ecdsaClientBootstrapStarted')).toBeLessThan(
      events.indexOf('fetch:/wallets/register/hss/respond'),
    );
    expect(captures.emailOtpEnrollmentMaterialArgs).toMatchObject({
      walletId: String(walletId),
      userId: 'google:registration-subject',
      appSessionJwt,
      targets: [
        expect.objectContaining({
          evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(walletId),
        }),
      ],
    });
    expect(captures.ecdsaClientBootstrapArgs).toMatchObject({
      clientRootShareHandle: {
        walletId: String(walletId),
        authSubjectId: 'google:registration-subject',
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      emailOtpEnrollment: {
        clientUnlockPublicKeyB64u: 'email-otp-client-unlock-public-key',
        thresholdEcdsaClientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        offerId: 'registration-offer-1',
        candidateId: 'registration-candidate-1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        backupActionKind: 'manual',
        acknowledgedAtMs: expect.any(Number),
        idempotencyKey: expect.stringContaining('email-otp-recovery-code-backup-ack'),
      },
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: {
        kind: 'email_otp',
        emailOtpAuthContext: {
          authority: {
            factor: {
              kind: 'email_otp',
            },
          },
        },
      },
    });
  } finally {
    backupRepository.write = originalBackupWrite;
    backupRepository.readMatching = originalBackupReadMatching;
    deferredEmailOtpEnrollmentMaterial.reject(new Error('test cleanup'));
    fetchMock.restore();
  }
});

test('registerWallet rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      publicIdentity: {
        ...(bootstrap.publicIdentity as Record<string, unknown>),
        hssClientSharePublicKey33B64u: MISMATCHED_CLIENT_PUBLIC_KEY_B64U,
      },
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/hssClientSharePublicKey33B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet rejects mismatched ECDSA wallet key before registration persistence', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationWalletKey: (walletKey: Record<string, unknown>) => ({
      ...walletKey,
      keyHandle: 'mismatched-key-handle',
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/keyHandle mismatch/),
    });
    expect(captures.finalizeBody).toBeDefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet orchestrates combined Ed25519 and ECDSA wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  const originalConsoleInfo = console.info;
  const consoleInfoCalls: unknown[][] = [];
  (globalThis as any).window = { isSecureContext: true };
  console.info = (...args: unknown[]) => {
    consoleInfoCalls.push(args);
  };
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey', rpId: RP_ID },
        wallet: { kind: 'server_allocated' },
        signerSelection: registrationSignerSet(
          nearRegistrationSigner('combined.testnet'),
          evmFamilyRegistrationSigner([{ kind: 'evm', namespace: 'eip155', chainId: 1 }]),
        ),
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/router-ab/keyset',
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/prepare',
      '/wallets/register/start',
      '/wallets/register/hss/respond',
      '/wallets/register/finalize',
    ]);
    expect(captures.registrationCredentialArgs).toMatchObject({
      walletId: 'combined.testnet',
      challengeB64u: captures.digest,
    });
    expectSingleRegistrationTouchIdPrompt(captures);
    expect(captures.respondBody).toMatchObject({
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
        },
      },
      ecdsa: {
        clientBootstrap: {
          hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        },
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      ed25519: {
        evaluationResult: {
          contextBindingB64u: 'context-binding',
          stagedEvaluatorArtifactB64u: 'staged-artifact',
          addStageRequestMessageB64u: 'add-stage-request',
        },
        sessionKind: 'jwt',
      },
      ecdsa: {
        expectedKeyHandles: ['ehss-registration-key'],
      },
    });
    expect(captures.storedEd25519Registration).toMatchObject({
      walletId: 'combined.testnet',
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      signerSlot: 1,
      relayerKeyId: 'relayer-ed25519',
    });
    expect(captures.storedEcdsa).toMatchObject({
      walletId: 'combined.testnet',
      walletKeys: [
        {
          keyHandle: 'ehss-registration-key',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    const activeRuntimeStates = registrationProgressEvents(
      consoleInfoCalls,
      'registration_active_runtime_state_constructed',
    );
    expect(activeRuntimeStates).toHaveLength(1);
    expect(activeRuntimeStates[0]).toMatchObject({
      stage: 'registration_active_runtime_state_constructed',
      walletId: 'combined.testnet',
      authMethod: 'passkey',
      ed25519: 'near_ed25519_ready',
      ed25519ThresholdSessionId: expect.stringMatching(/^tsess-/),
      ed25519SigningGrantId: 'wallet-session-ecdsa',
      ecdsa: 'evm_family_ecdsa_ready',
      ecdsaThresholdSessionId: 'session-ecdsa',
      ecdsaSigningGrantId: 'wallet-session-ecdsa',
      ecdsaTargetCount: 1,
    });
    const timingSummaries = consolePayloadsForLabel(
      consoleInfoCalls,
      '[Registration] wallet timing summary',
    );
    expect(timingSummaries).toHaveLength(1);
    expect(timingSummaries[0]).toMatchObject({
      kind: 'registration_timing_summary_v1',
      status: 'succeeded',
      authMethod: 'passkey',
      signerSet: {
        kind: 'signer_set',
        branches: ['near_ed25519', 'evm_family_ecdsa'],
      },
      criticalPath: {
        kind: 'registration_critical_path_summary_v1',
        totalElapsedMs: expect.any(Number),
        measuredWorkMs: expect.any(Number),
        overlappedOrBackgroundMs: expect.any(Number),
        topBuckets: expect.any(Array),
      },
      timings: {
        inputValidationMs: expect.any(Number),
        registrationWarmupMs: expect.any(Number),
        registrationWarmupWaitMs: expect.any(Number),
        registrationWarmupAuthenticatedWalletStateMs: expect.any(Number),
        registrationWarmupNoncePrefetchMs: expect.any(Number),
        registrationWarmupKeyMaterialReadMs: expect.any(Number),
        registrationWarmupUiConfirmPrewarmMs: expect.any(Number),
        registrationWarmupSignerWorkerPrewarmMs: expect.any(Number),
        managedRegistrationGrantMs: expect.any(Number),
        registrationIntentMs: expect.any(Number),
        registrationIntentDigestMs: expect.any(Number),
        authProofMs: expect.any(Number),
        passkeyAuthConfirmationMs: expect.any(Number),
        passkeyAuthPrfExtractionMs: expect.any(Number),
        passkeyAuthCredentialRedactionMs: expect.any(Number),
        passkeyAuthWorkerReadyMs: expect.any(Number),
        passkeyAuthWorkerRequestRoundTripMs: expect.any(Number),
        passkeyAuthWorkerResponseValidationMs: expect.any(Number),
        passkeyAuthRequestSetupMs: expect.any(Number),
        passkeyAuthPromptUserMs: expect.any(Number),
        passkeyAuthPromptElementDefineMs: expect.any(Number),
        passkeyAuthPromptMountMs: expect.any(Number),
        passkeyAuthPromptHostFirstUpdateMs: expect.any(Number),
        passkeyAuthPromptHostInteractiveMs: expect.any(Number),
        passkeyAuthPromptConfirmEventMs: expect.any(Number),
        passkeyAuthPromptDecisionWaitMs: expect.any(Number),
        passkeyAuthCredentialCreateStartMs: expect.any(Number),
        passkeyAuthCredentialCreateMs: expect.any(Number),
        passkeyAuthCredentialSerializeMs: expect.any(Number),
        passkeyAuthDuplicateRetryCount: expect.any(Number),
        passkeyAuthMainThreadTotalMs: expect.any(Number),
        ed25519ClientMaterialMs: expect.any(Number),
        walletRegisterPrepareMs: expect.any(Number),
        walletRegisterPrepareWaitMs: expect.any(Number),
        walletRegisterStartMs: expect.any(Number),
        ed25519ClientRequestMs: expect.any(Number),
        ecdsaClientBootstrapMs: expect.any(Number),
        walletRegisterHssRespondMs: expect.any(Number),
        ed25519EvaluationArtifactMs: expect.any(Number),
        walletRegisterFinalizeMs: expect.any(Number),
        ed25519CompletionParseMs: expect.any(Number),
        localWalletRegistrationPersistenceMs: expect.any(Number),
        thresholdEd25519SessionPersistenceMs: expect.any(Number),
        ecdsaRegistrationPersistenceMs: expect.any(Number),
        walletStateActivationMs: expect.any(Number),
        immediateSigningLaneAssertionMs: expect.any(Number),
        auth: {
          kind: 'passkey',
          passkeyAuthConfirmationMs: expect.any(Number),
          passkeyAuthPrfExtractionMs: expect.any(Number),
          passkeyAuthCredentialRedactionMs: expect.any(Number),
          passkeyAuthWorkerReadyMs: expect.any(Number),
          passkeyAuthWorkerRequestRoundTripMs: expect.any(Number),
          passkeyAuthWorkerResponseValidationMs: expect.any(Number),
          passkeyAuthRequestSetupMs: expect.any(Number),
          passkeyAuthPromptUserMs: expect.any(Number),
          passkeyAuthPromptElementDefineMs: expect.any(Number),
          passkeyAuthPromptMountMs: expect.any(Number),
          passkeyAuthPromptHostFirstUpdateMs: expect.any(Number),
          passkeyAuthPromptHostInteractiveMs: expect.any(Number),
          passkeyAuthPromptConfirmEventMs: expect.any(Number),
          passkeyAuthPromptDecisionWaitMs: expect.any(Number),
          passkeyAuthCredentialCreateStartMs: expect.any(Number),
          passkeyAuthCredentialCreateMs: expect.any(Number),
          passkeyAuthCredentialSerializeMs: expect.any(Number),
          passkeyAuthDuplicateRetryCount: expect.any(Number),
          passkeyAuthMainThreadTotalMs: expect.any(Number),
          emailOtpEnrollmentMaterialMs: 0,
          emailOtpRecoveryCodeBackupMs: 0,
        },
        ed25519: {
          kind: 'ed25519_enabled',
        },
        ecdsa: {
          kind: 'ecdsa_enabled',
        },
      },
    });
  } finally {
    console.info = originalConsoleInfo;
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

function installAddSignerFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/v1/registration/bootstrap-grants') {
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/intent`) {
      const intent = {
        version: 'add_signer_intent_v1' as const,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: body.signerSelection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'add-signer-nonce',
      };
      const digest = await computeAddSignerIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        addSignerIntentDigestB64u: digest,
        addSignerIntentGrant: 'add-signer-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/start`) {
      captures.startBody = body;
      if (body.intent?.signerSelection?.mode === 'ecdsa') {
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: 'add-signer-ceremony',
          intent: body.intent,
          ecdsa: {
            kind: 'evm_family_ecdsa_keygen',
            chainTargets: body.intent.signerSelection.ecdsa.chainTargets,
            prepare: {
              formatVersion: 'ecdsa-hss-role-local',
              walletSessionUserId: String(WALLET_SUBJECT_ID),
              walletId: String(WALLET_SUBJECT_ID),
              evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(WALLET_SUBJECT_ID),
              rpId: RP_ID,
              subjectId: String(WALLET_SUBJECT_ID),
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              applicationBindingDigestB64u: await ecdsaApplicationBindingDigestB64u(
                WALLET_SUBJECT_ID,
              ),
              keyScope: 'evm-family',
              relayerKeyId: 'relayer-ecdsa',
              requestId: 'request-ecdsa',
              thresholdSessionId: 'session-ecdsa',
              signingGrantId: 'wallet-session-ecdsa',
              ttlMs: 600_000,
              remainingUses: 1,
              participantIds: [1, 2],
              runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            },
          },
        });
      }
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: 'add-signer-ceremony',
        intent: body.intent,
        ed25519: {
          ceremonyHandle: 'ed25519-ceremony',
          preparedSession: {
            contextBindingB64u: 'server-context-binding',
            evaluatorDriverStateB64u: 'evaluator-driver-state',
          },
          clientOtOfferMessageB64u: 'client-ot-offer',
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`) {
      captures.respondBody = body;
      if (body.ecdsa) {
        const addSignerEcdsaExpiresAtMs = Date.now() + 60_000;
        let ecdsaBootstrap = {
          ...body.ecdsa.clientBootstrap,
          publicIdentity: {
            hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
            groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          },
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'ehss-key-matrix',
          relayerShareRetryCounter: 1,
          thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
          thresholdSessionId: String(body.ecdsa.clientBootstrap.thresholdSessionId || ''),
          expiresAtMs: addSignerEcdsaExpiresAtMs,
          expiresAt: new Date(addSignerEcdsaExpiresAtMs).toISOString(),
        } as Record<string, unknown>;
        const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
          | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        if (patchAddSignerBootstrap) {
          ecdsaBootstrap = patchAddSignerBootstrap(ecdsaBootstrap);
        }
        ecdsaBootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(ecdsaBootstrap);
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: body.addSignerCeremonyId,
          ecdsa: {
            bootstrap: ecdsaBootstrap,
          },
        });
      }
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: body.addSignerCeremonyId,
        ed25519: {
          contextBindingB64u: 'server-context-binding',
          serverInputDeliveryB64u: 'server-input-delivery',
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`) {
      captures.finalizeBody = body;
      if (body.ecdsa) {
        return jsonResponse({
          ok: true,
          walletId: WALLET_SUBJECT_ID,
          rpId: RP_ID,
          ecdsa: {
            walletKeys: [
              {
                keyScope: 'evm-family',
                chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
                walletSessionUserId: String(WALLET_SUBJECT_ID),
                walletId: String(WALLET_SUBJECT_ID),
                evmFamilySigningKeySlotId: plannedEcdsaWalletKeyId(WALLET_SUBJECT_ID),
                rpId: RP_ID,
                subjectId: String(WALLET_SUBJECT_ID),
                keyHandle: 'ehss-key-matrix',
                ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                signingRootId: 'project_matrix:dev',
                signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
                thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
                relayerKeyId: 'relayer-ecdsa',
                relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
                participantIds: [1, 2],
              },
            ],
          },
        });
      }
      const sessionPolicy = body.ed25519.sessionPolicy;
      const thresholdSessionId = String(
        sessionPolicy.thresholdSessionId || sessionPolicy.sessionId || '',
      );
      const signingGrantId = String(sessionPolicy.signingGrantId || '');
      const ed25519SessionExpiresAtMs = Date.now() + 60_000;
      return jsonResponse({
        ok: true,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        ed25519: {
          nearAccountId: 'later.testnet',
          nearEd25519SigningKeyId: 'later.testnet',
          publicKey: 'ed25519:public-key',
          relayerKeyId: 'relayer-ed25519',
          keyVersion: 'threshold-ed25519-hss-v1',
          recoveryExportCapable: true,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
          session: {
            sessionKind: 'jwt',
            walletId: WALLET_SUBJECT_ID,
            nearAccountId: 'later.testnet',
            nearEd25519SigningKeyId: 'later.testnet',
            thresholdSessionId,
            signingGrantId,
            expiresAtMs: ed25519SessionExpiresAtMs,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
            jwt: ed25519WalletSessionJwt({
              walletId: WALLET_SUBJECT_ID,
              nearAccountId: 'later.testnet',
              nearEd25519SigningKeyId: 'later.testnet',
              sessionId: thresholdSessionId,
              signingGrantId,
              relayerKeyId: 'relayer-ed25519',
              expiresAtMs: ed25519SessionExpiresAtMs,
              participantIds: [1, 2],
            }),
          },
        },
      });
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

test('addWalletSigner orchestrates later ECDSA from an Ed25519 wallet', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    expect(captures.authenticationArgs).toMatchObject({
      challengeB64u: captures.digest,
      includeSecondPrfOutput: false,
    });
    expect(captures.startBody).toMatchObject({
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          clientExtensionResults: null,
        },
      },
    });
    expect(captures.ecdsaClientBootstrapArgs).toMatchObject({
      passkeyPrfFirstB64u: AUTHENTICATION_PRF_FIRST_B64U,
      credentialIdB64u: 'credential-id',
    });
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        expectedKeyHandles: ['ehss-key-matrix'],
      },
    });
    expect(captures.storedEcdsa).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      walletKeys: [
        {
          keyHandle: 'ehss-key-matrix',
          thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
        },
      ],
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'credential-id' },
    });
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchAddSignerBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      contextBinding32B64u: 'mismatched-context-binding',
    }),
  };
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/contextBinding32B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsa).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner orchestrates later Ed25519 from an ECDSA wallet', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_near_account',
            nearAccountId: 'later.testnet',
            signerSlot: 2,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
            derivationVersion: 1,
          },
        },
        options: {},
      }),
    );

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'later.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    expect(captures.ed25519MaterialArgs).toMatchObject({
      hssBindingFacts: {
        nearEd25519SigningKeyId: 'later.testnet',
        signingRootId: 'project_matrix:dev',
        signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
      },
      participantIds: [1, 2],
    });
    expect(captures.respondBody).toMatchObject({
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
        },
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      ed25519: {
        evaluationResult: {
          contextBindingB64u: 'context-binding',
          stagedEvaluatorArtifactB64u: 'staged-artifact',
          addStageRequestMessageB64u: 'add-stage-request',
        },
        sessionKind: 'jwt',
      },
    });
    expect(captures.storedEd25519).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      nearAccountId: 'later.testnet',
      operationalPublicKey: 'ed25519:public-key',
      signerSlot: 2,
      relayerKeyId: 'relayer-ed25519',
    });
    expect(captures.hydratedSession).toMatchObject({
      sessionId: (captures.finalizeBody as any).ed25519.sessionPolicy.thresholdSessionId,
      prfFirstB64u: AUTHENTICATION_PRF_FIRST_B64U,
      transport: {
        curve: 'ed25519',
        walletId: String(WALLET_SUBJECT_ID),
        walletSessionJwt: expect.any(String),
      },
    });
  } finally {
    fetchMock.restore();
  }
});
