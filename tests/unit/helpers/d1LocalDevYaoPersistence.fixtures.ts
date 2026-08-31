import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWalletKeyId,
  parseWalletRecoveryOperationId,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import {
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  deriveRouterAbEd25519YaoStableContextBindingV1,
  ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1,
  parseRouterAbEd25519YaoExportAdmissionReceiptV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoExportExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportBindingV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  buildWalletAuthMethodRecordV2,
  registrationIntentGrantFromString,
  walletIdFromString,
  type RegistrationIntentV1,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseEd25519PublicKeyB64u } from '@shared/passkey-custody/primitives';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeLocatorV1,
  parseRecoveryCodeReservationId,
  parseWalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
import { buildWalletRecoveryBackupAcknowledgementV1 } from '@shared/wallet-recovery/backupAcknowledgement';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../packages/wallet-server/src/core/WalletStore';
import { D1WalletAuthMethodStore } from '../../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { D1WalletStore } from '../../../packages/wallet-server/src/core/d1WalletStore';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import type { CfExecutionContext } from '../../../packages/wallet-server/src/router/cloudflare/runtime/cloudflare.types';
import { buildRouterAbEd25519YaoRegistrationCapabilityRecordV1 } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1 } from '../../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoProductRegistrationPartitionedStateStore';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationRequestScopedRuntime';
import type { D1DatabaseLike } from '../../../packages/wallet-server/src/storage/tenantRoute';
import type { CloudflareServiceBindingFetcher } from '../../../packages/wallet-console-server-ts/src/router/cloudflare/routerAbServiceBindings';
import localD1DevWorker from '../../../packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker';
import { AuthorizationService } from '../../../packages/wallet-server/src/authorization/service';
import { capabilityPolicyPort } from '../../../packages/wallet-server/src/authorization/capabilityPolicy';
import { CloudflareD1AuthorizationStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { prepareD1WalletAuthorityPutStatement } from '../../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { createCloudflareD1RouterApiAuthService } from '../../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { routerAbMpcMaterialActivationRefFromWire } from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { resolveWalletSessionAuthorizationV2Admission } from '../../../packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission';
import { CloudflareD1WalletCustodyCommitStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { CloudflareD1WebAuthnStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import {
  buildWebAuthnRecoveryContinuityAnchorRecord,
  type WebAuthnRecoveryRegistrationChallengeRecord,
} from '../../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnRecords';
import { resolveWalletRecoveryKeyManifestV1 } from '../../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryKeyManifest';
import {
  UnavailableRouterAbEd25519YaoRegistrationBackend,
} from './routerAbEd25519YaoRegistrationBridge.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './linkedDeviceManagement.fixtures';
import { insertEmailOtpEnrollment } from './cloudflareD1RouterApiAuthService.fixtures';
import { SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort } from '../../helpers/routerAbSigningRuntimeTestUtils';
import {
  passkeyCustodyEnvelope,
  rawEmailOtpFactor,
  rawWalletCustodySeedBinding,
  rawWalletRecoveryCodeLocators,
  rawWalletRecoveryEnvelopeSet,
} from './passkeyCustodyEnvelope.fixtures';

const NAMESPACE = 'seams-local-yao-persistence';
const ORG_ID = 'org_abcdefgh1234';
const PROJECT_ID = 'project-local-yao';
const ENV_ID = 'env-local-yao';
const SIGNING_WORKER_ID = 'signing-worker.local';
const ROOT_SHARE_EPOCH = 'root-local-yao-v1';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;
const EXPIRES_AT_MS = 4_102_444_800_000;
const LOCAL_CEREMONY_ISSUER = 'http://127.0.0.1:4100';
const LOCAL_CEREMONY_AUDIENCE = 'router-ab';
const LOCAL_CEREMONY_KEY_ID = 'local-router-ab-r1';
const LOCAL_CEREMONY_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'dZBo_spdvrGU19BMbbgt3_4I4QlqHoNzfr1zH3QqFyI',
  d: 'iUlWL9uMjgvXkHHq9q0y-jfVnOEQ3nZLCObiP3tatqE',
} as const;
const LOCAL_ORIGIN = 'http://127.0.0.1:8787';
const EMAIL_PROVIDER_SUBJECT_ID = 'google:local-yao-user';
const EMAIL_ADDRESS = 'local-yao@example.test';

function localMaterialActivation(lifecycleBinding: string) {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `activation:${lifecycleBinding}`,
    capability: 'capability:local-existing-yao',
    material_owner: localWalletId(),
    key_binding: 'key:local-existing-yao',
    lifecycle_binding: lifecycleBinding,
    signing_worker: SIGNING_WORKER_ID,
  };
}

type LocalD1DevWorkerEnv = Parameters<typeof localD1DevWorker.fetch>[1];
type RegistrationBinding = RouterAbEd25519YaoActivationBindingV1<'registration'>;
type RegistrationExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
type RecoveryBinding = RouterAbEd25519YaoActivationBindingV1<'recovery'>;
type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type ActiveEmailOtpWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'email_otp'; readonly status: 'active' }
>;

class UnsupportedServiceBinding implements CloudflareServiceBindingFetcher {
  async fetch(): Promise<Response> {
    return Response.json({ ok: false, code: 'unexpected_service_binding' }, { status: 500 });
  }
}

class DeferredValue<T> {
  readonly promise: Promise<T>;
  private resolveValue: ((value: T) => void) | null = null;

  constructor() {
    this.promise = new Promise<T>(this.captureResolver.bind(this));
  }

  resolve(value: T): void {
    if (!this.resolveValue) throw new Error('Deferred value is already resolved');
    const resolve = this.resolveValue;
    this.resolveValue = null;
    resolve(value);
  }

  private captureResolver(resolve: (value: T) => void): void {
    this.resolveValue = resolve;
  }
}

class LocalYaoExecutionContext implements CfExecutionContext {
  waitUntil(promise: Promise<unknown>): void {
    void promise;
  }

  passThroughOnException(): void {}
}

type RouterDelayState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'armed'; readonly entered: DeferredValue<void> }
  | {
      readonly kind: 'entered';
      readonly entered: DeferredValue<void>;
      readonly response: DeferredValue<Response>;
      readonly value: Response;
    };

export class LocalYaoRouterBindingFixture implements CloudflareServiceBindingFetcher {
  executeCalls = 0;
  registrationExecuteCalls = 0;
  recoveryExecuteCalls = 0;
  exportExecuteCalls = 0;
  recoveryPromotionCalls = 0;
  private delay: RouterDelayState = { kind: 'idle' };

  deferNextExecute(): void {
    if (this.delay.kind !== 'idle') throw new Error('Router execute is already deferred');
    this.delay = { kind: 'armed', entered: new DeferredValue<void>() };
  }

  async waitUntilExecuteEntered(): Promise<void> {
    if (this.delay.kind === 'idle') throw new Error('Router execute was not deferred');
    await this.delay.entered.promise;
  }

  releaseDeferredExecute(): void {
    if (this.delay.kind !== 'entered') {
      throw new Error('Deferred Router execute has not entered');
    }
    const delay = this.delay;
    this.delay = { kind: 'idle' };
    delay.response.resolve(delay.value);
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    const pathname = new URL(request.url).pathname;
    if (pathname === '/router-ab/router/ed25519-yao/recovery/promote') {
      return await this.promoteRecovery(request);
    }
    if (pathname !== '/router-ab/router/ed25519-yao/execute') {
      return Response.json({ ok: false, code: 'unexpected_router_path' }, { status: 404 });
    }
    const body = requireRecord(await request.json(), 'Router execute request');
    const response = this.executeResponse(body);
    if (!response.ok) return response.value;
    this.executeCalls += 1;
    if (this.delay.kind !== 'armed') return response.value;
    const entered = this.delay.entered;
    const deferredResponse = new DeferredValue<Response>();
    this.delay = {
      kind: 'entered',
      entered,
      response: deferredResponse,
      value: response.value,
    };
    entered.resolve();
    return await deferredResponse.promise;
  }

  private executeResponse(
    body: Record<string, unknown>,
  ):
    | { readonly ok: true; readonly value: Response }
    | { readonly ok: false; readonly value: Response } {
    switch (body.operation) {
      case 'registration': {
        const execution = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(
          executeProtocolFields(body),
        );
        if (!execution.ok) return invalidRouterRequest(execution.code);
        this.registrationExecuteCalls += 1;
        return { ok: true, value: this.activationSuccessResponse(execution.value.binding) };
      }
      case 'recovery': {
        const execution = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(
          executeProtocolFields(body),
        );
        if (!execution.ok) return invalidRouterRequest(execution.code);
        this.recoveryExecuteCalls += 1;
        return { ok: true, value: this.activationSuccessResponse(execution.value.binding) };
      }
      case 'export': {
        const execution = parseRouterAbEd25519YaoExportExecuteRequestV1(
          executeProtocolFields(body),
        );
        if (!execution.ok) return invalidRouterRequest(execution.code);
        this.exportExecuteCalls += 1;
        return { ok: true, value: exportSuccessResponse(execution.value) };
      }
      default:
        return {
          ok: false,
          value: Response.json({ ok: false, code: 'unexpected_operation' }, { status: 400 }),
        };
    }
  }

  private activationSuccessResponse(binding: RegistrationBinding | RecoveryBinding): Response {
    return Response.json({
      status: 'succeeded',
      result: {
        operation: binding.operation,
        result: activationResult(binding),
      },
    });
  }

  private async promoteRecovery(request: Request): Promise<Response> {
    const parsed = parseRouterAbEd25519YaoRecoveryActivationRequestV1(await request.json());
    if (!parsed.ok) return Response.json({ ok: false, code: parsed.code }, { status: 400 });
    this.recoveryPromotionCalls += 1;
    return Response.json({
      status: 'active',
      session: parsed.value.binding.session_id,
      transcript: parsed.value.public_receipt.transcript,
      registered_public_key: parsed.value.public_receipt.registered_public_key,
      joined_client_commitment: parsed.value.public_receipt.joined_client_commitment,
      joined_signing_worker_commitment:
        parsed.value.public_receipt.joined_signing_worker_commitment,
      signing_worker_verifying_share: parsed.value.public_receipt.signing_worker_verifying_share,
      state_epoch: parsed.value.public_receipt.state_epoch,
    });
  }
}

function executeProtocolFields(body: Record<string, unknown>) {
  return {
    binding: body.binding,
    deriver_a_input: body.deriver_a_input,
    deriver_b_input: body.deriver_b_input,
  };
}

function invalidRouterRequest(code: string): { readonly ok: false; readonly value: Response } {
  return { ok: false, value: Response.json({ ok: false, code }, { status: 400 }) };
}

export function createLocalYaoWorkerEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
  readonly router: LocalYaoRouterBindingFixture;
}): LocalD1DevWorkerEnv {
  const unsupported = new UnsupportedServiceBinding();
  return {
    CONSOLE_DB: input.consoleDatabase,
    SIGNER_DB: input.signerDatabase,
    MPC_ROUTER: input.router,
    SIGNING_WORKER: unsupported,
    SEAMS_TENANT_STORAGE_NAMESPACE: NAMESPACE,
    SEAMS_LOCAL_CONSOLE_USER_ID: 'local-yao-user',
    SEAMS_LOCAL_CONSOLE_ORG_ID: ORG_ID,
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: PROJECT_ID,
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: ENV_ID,
    LINKED_DEVICE_WEBAUTHN_RP_ID: 'wallet.local',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID,
    SIGNING_WORKER_ID,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-yao-internal-auth',
    ROUTER_AB_CEREMONY_JWT_ISSUER: LOCAL_CEREMONY_ISSUER,
    ROUTER_AB_CEREMONY_JWT_AUDIENCE: LOCAL_CEREMONY_AUDIENCE,
    ROUTER_AB_CEREMONY_JWT_KEY_ID: LOCAL_CEREMONY_KEY_ID,
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'11'.repeat(32)}`,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'22'.repeat(32)}`,
    DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'11'.repeat(32)}`,
    DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: `x25519:${'22'.repeat(32)}`,
    DERIVER_A_PEER_VERIFYING_KEY_HEX: '33'.repeat(32),
    DERIVER_B_PEER_VERIFYING_KEY_HEX: '44'.repeat(32),
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH: 'epoch-1',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: `x25519:${'55'.repeat(32)}`,
    ACCOUNT_ID_DERIVATION_SECRET: 'local-yao-account-id-secret',
    ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK: JSON.stringify(LOCAL_CEREMONY_PRIVATE_JWK),
    ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: JSON.stringify({
      routerId: 'local-router',
      signerSet: {
        signer_set_id: 'signer-set-v1',
        policy: 'all_2',
        signer_a: { role: 'signer_a', signer_id: 'signer-a', key_epoch: 'epoch-1' },
        signer_b: { role: 'signer_b', signer_id: 'signer-b', key_epoch: 'epoch-1' },
        selected_server: {
          server_id: SIGNING_WORKER_ID,
          key_epoch: 'epoch-1',
          recipient_encryption_key: 'unused-local-recipient-key',
        },
      },
      deriverRecipientKeys: {
        deriver_a: { role: 'signer_a', key_epoch: 'epoch-1', public_key: 'unused-a' },
        deriver_b: { role: 'signer_b', key_epoch: 'epoch-1', public_key: 'unused-b' },
      },
    }),
  };
}

export function buildLocalYaoRegistrationFixture(lifecycleId: string) {
  const walletId = walletIdFromString(`wallet-${lifecycleId}`);
  const grant = registrationIntentGrantFromString(`rig_${lifecycleId}-credential`);
  const admission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: lifecycleId,
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: walletId,
      threshold_session_id: `wallet-session-${lifecycleId}`,
      signer_set_id: 'ed25519:1',
      signing_worker_id: SIGNING_WORKER_ID,
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: `activation-${lifecycleId}`,
        capability: `capability-${lifecycleId}`,
        material_owner: String(walletId),
        key_binding: `key-${lifecycleId}`,
        lifecycle_binding: lifecycleId,
        signing_worker: SIGNING_WORKER_ID,
      },
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: `ed25519ks_${lifecycleId}`,
      signing_root_id: SIGNING_ROOT_ID,
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
  });
  if (!admission.ok) throw new Error(admission.message);
  return {
    admission: admission.value,
    grant,
    intent: registrationIntent(walletId),
  };
}

export async function bindLocalYaoRegistrationIntent(input: {
  readonly signerDatabase: D1DatabaseLike;
  readonly fixture: ReturnType<typeof buildLocalYaoRegistrationFixture>;
}): Promise<void> {
  const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1({
    database: input.signerDatabase,
    scope: { namespace: NAMESPACE, orgId: ORG_ID, projectId: PROJECT_ID, envId: ENV_ID },
  });
  const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
    signingWorkerId: SIGNING_WORKER_ID,
    store,
    registrationBackend: new UnavailableRouterAbEd25519YaoRegistrationBackend(),
  });
  const result = await runtime.bindVerifiedIntent({
    kind: 'verified_registration_intent',
    registrationIntentGrant: input.fixture.grant,
    intent: input.fixture.intent,
    admissionRequest: input.fixture.admission,
    expiresAtMs: EXPIRES_AT_MS,
  });
  if (!result.ok) throw new Error(result.message);
}

export async function buildLocalYaoExistingWalletFixture(input: {
  readonly signerDatabase: D1DatabaseLike;
  readonly lifecycleId: string;
}) {
  const capability = await buildLocalRegistrationCapability();
  await persistLocalCapability(input.signerDatabase, capability);
  const session = await issueLocalWalletSessionCredential({
    database: input.signerDatabase,
    capability,
  });
  const recovery = await prepareLocalYaoRecoveryAdmission({
    database: input.signerDatabase,
    capability,
    authority: session.authority,
    authMethod: session.authMethod,
    label: input.lifecycleId,
  });
  const exportProtocol = await localExportAdmission(capability);
  return {
    token: session.token,
    capability,
    warmBootstrap: requireParsed(
      parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
        kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
        walletId: capability.admissionRequest.application_binding.wallet_id,
        nearAccountId: capability.nearAccountId,
        nearEd25519SigningKeyId:
          capability.admissionRequest.application_binding.near_ed25519_signing_key_id,
        signerSlot: capability.admissionRequest.application_binding.key_creation_signer_slot,
        thresholdSessionId: capability.admissionRequest.scope.threshold_session_id,
        signingWorkerId: capability.admissionRequest.scope.signing_worker_id,
        participantIds: capability.admissionRequest.participant_ids,
      }),
    ),
    recoveryAdmission: recovery.admission,
    recoveryChallengeId: recovery.challengeId,
    exportProtocol,
    emailOtp: {
      providerSubjectId: EMAIL_PROVIDER_SUBJECT_ID,
      walletAuthMethodId: session.walletAuthMethodId,
    },
  };
}

export async function createLocalYaoEmailOtpExportAuthorization(input: {
  readonly env: LocalD1DevWorkerEnv;
  readonly signerDatabase: D1DatabaseLike;
  readonly token: string;
  readonly walletId: string;
  readonly providerSubjectId: string;
  readonly walletAuthMethodId: string;
}) {
  const response = await callLocalYaoWorker({
    env: input.env,
    path: '/wallet/email-otp/challenge',
    body: {
      walletId: input.walletId,
      walletAuthMethodId: input.walletAuthMethodId,
      otpChannel: 'email_otp',
      operation: 'export_key',
    },
    grant: input.token,
    origin: LOCAL_ORIGIN,
  });
  if (!response.ok) {
    throw new Error(`local Yao Email OTP export challenge failed: ${await response.text()}`);
  }
  const body = requireRecord(await response.json(), 'Email OTP export challenge response');
  const challenge = requireRecord(body.challenge, 'Email OTP export challenge');
  const challengeId = String(challenge.challengeId || '').trim();
  const walletAuthMethodId = String(body.walletAuthMethodId || '').trim();
  if (!challengeId || walletAuthMethodId !== input.walletAuthMethodId) {
    throw new Error('local Yao Email OTP export challenge identity changed');
  }
  const service = createCloudflareD1RouterApiAuthService({
    database: input.signerDatabase,
    namespace: NAMESPACE,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    accountIdDerivationSecret: 'local-yao-account-id-secret',
    emailOtpDeliveryMode: 'dev_d1_outbox',
    emailOtpDevOutboxEnabled: true,
    ecdsaStrictRegistration: new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort(),
  });
  const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
    challengeId,
    userId: input.providerSubjectId,
    walletId: input.walletId,
  });
  if (!outbox.ok) throw new Error(outbox.message);
  return {
    kind: 'email_otp_factor' as const,
    providerSubjectId: input.providerSubjectId,
    walletAuthMethodId,
    challengeId,
    otpCode: outbox.otpCode,
  };
}

export function recoveryExecuteFromAdmission(
  rawAdmissionReceipt: unknown,
  ciphertextSeed = 29,
): RecoveryExecuteRequest {
  const receipt = requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(rawAdmissionReceipt),
  );
  const parsed = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
    binding: receipt.binding,
    deriver_a_input: activationInput(receipt.binding, 'deriver_a', ciphertextSeed),
    deriver_b_input: activationInput(receipt.binding, 'deriver_b', ciphertextSeed + 1),
  });
  return requireParsed(parsed);
}

export function recoveryActivationFromExecution(rawExecutionResult: unknown) {
  const execution = requireRecord(rawExecutionResult, 'Recovery execution result');
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationRequestV1({
      binding: execution.binding,
      public_receipt: execution.public_receipt,
    }),
  );
}

export function exportExecuteFromAdmission(
  rawAdmissionReceipt: unknown,
  ciphertextSeed = 39,
): RouterAbEd25519YaoExportExecuteRequestV1 {
  const envelope = requireRecord(rawAdmissionReceipt, 'Export admission response');
  const receipt = requireParsed(
    parseRouterAbEd25519YaoExportAdmissionReceiptV1(envelope.protocol),
  );
  const binding = receipt.binding;
  return requireParsed(
    parseRouterAbEd25519YaoExportExecuteRequestV1({
      binding,
      deriver_a_input: exportInput(binding, 'deriver_a', ciphertextSeed),
      deriver_b_input: exportInput(binding, 'deriver_b', ciphertextSeed + 1),
    }),
  );
}

export function registrationExecuteFromAdmission(
  rawAdmissionReceipt: unknown,
  ciphertextSeed = 9,
): RegistrationExecuteRequest {
  const receipt =
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(rawAdmissionReceipt);
  if (!receipt.ok) throw new Error(receipt.message);
  const binding = receipt.value.binding;
  const execution = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
    binding,
    deriver_a_input: activationInput(binding, 'deriver_a', ciphertextSeed),
    deriver_b_input: activationInput(binding, 'deriver_b', ciphertextSeed + 1),
  });
  if (!execution.ok) throw new Error(execution.message);
  return execution.value;
}

export async function callLocalYaoWorker(input: {
  readonly env: LocalD1DevWorkerEnv;
  readonly path: string;
  readonly body: unknown;
  readonly grant: string;
  readonly origin?: string;
  readonly recoveryChallengeId?: string;
}): Promise<Response> {
  const headers = new Headers({
    authorization: `Bearer ${input.grant}`,
    'content-type': 'application/json',
  });
  if (input.origin) headers.set('origin', input.origin);
  if (input.recoveryChallengeId) {
    headers.set(
      ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1,
      input.recoveryChallengeId,
    );
  }
  return await localD1DevWorker.fetch(
    new Request(`http://127.0.0.1:8787/relay${input.path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(input.body),
    }),
    input.env,
    new LocalYaoExecutionContext(),
  );
}

export function localYaoOrigin(): string {
  return LOCAL_ORIGIN;
}

function registrationIntent(walletId: ReturnType<typeof walletIdFromString>): RegistrationIntentV1 {
  const rpId = parseWebAuthnRpId('wallet.local');
  const foundingWalletAuthMethodId = parseWalletAuthMethodId(
    'wallet-auth-method:local-yao-registration',
  );
  if (!rpId.ok || !foundingWalletAuthMethodId.ok) {
    throw new Error('local Yao registration auth identity is invalid');
  }
  return {
    version: 'registration_intent_v1',
    walletId,
    authMethod: { kind: 'passkey', rpId: rpId.value },
    foundingWalletAuthMethodId: foundingWalletAuthMethodId.value,
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    },
    nonceB64u: 'local-yao-registration-nonce',
  };
}

function activationInput(
  binding: RegistrationBinding | RecoveryBinding,
  deriver: 'deriver_a' | 'deriver_b',
  ciphertextSeed: number,
) {
  return {
    kind: 'activation',
    deriver,
    operation: binding.operation,
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(ciphertextSeed + 10),
    ciphertext: bytes(ciphertextSeed),
  };
}

function activationResult(binding: RegistrationBinding | RecoveryBinding) {
  const stateEpoch = binding.operation === 'registration' ? 1 : 2;
  return {
    binding,
    deriver_a_client_package: activationClientPackage(binding, 'deriver_a', 41),
    deriver_b_client_package: activationClientPackage(binding, 'deriver_b', 51),
    public_receipt: {
      transcript: bytes(61),
      registered_public_key: bytes(62),
      joined_client_commitment: bytes(63),
      joined_signing_worker_commitment: bytes(64),
      signing_worker_verifying_share: bytes(64),
      state_epoch: stateEpoch,
      material_activation: binding.material_activation,
    },
  };
}

async function buildLocalRegistrationCapability(): Promise<WalletEd25519YaoActiveCapabilityRecord> {
  const admissionRequest = requireParsed(
    parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
      scope: {
        lifecycle_id: 'registration-local-existing-wallet',
        root_share_epoch: ROOT_SHARE_EPOCH,
        account_id: localWalletId(),
        threshold_session_id: localWalletSessionId(),
        signer_set_id: 'ed25519:1',
        signing_worker_id: SIGNING_WORKER_ID,
        material_activation: localMaterialActivation('registration-local-existing-wallet'),
      },
      application_binding: {
        wallet_id: localWalletId(),
        near_ed25519_signing_key_id: localNearSigningKeyId(),
        signing_root_id: SIGNING_ROOT_ID,
        key_creation_signer_slot: 1,
      },
      participant_ids: [1, 2],
    }),
  );
  const binding: RegistrationBinding = {
    lifecycle: {
      lifecycle_id: admissionRequest.scope.lifecycle_id,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: admissionRequest.scope.root_share_epoch,
      account_id: admissionRequest.scope.account_id,
      session_id: admissionRequest.scope.threshold_session_id,
      signer_set_id: admissionRequest.scope.signer_set_id,
      selected_server_id: admissionRequest.scope.signing_worker_id,
    },
    operation: 'registration',
    session_id: bytes(20),
    stable_key_context_binding: await deriveRouterAbEd25519YaoStableContextBindingV1(
      admissionRequest.application_binding,
      admissionRequest.participant_ids,
    ),
    material_activation: admissionRequest.scope.material_activation,
  };
  const registrationResult = requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationResultV1(activationResult(binding)),
  );
  const registrationAdmissionReceipt = requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
      binding,
      keyset: {
        deriver_a_input_public_key: bytes(31),
        deriver_b_input_public_key: bytes(32),
        signing_worker_recipient_public_key: bytes(33),
      },
    }),
  );
  const built = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1({
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: bytes(20),
    nearAccountId: localNearAccountId(),
    registrationAdmissionRequest: admissionRequest,
    registrationAdmissionReceipt,
    registrationResult,
    runtimePolicyScope: localRuntimePolicyScope(),
  });
  if (!built.ok) throw new Error(built.message);
  return built.record;
}

async function persistLocalCapability(
  database: D1DatabaseLike,
  capability: WalletEd25519YaoActiveCapabilityRecord,
): Promise<void> {
  const walletId = parseWalletId(capability.admissionRequest.application_binding.wallet_id);
  if (!walletId.ok) throw new Error(walletId.error.message);
  const walletStore = new D1WalletStore({
    database,
    namespace: NAMESPACE,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    ensureSchema: false,
  });
  await walletStore.putSigner(
    buildYaoEd25519WalletSignerRecord({
      walletId: walletId.value,
      nearAccountId: capability.nearAccountId,
      nearEd25519SigningKeyId:
        capability.admissionRequest.application_binding.near_ed25519_signing_key_id,
      thresholdSessionId: capability.admissionRequest.scope.threshold_session_id,
      signerSlot: capability.admissionRequest.application_binding.key_creation_signer_slot,
      publicKey: ed25519NearPublicKeyFromBytes(
        capability.activationResult.public_receipt.registered_public_key,
      ),
      signingWorkerId: capability.admissionRequest.scope.signing_worker_id,
      keyVersion: 'router-ab-ed25519-yao-v1',
      participantIds: capability.admissionRequest.participant_ids,
      signingRootId: capability.admissionRequest.application_binding.signing_root_id,
      signingRootVersion: capability.admissionRequest.scope.root_share_epoch,
      runtimePolicyScope: capability.runtimePolicyScope,
      activeYaoCapability: capability,
      custodyKeyManifestDigestB64u: Buffer.alloc(32, 21).toString('base64url'),
      now: Date.now() - 10_000,
    }),
  );
}

async function issueLocalWalletSessionCredential(input: {
  readonly database: D1DatabaseLike;
  readonly capability: WalletEd25519YaoActiveCapabilityRecord;
}): Promise<{
  readonly token: string;
  readonly walletAuthMethodId: string;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveEmailOtpWalletAuthMethodRecordV2;
}> {
  const emailHashHex = await sha256HexUtf8(EMAIL_ADDRESS);
  const factorAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: localWalletId(),
    provider: 'google',
    providerUserId: EMAIL_PROVIDER_SUBJECT_ID,
    emailHashHex,
  });
  const walletKeyId = parseWalletKeyId('wallet-key:local-existing-yao');
  if (!walletKeyId.ok) throw new Error(walletKeyId.error.message);
  const registeredPublicKeyB64u = parseEd25519PublicKeyB64u(
    base64UrlEncode(
      Uint8Array.from(
        input.capability.activationResult.public_receipt.registered_public_key,
      ),
    ),
  );
  const records = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'local-existing-yao',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(
      input.capability.admissionRequest.scope.material_activation,
    ),
    ed25519Signer: {
      walletKeyId: walletKeyId.value,
      registeredPublicKeyB64u,
    },
    tenantId: ORG_ID,
    principalId: String(localWalletId()),
    expiresAtMs: Date.now() + 120_000,
    identity: {
      walletId: String(localWalletId()),
      authorityId: 'wallet-authority:local-existing-yao',
      walletAuthMethodId: String(factorAuthority.bindingId),
      rpId: 'wallet.local',
    },
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: records.authMethod.walletAuthMethodId,
    walletId: records.authMethod.walletId,
    walletAuthorityId: records.authMethod.walletAuthorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex,
    registrationAuthorityId: String(records.authority.authorityId),
    createdAtMs: records.authMethod.createdAtMs,
    updatedAtMs: records.authMethod.updatedAtMs,
    activatedAtMs: records.authMethod.activatedAtMs,
  });
  if (authMethod.kind !== 'email_otp' || authMethod.status !== 'active') {
    throw new Error('local Yao Email OTP auth method changed branch');
  }
  const scope = { namespace: NAMESPACE, orgId: ORG_ID, projectId: PROJECT_ID, envId: ENV_ID };
  await prepareD1WalletAuthorityPutStatement({
    database: input.database,
    scope,
    authority: records.authority,
  }).run();
  await new D1WalletAuthMethodStore({
    database: input.database,
    ...scope,
    ensureSchema: false,
  }).putV2(authMethod);
  await insertEmailOtpEnrollment({
    database: input.database,
    ...scope,
    walletId: String(localWalletId()),
    providerUserId: EMAIL_PROVIDER_SUBJECT_ID,
    verifiedEmail: EMAIL_ADDRESS,
  });

  const tenantId = parseTenantId(ORG_ID);
  const principalId = parsePrincipalId(String(localWalletId()));
  const mintId = parseWalletSessionMintId('mint:local-existing-yao');
  if (!tenantId.ok || !principalId.ok || !mintId.ok) {
    throw new Error('local Yao Wallet Session identity is invalid');
  }
  const authorizationStore = new CloudflareD1AuthorizationStore({
    database: input.database,
    namespace: NAMESPACE,
    walletSignerScope: scope,
  });
  const service = new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: authorizationStore,
    evidence: authorizationStore,
    grants: authorizationStore,
    authorizedOperations: authorizationStore,
    audit: authorizationStore,
  });
  const issuedAtMs = Date.now();
  const issued = await service.issueDirectWalletSessionAuthorizationV2({
    tenantId: tenantId.value,
    principalId: principalId.value,
    walletId: records.authority.walletId,
    authority: records.authority,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    mintId: mintId.value,
    remainingUses: 10,
    issuedAtMs,
    expiresAtMs: issuedAtMs + 120_000,
  });
  if (issued.kind !== 'issued') {
    throw new Error(`local Yao Wallet Session issuance failed: ${issued.kind}`);
  }
  const admission = resolveWalletSessionAuthorizationV2Admission({
    authorization: issued.session,
    authority: records.authority,
    authMethod,
    operation: {
      tenantId: tenantId.value,
      principalId: principalId.value,
      walletId: records.authority.walletId,
      keyFamily: 'ed25519',
      operationKind: 'near.sign_transaction',
    },
    retiredAtMs: null,
    nowMs: issuedAtMs,
  });
  if (!admission.ok) {
    throw new Error(`local Yao Wallet Session admission failed: ${admission.error}`);
  }
  return {
    token: issued.operationCredential.token,
    walletAuthMethodId: String(authMethod.walletAuthMethodId),
    authority: records.authority,
    authMethod,
  };
}

async function prepareLocalYaoRecoveryAdmission(input: {
  readonly database: D1DatabaseLike;
  readonly capability: WalletEd25519YaoActiveCapabilityRecord;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveEmailOtpWalletAuthMethodRecordV2;
  readonly label: string;
}): Promise<{
  readonly admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly challengeId: string;
}> {
  const nowMs = Date.now();
  const walletId = input.authority.walletId;
  const reservationId = parseRecoveryCodeReservationId(`recovery-reservation:${input.label}`);
  const initialRecoverySet = parseWalletRecoveryEnvelopeSetRecord(
    rawWalletRecoveryEnvelopeSet({ walletId: String(walletId) }),
    { expectedWalletId: walletId },
  );
  const selectedWrap = initialRecoverySet.manifestKekWraps[0];
  if (!selectedWrap || selectedWrap.lifecycle.state !== 'active') {
    throw new Error('local Yao recovery set has no active code');
  }
  const reservedWrap = buildWalletRecoveryManifestKekWrap({
    recoveryKeyId: selectedWrap.recoveryKeyId,
    nonceB64u: selectedWrap.nonceB64u,
    wrappedManifestKekB64u: selectedWrap.wrappedManifestKekB64u,
    aadHashB64u: selectedWrap.aadHashB64u,
    lifecycle: {
      state: 'reserved',
      issuedAtMs: selectedWrap.lifecycle.issuedAtMs,
      reservationId,
      reservedAtMs: nowMs,
      reservationExpiresAtMs: nowMs + 120_000,
    },
  });
  const recoverySet = buildWalletRecoveryEnvelopeSetRecord({
    walletId,
    manifestKekWraps: initialRecoverySet.manifestKekWraps.map((wrap, index) =>
      index === 0 ? reservedWrap : wrap,
    ),
    entries: initialRecoverySet.entries,
    issuedAtMs: initialRecoverySet.issuedAtMs,
    updatedAtMs: nowMs,
  });
  const envelope = passkeyCustodyEnvelope({
    envelopeId: `envelope:${input.label}`,
    walletId: String(walletId),
    binding: rawWalletCustodySeedBinding(),
    factor: rawEmailOtpFactor({ enrollmentId: 'local-yao-email-enrollment' }),
    ownership: {
      kind: 'method_bound',
      walletAuthMethodId: String(input.authMethod.walletAuthMethodId),
    },
    lifecycle: { state: 'active', activatedAtMs: nowMs },
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  });
  const scope = { namespace: NAMESPACE, orgId: ORG_ID, projectId: PROJECT_ID, envId: ENV_ID };
  const custodyStore = new CloudflareD1WalletCustodyCommitStore({
    database: input.database,
    scope,
  });
  const locators = rawWalletRecoveryCodeLocators();
  const committed = await custodyStore.commitRegistration({
    envelope,
    recoverySet,
    recoveryBackupAcknowledgement: buildWalletRecoveryBackupAcknowledgementV1({
      walletId: String(walletId),
      issuedAtMs: recoverySet.issuedAtMs,
      acknowledgedAtMs: nowMs,
    }),
    recoveryCodeLocators: recoverySet.manifestKekWraps.map((wrap, index) => {
      const locator = locators[index];
      if (!locator) throw new Error('local Yao recovery locator set is incomplete');
      return {
        locatorB64u: parseRecoveryCodeLocatorV1(locator.locatorB64u),
        walletId,
        recoveryKeyId: wrap.recoveryKeyId,
      };
    }),
  });
  if (committed.kind !== 'committed') {
    throw new Error(`local Yao recovery custody commit failed: ${committed.kind}`);
  }

  const walletStore = new D1WalletStore({
    database: input.database,
    ...scope,
    ensureSchema: false,
  });
  const manifest = await resolveWalletRecoveryKeyManifestV1({ registry: walletStore, walletId });
  const entry = manifest.entries.find((candidate) => candidate.kind === 'near_ed25519');
  if (!entry) throw new Error('local Yao recovery manifest has no Ed25519 key set');
  const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId,
    keySetId: entry.keySetId,
  });
  const basis = entry.recoveryBasis;
  const admission = requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: String(lifecycleId),
        root_share_epoch: basis.scope.root_share_epoch,
        account_id: basis.scope.account_id,
        threshold_session_id: `${lifecycleId}:threshold-session`,
        signer_set_id: basis.scope.signer_set_id,
        signing_worker_id: basis.scope.signing_worker_id,
        material_activation: localMaterialActivation(`${input.label}-replacement`),
      },
      active_material_activation: basis.activeMaterialActivation,
      application_binding: basis.applicationBinding,
      participant_ids: basis.participantIds,
      active_capability_binding: basis.activeCapabilityBinding,
      replacement_capability_binding: bytes(77),
      registered_public_key: basis.registeredPublicKey,
    }),
  );

  const challengeId = `recovery-challenge:${input.label}`;
  const recoveryOperationId = parseWalletRecoveryOperationId(
    `recovery-operation:${input.label}`,
  );
  const rpId = parseWebAuthnRpId('wallet.local');
  if (!recoveryOperationId.ok || !rpId.ok) {
    throw new Error('local Yao recovery challenge identity is invalid');
  }
  const challenge: WebAuthnRecoveryRegistrationChallengeRecord = {
    version: 'webauthn_recovery_registration_challenge_v2',
    challengeId,
    walletId,
    reservationId,
    recoveryOperationId: recoveryOperationId.value,
    targetDeviceId: input.authority.principal.deviceId,
    targetAuthorityId: input.authority.authorityId,
    targetWalletAuthMethodId: input.authMethod.walletAuthMethodId,
    origin: LOCAL_ORIGIN,
    rpId: rpId.value,
    replacementId: `replacement:${input.label}`,
    challengeB64u: base64UrlEncode(new Uint8Array(32).fill(71)),
    continuityAnchor: buildWebAuthnRecoveryContinuityAnchorRecord({
      authority: input.authority,
      method: input.authMethod,
      envelope,
    }),
    createdAtMs: nowMs,
    expiresAtMs: nowMs + 120_000,
  };
  await new CloudflareD1WebAuthnStore({ database: input.database, ...scope }).writeChallenge({
    challengeId,
    challengeKind: 'recovery_registration',
    record: challenge,
    createdAtMs: challenge.createdAtMs,
    expiresAtMs: challenge.expiresAtMs,
  });
  return { admission, challengeId };
}

async function localExportAdmission(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): Promise<RouterAbEd25519YaoExportAdmissionRequestV1> {
  const nowMs = Date.now();
  const identity = {
    scope: {
      lifecycle_id: capability.admissionRequest.scope.lifecycle_id,
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: localWalletId(),
      threshold_session_id: localWalletSessionId(),
      signer_set_id: 'ed25519:1',
      signing_worker_id: SIGNING_WORKER_ID,
      material_activation: capability.admissionRequest.scope.material_activation,
    },
    application_binding: capability.admissionRequest.application_binding,
    participant_ids: capability.admissionRequest.participant_ids,
    registered_public_key: capability.activationResult.public_receipt.registered_public_key,
    state_epoch: capability.activationResult.public_receipt.state_epoch,
    runtime_policy_binding:
      await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(localRuntimePolicyScope()),
  };
  const nonce = bytes(88);
  const issuedAtMs = nowMs - 1_000;
  const expiresAtMs = nowMs + 59_000;
  const confirmationDigest = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce,
    issuedAtMs,
    expiresAtMs,
  });
  const authorizationDigest = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
    identity,
    confirmationDigest,
    nonce,
    issuedAtMs,
    expiresAtMs,
    authority: { kind: 'email_otp', providerSubjectId: EMAIL_PROVIDER_SUBJECT_ID },
  });
  return requireParsed(
    parseRouterAbEd25519YaoExportAdmissionRequestV1({
      ...identity,
      authorization: {
        confirmation_digest: confirmationDigest,
        authorization_digest: authorizationDigest,
        nonce,
        issued_at_ms: issuedAtMs,
        expires_at_ms: expiresAtMs,
      },
    }),
  );
}

function exportInput(
  binding: RouterAbEd25519YaoExportBindingV1,
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
) {
  return {
    kind: 'export',
    deriver,
    operation: 'export',
    session: binding.ceremony.session_id,
    stable_context_binding: binding.ceremony.stable_key_context_binding,
    encapsulated_key: bytes(seed + 10),
    ciphertext: bytes(seed, 16),
  };
}

function exportSuccessResponse(request: RouterAbEd25519YaoExportExecuteRequestV1): Response {
  const transcript = bytes(91);
  return Response.json({
    status: 'succeeded',
    result: {
      operation: 'export',
      result: {
        binding: request.binding,
        transcript,
        deriver_a_client_package: exportClientPackage(request.binding, 'deriver_a', transcript, 92),
        deriver_b_client_package: exportClientPackage(request.binding, 'deriver_b', transcript, 94),
      },
    },
  });
}

function exportClientPackage(
  binding: RouterAbEd25519YaoExportBindingV1,
  deriver: 'deriver_a' | 'deriver_b',
  transcript: readonly number[],
  seed: number,
) {
  return {
    kind: 'export_client',
    deriver,
    session: binding.ceremony.session_id,
    transcript,
    encapsulated_key: bytes(seed),
    ciphertext: bytes(seed + 1, 16),
  };
}

function localRuntimePolicyScope() {
  return {
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    signingRootVersion: ROOT_SHARE_EPOCH,
  };
}

function localWalletId() {
  return walletIdFromString('wallet-local-existing-yao');
}

function localWalletSessionId(): string {
  return 'wallet-session-local-existing-yao';
}

function localNearSigningKeyId(): string {
  return 'ed25519ks_local_existing_yao';
}

function localNearAccountId(): string {
  return '0c'.repeat(32);
}

function requireParsed<T>(parsed: { ok: true; value: T } | { ok: false; message: string }): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function activationClientPackage(
  binding: RegistrationBinding | RecoveryBinding,
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
) {
  return {
    kind: 'activation_client',
    deriver,
    session: binding.session_id,
    transcript: bytes(61),
    encapsulated_key: bytes(seed),
    ciphertext: bytes(seed + 1),
  };
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}
