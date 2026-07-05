import { expect } from '@playwright/test';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash } from 'node:crypto';
import type { D1DatabaseLike } from '../../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse
} from '../../../packages/sdk-server-ts/src/core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload
} from '../../../packages/sdk-server-ts/src/core/registrationContracts';
import type { ThresholdSigningService } from '../../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords';
import { parseD1RegistrationIntent } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { buildD1ThresholdEd25519RegistrationSessionPolicy } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch';
import { base64UrlDecode, base64UrlEncode } from '../../../packages/shared-ts/src/utils/encoders';
import { parseWebAuthnRpId } from '../../../packages/shared-ts/src/utils/domainIds';
import { normalizeRuntimePolicyScope } from '../../../packages/shared-ts/src/threshold/signingRootScope';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import { buildPasskeyWalletAuthAuthority } from '../../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '../../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '../../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/cipher';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../../helpers/sqliteD1';

export type SqliteJsonRow = Record<string, unknown>;
export type TestEcdsaClientSharePublicKey =
  WalletRegistrationEcdsaClientBootstrap['hssClientSharePublicKey33B64u'];
export type TestEcdsaRelayerPublicKey =
  EcdsaHssServerBootstrapResponse['publicIdentity']['relayerPublicKey33B64u'];

export const EMAIL_OTP_SERVER_SEAL_KEY_VERSION = 'kek-s-email-otp-test';
export const EMAIL_OTP_SHAMIR_PRIME_B64U = encodePositiveBigIntB64u(257n);
export const EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(3n);
export const EMAIL_OTP_SERVER_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(171n);
export const EMAIL_OTP_CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
export const EMAIL_OTP_CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(205n);

export type WebAuthnAssertionFixture = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly privateKey: CryptoKey;
};

export const TEST_COMBINED_NEAR_ACCOUNT_ID =
  '0000000000000000000000000000000000000000000000000000000000000001';
export const TEST_ED25519_APPLICATION_BINDING_DIGEST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export function googleEmailOtpD1RegistrationAttemptBoundaryFixture(input: {
  readonly authProvider: string;
}): Record<string, unknown> {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: 'google-email-otp-boundary-attempt',
    providerSubject: 'google:boundary-user',
    email: 'boundary@example.test',
    walletId: 'wallet-google-email-otp-boundary',
    offerId: 'google-email-otp-boundary-offer',
    offerCandidates: [
      {
        candidateId: 'google-email-otp-boundary-candidate',
        walletId: 'wallet-google-email-otp-boundary',
        collisionCounter: 0,
      },
    ],
    selectedCandidateId: 'google-email-otp-boundary-candidate',
    appSessionVersion: 'app-session-google-email-otp-boundary',
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: 'google-email-otp-boundary-nonce',
    collisionCounter: 0,
    state: 'started',
    createdAtMs: 1_800_000_000_000,
    updatedAtMs: 1_800_000_000_100,
    expiresAtMs: 1_800_000_060_000,
    runtimePolicyScope: {
      orgId: 'org-google-email-otp-boundary',
      projectId: 'project-google-email-otp-boundary',
      envId: 'env-google-email-otp-boundary',
      signingRootVersion: 'root-google-email-otp-boundary',
    },
  };
}

export function testEd25519PreparedServerState() {
  return {
    context: {
      applicationBindingDigestB64u: TEST_ED25519_APPLICATION_BINDING_DIGEST_B64U,
      participantIds: [1, 2],
    },
    preparedServerSession: {
      evaluatorDriverStateB64u: 'AQ',
      garblerDriverStateB64u: 'Ag',
    },
    serverInputs: {
      yRelayerB64u: 'Aw',
      tauRelayerB64u: 'BA',
    },
  };
}

export function testEd25519RespondedServerState() {
  const prepared = testEd25519PreparedServerState();
  return {
    context: prepared.context,
    preparedServerSession: {
      ...prepared.preparedServerSession,
      serverEvalStateB64u: '',
    },
  };
}

export function testEvmFamilyRegistrationSignerSet() {
  return {
    kind: 'signer_set' as const,
    signers: [
      {
        kind: 'evm_family_ecdsa' as const,
        participantIds: [1, 2, 3],
        chainTargets: [{ kind: 'evm' as const, namespace: 'eip155', chainId: 8453 }],
      },
    ],
  };
}

export function testCombinedRegistrationSignerSet() {
  return {
    kind: 'signer_set' as const,
    signers: [
      {
        kind: 'near_ed25519' as const,
        accountProvisioning: implicitNearAccountProvisioning(),
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
      {
        kind: 'evm_family_ecdsa' as const,
        participantIds: [1, 2, 3],
        chainTargets: [{ kind: 'evm' as const, namespace: 'eip155', chainId: 8453 }],
      },
    ],
  };
}

export function requireParsedDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid test domain id');
  return result.value;
}

export class RecordingEmailOtpDeliveryProvider {
  readonly calls: CloudflareD1EmailOtpDeliveryProviderInput[] = [];

  constructor(private readonly result: CloudflareD1EmailOtpDeliveryProviderResult = { ok: true }) {}

  async deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    this.calls.push(input);
    return this.result;
  }
}

export class ThrowingDurableObjectStub implements CloudflareDurableObjectStubLike {
  async fetch(): Promise<Response> {
    throw new Error('Unexpected Durable Object fetch in threshold wiring test');
  }
}

export class ThrowingDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  private readonly stub = new ThrowingDurableObjectStub();

  idFromName(name: string): string {
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    return this.stub;
  }
}

export class RecordingDurableObjectStub implements CloudflareDurableObjectStubLike {
  readonly requests: Record<string, unknown>[] = [];
  readonly values = new Map<string, unknown>();

  async fetch(_input: RequestInfo, init?: RequestInit): Promise<Response> {
    const request = parseRecordingDurableObjectRequest(init?.body);
    this.requests.push(request);
    const op = String(request.op || '');
    if (op === 'set') return this.handleSet(request);
    if (op === 'get') return this.handleGet(request);
    if (op === 'getdel') return this.handleGetDel(request);
    if (op === 'del') return this.handleDel(request);
    if (op === 'authReserveReplayGuard') return this.handleReserveReplayGuard(request);
    if (op === 'registrationHssAdvanceClaimTransition') {
      return this.handleRegistrationHssAdvanceClaimTransition(request);
    }
    return recordingDurableObjectJson({
      ok: false,
      code: 'unsupported_op',
      message: `Unsupported op: ${op}`,
    });
  }

  private handleSet(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    this.values.set(key, request.value);
    return recordingDurableObjectJson({ ok: true, value: true });
  }

  private handleGet(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    return recordingDurableObjectJson({
      ok: true,
      value: this.values.get(key) ?? null,
    });
  }

  private handleGetDel(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    const value = this.values.get(key) ?? null;
    this.values.delete(key);
    return recordingDurableObjectJson({ ok: true, value });
  }

  private handleDel(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    return recordingDurableObjectJson({ ok: true, value: this.values.delete(key) });
  }

  private handleReserveReplayGuard(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    const expiresAtMs = Number(request.expiresAtMs);
    const existing = this.values.get(key);
    if (isActiveRecordingReplayGuard(existing)) {
      return recordingDurableObjectJson({
        ok: false,
        code: 'replay',
        message: 'Replay guard already reserved',
      });
    }
    this.values.set(key, { expiresAtMs });
    return recordingDurableObjectJson({ ok: true, value: { reserved: true } });
  }

  private handleRegistrationHssAdvanceClaimTransition(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    const transition = isSqliteJsonRow(request.transition) ? request.transition : {};
    const value = isSqliteJsonRow(request.value) ? request.value : {};
    if (!key) {
      return recordingDurableObjectJson({
        ok: false,
        code: 'invalid_body',
        message: 'Missing key',
      });
    }
    const kind = String(transition.kind || '').trim();
    if (kind === 'start') return this.handleRegistrationHssAdvanceClaimStart(key, value);
    if (kind === 'fulfill' || kind === 'fail') {
      return this.handleRegistrationHssAdvanceClaimComplete(key, transition, value, kind);
    }
    return recordingDurableObjectJson({
      ok: false,
      code: 'invalid_body',
      message: 'Invalid HSS advance claim transition',
    });
  }

  private handleRegistrationHssAdvanceClaimStart(
    key: string,
    value: Record<string, unknown>,
  ): Response {
    const existing = this.values.get(key);
    if (!isSqliteJsonRow(existing)) {
      this.values.set(key, value);
      return recordingDurableObjectJson({ ok: true, value: { status: 'started', record: value } });
    }
    const state = String(existing.state || '').trim();
    if (state === 'fulfilled') {
      return recordingDurableObjectJson({
        ok: true,
        value: { status: 'fulfilled', record: existing },
      });
    }
    if (state === 'in_flight') {
      return recordingDurableObjectJson({
        ok: true,
        value: { status: 'in_flight', record: existing },
      });
    }
    this.values.set(key, value);
    return recordingDurableObjectJson({ ok: true, value: { status: 'started', record: value } });
  }

  private handleRegistrationHssAdvanceClaimComplete(
    key: string,
    transition: Record<string, unknown>,
    value: Record<string, unknown>,
    state: 'fulfill' | 'fail',
  ): Response {
    const existing = this.values.get(key);
    if (!isSqliteJsonRow(existing)) {
      return recordingDurableObjectJson({ ok: true, value: { status: 'not_found' } });
    }
    if (String(existing.claimId || '').trim() !== String(transition.expectedClaimId || '').trim()) {
      return recordingDurableObjectJson({
        ok: true,
        value: { status: 'claim_mismatch', record: existing },
      });
    }
    this.values.set(key, value);
    return recordingDurableObjectJson({
      ok: true,
      value: { status: state === 'fulfill' ? 'fulfilled' : 'failed', record: value },
    });
  }
}

export class RecordingDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  readonly stub = new RecordingDurableObjectStub();
  readonly objectNames: string[] = [];

  idFromName(name: string): string {
    this.objectNames.push(name);
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    return this.stub;
  }
}

export function parseRecordingDurableObjectRequest(
  body: BodyInit | null | undefined,
): Record<string, unknown> {
  if (typeof body !== 'string') return {};
  const parsed: unknown = JSON.parse(body);
  return isSqliteJsonRow(parsed) ? parsed : {};
}

export function recordingDurableObjectJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

export function isActiveRecordingReplayGuard(value: unknown): boolean {
  if (!isSqliteJsonRow(value)) return false;
  return Number(value.expiresAtMs || 0) > Date.now();
}

export function isRecordingDurableObjectReplayReservationRequest(
  request: Record<string, unknown>,
): boolean {
  return String(request.op || '') === 'authReserveReplayGuard';
}

export function recordingDurableObjectRequestKey(request: Record<string, unknown>): string {
  return String(request.key || '').trim();
}

export function recordingDurableObjectRequestOp(request: Record<string, unknown>): string {
  return String(request.op || '').trim();
}

export function countRecordingDurableObjectRequests(input: {
  readonly requests: readonly Record<string, unknown>[];
  readonly op: string;
  readonly key: string;
}): number {
  let count = 0;
  for (const request of input.requests) {
    if (
      recordingDurableObjectRequestOp(request) === input.op &&
      recordingDurableObjectRequestKey(request) === input.key
    ) {
      count += 1;
    }
  }
  return count;
}

export function recordingDurableObjectRequestsIncludeKey(
  requests: readonly Record<string, unknown>[],
  key: string,
): boolean {
  for (const request of requests) {
    if (recordingDurableObjectRequestKey(request) === key) return true;
  }
  return false;
}

export function walletRegistrationDoKey(input: {
  readonly prefix: string;
  readonly scope: 'intent' | 'preparation' | 'ceremony';
  readonly id: string;
}): string {
  return `${input.prefix}:wallet-registration:${input.scope}:${input.id}`;
}

export function requireRecordingDurableObjectRecord(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly key: string;
}): Record<string, unknown> {
  const record = input.durableObjects.stub.values.get(input.key);
  if (!isSqliteJsonRow(record)) throw new Error(`Missing Durable Object record ${input.key}`);
  return record;
}

export function replaceRecordingDurableObjectRecord(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly key: string;
  readonly record: Record<string, unknown>;
}): void {
  input.durableObjects.stub.values.set(input.key, input.record);
}

export function recordingDurableObjectKeysWithPrefix(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly prefix: string;
}): string[] {
  const matches: string[] = [];
  for (const key of input.durableObjects.stub.values.keys()) {
    if (key.startsWith(input.prefix)) matches.push(key);
  }
  return matches;
}

export function requireNestedRecordingDurableObjectRecord(input: {
  readonly record: Record<string, unknown>;
  readonly field: string;
}): Record<string, unknown> {
  const nested = input.record[input.field];
  if (!isSqliteJsonRow(nested)) {
    throw new Error(`Durable Object record field ${input.field} is missing`);
  }
  return nested;
}

export function testEcdsaClientBootstrap(
  prepare: WalletRegistrationEcdsaPreparePayload['prepare'],
): WalletRegistrationEcdsaClientBootstrap {
  return {
    formatVersion: prepare.formatVersion,
    walletId: prepare.walletId,
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    keyScope: prepare.keyScope,
    relayerKeyId: prepare.relayerKeyId,
    ...(prepare.registrationPreparationId
      ? { registrationPreparationId: prepare.registrationPreparationId }
      : {}),
    hssClientSharePublicKey33B64u: 'test-client-share-public-key' as TestEcdsaClientSharePublicKey,
    clientShareRetryCounter: 0,
    contextBinding32B64u: 'test-context-binding-32',
    requestId: prepare.requestId,
    thresholdSessionId: prepare.thresholdSessionId,
    signingGrantId: prepare.signingGrantId,
    ttlMs: prepare.ttlMs,
    remainingUses: prepare.remainingUses,
    participantIds: prepare.participantIds,
    ...(prepare.runtimePolicyScope ? { runtimePolicyScope: prepare.runtimePolicyScope } : {}),
  };
}

export function requireSingleEcdsaPrepare(
  ecdsa: WalletRegistrationEcdsaPreparePayload,
): WalletRegistrationEcdsaPreparePayload['targets'][number]['prepare'] {
  expect(ecdsa.targets).toHaveLength(1);
  return ecdsa.targets[0].prepare;
}

export function testEcdsaClientBootstrapTargets(
  ecdsa: WalletRegistrationEcdsaPreparePayload,
): {
  chainTarget: WalletRegistrationEcdsaPreparePayload['targets'][number]['chainTarget'];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
}[] {
  return ecdsa.targets.map((target) => ({
    chainTarget: target.chainTarget,
    clientBootstrap: testEcdsaClientBootstrap(target.prepare),
  }));
}

export function testEcdsaServerBootstrapResponse(
  request: EcdsaHssClientBootstrapRequest,
): EcdsaHssServerBootstrapResponse {
  const expiresAtMs = Date.now() + 10 * 60_000;
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: request.walletId,
    evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
    relayerKeyId: request.relayerKeyId,
    applicationBindingDigestB64u: 'test-application-binding-digest',
    contextBinding32B64u: request.contextBinding32B64u,
    publicIdentity: {
      hssClientSharePublicKey33B64u: request.hssClientSharePublicKey33B64u,
      relayerPublicKey33B64u: 'test-relayer-public-key' as TestEcdsaRelayerPublicKey,
      groupPublicKey33B64u: 'test-group-public-key',
      ethereumAddress: '0x0000000000000000000000000000000000000001',
    },
    clientShareRetryCounter: request.clientShareRetryCounter,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: 'test-public-transcript-digest',
    keyHandle: 'test-add-signer-ecdsa-key-handle',
    signingRootId: request.signingRootId,
    signingRootVersion: request.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: 'test-group-public-key',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
    relayerVerifyingShareB64u: 'test-relayer-public-key',
    participantIds: request.participantIds,
    thresholdSessionId: request.sessionId,
    signingGrantId: request.signingGrantId,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: request.remainingUses,
  };
}

export async function testEd25519PrepareForRegistration() {
  return {
    ok: true as const,
    ceremonyHandle: 'ed25519-ceremony-handle',
    preparedSession: {
      contextBindingB64u: 'ed25519-context-binding',
      evaluatorDriverStateB64u: 'ed25519-evaluator-driver-state',
    },
    clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    serverState: testEd25519PreparedServerState(),
  };
}

export async function testEd25519RespondForRegistration() {
  return {
    ok: true as const,
    contextBindingB64u: 'ed25519-context-binding',
    serverInputDeliveryB64u: 'ed25519-server-input-delivery',
    serverState: testEd25519RespondedServerState(),
  };
}

export async function testEd25519AdvanceForRegistration(request: {
  readonly request: {
    readonly addStageRequestMessageB64u: string;
    readonly projectionMode: 'registration_seed_and_output' | 'registration_output_only';
  };
}) {
  return {
    ok: true as const,
    contextBindingB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
    advancedServerEvalStateB64u: base64UrlEncode(utf8Bytes('advanced-server-eval-state')),
    priorStageResponseMessageB64u: base64UrlEncode(utf8Bytes('prior-stage-response-message')),
    addStageRequestDigestB64u: base64UrlEncode(
      await sha256(base64UrlDecode(request.request.addStageRequestMessageB64u)),
    ),
    projectionMode: request.request.projectionMode,
  };
}

export async function testEd25519FinalizeForRegistration() {
  return {
    ok: true as const,
    publicKey: 'ed25519:combined-test-public-key',
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    relayerKeyId: 'combined-test-relayer-key',
    finalizedServerOutputMessageB64u: base64UrlEncode(utf8Bytes('finalized-server-output')),
    finalizedReport: {
      kind: 'threshold_ed25519_hss_finalized_report_v1',
      contextBindingB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
      clientOutputMessageB64u: base64UrlEncode(utf8Bytes('finalized-client-output')),
      seedOutputMessageB64u: base64UrlEncode(utf8Bytes('finalized-seed-output')),
    },
  };
}

export async function testEd25519RegistrationKeygenFromRegistrationMaterial() {
  return {
    ok: true as const,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    relayerKeyId: 'combined-test-relayer-key',
    publicKey: 'ed25519:combined-test-public-key',
    keyVersion: 'threshold-ed25519-hss-v1',
    recoveryExportCapable: true as const,
    relayerVerifyingShareB64u: 'combined-test-relayer-verifying-share',
  };
}

export async function testEcdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
  return {
    ok: true as const,
    value: testEcdsaServerBootstrapResponse(request),
  };
}

export function testGetCombinedRegistrationSchemeModule(schemeId: string) {
  if (schemeId !== 'threshold-ed25519-frost-2p-v1') return null;
  return {
    schemeId: 'threshold-ed25519-frost-2p-v1',
    protocol: {},
    healthz: testThresholdSchemeHealthz,
    session: testThresholdSchemeSession,
    registration: {
      keygenFromRegistrationMaterial: testEd25519RegistrationKeygenFromRegistrationMaterial,
    },
  };
}

export async function testThresholdSchemeHealthz() {
  return { ok: true };
}

export async function testThresholdSchemeSession() {
  return { ok: false as const, code: 'unsupported', message: 'not used by this test' };
}

export const testCombinedRegistrationThresholdSigningService = {
  ed25519Hss: {
    prepareForRegistration: testEd25519PrepareForRegistration,
    respondForRegistration: testEd25519RespondForRegistration,
    advanceForRegistration: testEd25519AdvanceForRegistration,
    finalizeForRegistration: testEd25519FinalizeForRegistration,
  },
  ecdsaHssRoleLocalBootstrap: testEcdsaHssRoleLocalBootstrap,
  getSchemeModule: testGetCombinedRegistrationSchemeModule,
} as unknown as ThresholdSigningService;

export function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function arrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

export function concatBytes(...inputs: readonly Uint8Array[]): Uint8Array {
  const length = inputs.reduce((total, item) => total + item.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const item of inputs) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

export function derIntegerBytes(input: Uint8Array): Uint8Array {
  const bytes = [...input];
  while (bytes.length > 1 && bytes[0] === 0 && ((bytes[1] || 0) & 0x80) === 0) bytes.shift();
  if (((bytes[0] || 0) & 0x80) !== 0) bytes.unshift(0);
  return new Uint8Array([0x02, bytes.length, ...bytes]);
}

export function rawP256SignatureToDer(input: Uint8Array): Uint8Array {
  if (input.length !== 64) throw new Error('Expected raw P-256 signature to be 64 bytes');
  const r = derIntegerBytes(input.slice(0, 32));
  const s = derIntegerBytes(input.slice(32));
  const body = concatBytes(r, s);
  if (body.length >= 128) throw new Error('Unexpected long-form DER signature length');
  return new Uint8Array([0x30, body.length, ...body]);
}

export async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBufferCopy(input)));
}

export function hexBytes(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export async function createWebAuthnAssertionFixture(): Promise<WebAuthnAssertionFixture> {
  const keyPair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  const x = base64UrlDecode(String(jwk.x || ''));
  const y = base64UrlDecode(String(jwk.y || ''));
  const cosePublicKey = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  );
  const credentialIdB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  return {
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(cosePublicKey),
    privateKey: keyPair.privateKey,
  };
}

export async function createWebAuthnAssertion(input: {
  readonly fixture: WebAuthnAssertionFixture;
  readonly rpId: string;
  readonly origin: string;
  readonly challengeB64u: string;
  readonly counter: number;
}): Promise<Record<string, unknown>> {
  const rpIdHash = await sha256(utf8Bytes(input.rpId));
  const flags = new Uint8Array([0x01]);
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, input.counter, false);
  const authenticatorData = concatBytes(rpIdHash, flags, counter);
  const clientDataJSON = utf8Bytes(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: input.challengeB64u,
      origin: input.origin,
      crossOrigin: false,
    }),
  );
  const signedBytes = concatBytes(authenticatorData, await sha256(clientDataJSON));
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      input.fixture.privateKey,
      arrayBufferCopy(signedBytes),
    ),
  );
  return {
    id: input.fixture.credentialIdB64u,
    rawId: input.fixture.credentialIdB64u,
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(rawP256SignatureToDer(rawSignature)),
      userHandle: null,
    },
    clientExtensionResults: {},
  };
}

export async function createWebAuthnRegistrationCredential(input: {
  readonly rpId: string;
  readonly origin: string;
  readonly challengeB64u: string;
}): Promise<Record<string, unknown>> {
  const fixture = await createWebAuthnAssertionFixture();
  const clientDataJSON = utf8Bytes(
    JSON.stringify({
      type: 'webauthn.create',
      challenge: input.challengeB64u,
      origin: input.origin,
      crossOrigin: false,
    }),
  );
  const rpIdHash = await sha256(utf8Bytes(input.rpId));
  const flags = new Uint8Array([0x41]);
  const counter = new Uint8Array(4);
  const aaguid = new Uint8Array(16);
  const credentialId = base64UrlDecode(fixture.credentialIdB64u);
  const credentialIdLength = new Uint8Array(2);
  new DataView(credentialIdLength.buffer).setUint16(0, credentialId.byteLength, false);
  const attestedCredentialData = concatBytes(
    aaguid,
    credentialIdLength,
    credentialId,
    base64UrlDecode(fixture.credentialPublicKeyB64u),
  );
  const authData = concatBytes(rpIdHash, flags, counter, attestedCredentialData);
  const attestationObject = isoCBOR.encode(
    new Map<string, string | Uint8Array | Map<never, never>>([
      ['fmt', 'none'],
      ['attStmt', new Map<never, never>()],
      ['authData', authData],
    ]),
  );
  return {
    id: fixture.credentialIdB64u,
    rawId: fixture.credentialIdB64u,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: base64UrlEncode(clientDataJSON),
      attestationObject: base64UrlEncode(attestationObject),
      transports: ['internal'],
    },
    clientExtensionResults: {},
  };
}

export function jsonBase64Url(input: Record<string, unknown>): string {
  return base64UrlEncode(utf8Bytes(JSON.stringify(input)));
}

export function fakeWebAuthnRegistrationCredential(input: {
  readonly challengeB64u: string;
  readonly origin: string;
  readonly type?: string;
}): Record<string, unknown> {
  return {
    id: 'fake-registration-credential',
    rawId: 'fake-registration-credential',
    type: 'public-key',
    response: {
      clientDataJSON: jsonBase64Url({
        type: input.type || 'webauthn.create',
        challenge: input.challengeB64u,
        origin: input.origin,
        crossOrigin: false,
      }),
    },
    clientExtensionResults: {},
  };
}

export function encodePositiveBigIntB64u(value: bigint): string {
  if (value <= 0n) throw new Error('value must be > 0');
  const bytesReversed: number[] = [];
  let cursor = value;
  while (cursor > 0n) {
    bytesReversed.push(Number(cursor & 255n));
    cursor >>= 8n;
  }
  bytesReversed.reverse();
  return base64UrlEncode(Uint8Array.from(bytesReversed));
}

export function addEmailOtpClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

export function removeEmailOtpClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.removeServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_CLIENT_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

export function addEmailOtpServerSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

export async function generateGoogleOidcTestKey(kid: string): Promise<{
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const exportedPublicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  return {
    kid,
    privateKey: keyPair.privateKey,
    publicJwk: Object.assign(exportedPublicJwk, {
      kid,
      use: 'sig',
      alg: 'RS256',
    }),
  };
}

export async function makeSignedGoogleIdToken(input: {
  readonly privateKey: CryptoKey;
  readonly kid: string;
  readonly payload: Record<string, unknown>;
}): Promise<string> {
  const headerB64u = jsonBase64Url({ alg: 'RS256', typ: 'JWT', kid: input.kid });
  const payloadB64u = jsonBase64Url(input.payload);
  const data = utf8Bytes(`${headerB64u}.${payloadB64u}`);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      input.privateKey,
      arrayBufferCopy(data),
    ),
  );
  return `${headerB64u}.${payloadB64u}.${base64UrlEncode(signature)}`;
}

export let googleJwksFetchMockPublicJwk: JsonWebKey | null = null;
export let oidcJwksFetchMockUrl = '';
export let oidcJwksFetchMockPublicJwk: JsonWebKey | null = null;

export async function googleJwksFetchMock(input: RequestInfo | URL): Promise<Response> {
  expect(String(input)).toBe('https://www.googleapis.com/oauth2/v3/certs');
  return new Response(JSON.stringify({ keys: [googleJwksFetchMockPublicJwk] }), {
    status: 200,
    headers: { 'cache-control': 'public, max-age=300' },
  });
}

export function installGoogleJwksFetchMock(publicJwk: JsonWebKey): typeof globalThis.fetch {
  const originalFetch = globalThis.fetch;
  googleJwksFetchMockPublicJwk = publicJwk;
  globalThis.fetch = googleJwksFetchMock;
  return originalFetch;
}

export function restoreGoogleJwksFetchMock(originalFetch: typeof globalThis.fetch): void {
  globalThis.fetch = originalFetch;
  googleJwksFetchMockPublicJwk = null;
}

export async function oidcJwksFetchMock(input: RequestInfo | URL): Promise<Response> {
  expect(String(input)).toBe(oidcJwksFetchMockUrl);
  return new Response(JSON.stringify({ keys: [oidcJwksFetchMockPublicJwk] }), {
    status: 200,
    headers: { 'cache-control': 'public, max-age=300' },
  });
}

export function installOidcJwksFetchMock(input: {
  readonly jwksUrl: string;
  readonly publicJwk: JsonWebKey;
}): typeof globalThis.fetch {
  const originalFetch = globalThis.fetch;
  oidcJwksFetchMockUrl = input.jwksUrl;
  oidcJwksFetchMockPublicJwk = input.publicJwk;
  globalThis.fetch = oidcJwksFetchMock;
  return originalFetch;
}

export function restoreOidcJwksFetchMock(originalFetch: typeof globalThis.fetch): void {
  globalThis.fetch = originalFetch;
  oidcJwksFetchMockUrl = '';
  oidcJwksFetchMockPublicJwk = null;
}

export function applySignerMigrations(database: D1DatabaseLike): Promise<void> {
  return applyD1MigrationFiles(database, listD1MigrationFiles('d1-signer'));
}

export function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

export function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

export async function insertIdentity(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
  readonly subject: string;
}): Promise<void> {
  await input.database
    .prepare(
      `INSERT INTO identity_links (
        namespace, org_id, project_id, env_id, subject, user_id, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.subject,
      input.userId,
      JSON.stringify({
        version: 'identity_subject_v1',
        subject: input.subject,
        userId: input.userId,
        createdAtMs: 100,
        updatedAtMs: 100,
      }),
      100,
      100,
    )
    .run();
}

export async function insertWebAuthn(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
  readonly rpId?: string;
  readonly credentialIdB64u?: string;
  readonly credentialPublicKeyB64u?: string;
  readonly counter?: number;
  readonly signerSlot?: number;
}): Promise<void> {
  const rpId = input.rpId || 'example.com';
  const credentialIdB64u = input.credentialIdB64u || 'credential-a';
  const credentialPublicKeyB64u = input.credentialPublicKeyB64u || 'credential-public-key-a';
  const counter = input.counter ?? 0;
  const signerSlot = input.signerSlot ?? 2;
  await input.database
    .prepare(
      `INSERT INTO webauthn_authenticators (
        namespace, org_id, project_id, env_id, user_id, credential_id_b64u,
        credential_public_key_b64u, counter, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      credentialIdB64u,
      credentialPublicKeyB64u,
      counter,
      200,
      300,
    )
    .run();
  await input.database
    .prepare(
      `INSERT INTO webauthn_credential_bindings (
        namespace, org_id, project_id, env_id, rp_id, credential_id_b64u, user_id,
        signer_slot, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      rpId,
      credentialIdB64u,
      input.userId,
      signerSlot,
      JSON.stringify({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: input.userId,
        nearAccountId: 'near.testnet',
        nearEd25519SigningKeyId: 'ed25519:key',
        signerSlot,
        publicKey: 'ed25519:public',
        createdAtMs: 150,
        updatedAtMs: 250,
      }),
      150,
      250,
    )
    .run();
}

export async function readWebAuthnChallengeRow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly challengeId: string;
}): Promise<SqliteJsonRow | null> {
  return await input.database
    .prepare(
      `SELECT challenge_kind, record_json, created_at_ms, expires_at_ms
         FROM webauthn_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, input.challengeId)
    .first<SqliteJsonRow>();
}

export async function readWebAuthnAuthenticatorRow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
  readonly credentialIdB64u: string;
}): Promise<SqliteJsonRow | null> {
  return await input.database
    .prepare(
      `SELECT credential_public_key_b64u, counter, updated_at_ms
         FROM webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
          AND credential_id_b64u = ?
        LIMIT 1`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      input.credentialIdB64u,
    )
    .first<SqliteJsonRow>();
}

export async function insertNearPublicKey(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
}): Promise<void> {
  const record = {
    version: 'near_public_key_v1',
    userId: input.userId,
    publicKey: 'ed25519:near-public',
    kind: 'threshold',
    signerSlot: 1,
    authBinding: {
      kind: 'passkey',
      credentialIdB64u: 'credential-a',
      rpId: 'example.com',
    },
    createdAtMs: 400,
    updatedAtMs: 500,
  };
  await input.database
    .prepare(
      `INSERT INTO near_public_keys (
        namespace, org_id, project_id, env_id, user_id, public_key, kind, signer_slot,
        record_json, created_at_ms, updated_at_ms, removed_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      record.publicKey,
      record.kind,
      record.signerSlot,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
      null,
    )
    .run();
}

export async function insertSignerWallet(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
}): Promise<void> {
  const nowMs = Date.now();
  const record = {
    version: 'wallet_v1',
    walletId: input.walletId,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
  await input.database
    .prepare(
      `INSERT INTO wallets (
        namespace, org_id, project_id, env_id, wallet_id, record_json,
        created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

export type TestWalletAuthMethodRecord =
  | {
      readonly version: 'wallet_auth_method_v1';
      readonly kind: 'passkey';
      readonly status: 'active' | 'revoked';
      readonly walletId: string;
      readonly rpId: string;
      readonly credentialIdB64u: string;
      readonly credentialPublicKeyB64u: string;
      readonly counter: number;
      readonly createdAtMs: number;
      readonly updatedAtMs: number;
      readonly emailHashHex?: never;
      readonly registrationAuthorityId?: never;
    }
  | {
      readonly version: 'wallet_auth_method_v1';
      readonly kind: 'email_otp';
      readonly status: 'active' | 'revoked';
      readonly walletId: string;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly createdAtMs: number;
      readonly updatedAtMs: number;
      readonly rpId?: never;
      readonly credentialIdB64u?: never;
      readonly credentialPublicKeyB64u?: never;
      readonly counter?: never;
    };

export type TestWalletAuthMethodIdentity = {
  readonly walletAuthMethodId: string;
  readonly rpId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
};

export function testWalletAuthMethodIdentity(
  record: TestWalletAuthMethodRecord,
): TestWalletAuthMethodIdentity {
  switch (record.kind) {
    case 'passkey':
      return {
        walletAuthMethodId: `passkey:${record.rpId}:${record.credentialIdB64u}`,
        rpId: record.rpId,
        authIdentifierKey: record.credentialIdB64u,
        credentialIdB64u: record.credentialIdB64u,
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        emailHashHex: null,
        registrationAuthorityId: null,
      };
    case 'email_otp':
      return {
        walletAuthMethodId: `email_otp:${record.walletId}:${record.emailHashHex}`,
        rpId: '',
        authIdentifierKey: record.emailHashHex,
        credentialIdB64u: null,
        credentialPublicKeyB64u: null,
        emailHashHex: record.emailHashHex,
        registrationAuthorityId: record.registrationAuthorityId,
      };
  }
}

export async function insertWalletAuthMethod(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly record: TestWalletAuthMethodRecord;
}): Promise<void> {
  const identity = testWalletAuthMethodIdentity(input.record);
  await input.database
    .prepare(
      `INSERT INTO wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        rp_id,
        kind,
        status,
        wallet_auth_method_id,
        auth_identifier_key,
        credential_id_b64u,
        credential_public_key_b64u,
        email_hash_hex,
        registration_authority_id,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.record.walletId,
      identity.rpId,
      input.record.kind,
      input.record.status,
      identity.walletAuthMethodId,
      identity.authIdentifierKey,
      identity.credentialIdB64u,
      identity.credentialPublicKeyB64u,
      identity.emailHashHex,
      identity.registrationAuthorityId,
      JSON.stringify(input.record),
      input.record.createdAtMs,
      input.record.updatedAtMs,
    )
    .run();
}

export async function readWalletAuthMethodRecord(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletAuthMethodId: string;
}): Promise<SqliteJsonRow> {
  const row = await input.database
    .prepare(
      `SELECT record_json
         FROM wallet_auth_methods
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_auth_method_id = ?
        LIMIT 1`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, input.walletAuthMethodId)
    .first<SqliteJsonRow>();
  const raw = row?.record_json;
  if (typeof raw !== 'string') throw new Error('wallet auth method record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('wallet auth method record_json invalid');
  return parsed;
}

export async function readSignerWalletRecord(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
}): Promise<SqliteJsonRow> {
  const row = await input.database
    .prepare(
      `SELECT record_json
         FROM wallets
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, input.walletId)
    .first<SqliteJsonRow>();
  const raw = row?.record_json;
  if (typeof raw !== 'string') throw new Error('signer wallet record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('signer wallet record_json invalid');
  return parsed;
}

export async function readWalletSignerRecord(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
  readonly signerFamily: 'ed25519' | 'ecdsa';
  readonly signerId: string;
}): Promise<SqliteJsonRow> {
  const row = await input.database
    .prepare(
      `SELECT record_json
         FROM wallet_signers
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND signer_family = ?
          AND signer_id = ?
        LIMIT 1`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.walletId,
      input.signerFamily,
      input.signerId,
    )
    .first<SqliteJsonRow>();
  const raw = row?.record_json;
  if (typeof raw !== 'string') throw new Error('wallet signer record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('wallet signer record_json invalid');
  return parsed;
}

export async function insertEmailOtpEnrollment(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId?: string;
  readonly providerUserId?: string;
  readonly verifiedEmail?: string;
  readonly clientUnlockPublicKeyB64u?: string;
}): Promise<void> {
  const record = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: input.walletId || 'email-wallet.testnet',
    providerUserId: input.providerUserId || 'google:email-user',
    orgId: input.orgId,
    verifiedEmail: input.verifiedEmail || 'alice@example.test',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryWrappedEnrollmentEscrowCount: 3,
    clientUnlockPublicKeyB64u: input.clientUnlockPublicKeyB64u || 'client-unlock-public-key',
    unlockKeyVersion: 'unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-verifying-share',
    createdAtMs: 600,
    updatedAtMs: 700,
  };
  await input.database
    .prepare(
      `INSERT INTO email_otp_wallet_enrollments (
        namespace, org_id, project_id, env_id, wallet_id, provider_user_id, record_org_id,
        verified_email, record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.providerUserId,
      record.orgId,
      record.verifiedEmail,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

export async function listGoogleEmailOtpRegistrationAttemptRows(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<SqliteJsonRow[]> {
  const result = await input.database
    .prepare(
      `SELECT attempt_id, state, app_session_version, runtime_org_id, runtime_policy_key,
              offer_wallet_ids_json, record_json
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
        ORDER BY created_at_ms ASC, attempt_id ASC`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId)
    .all<SqliteJsonRow>();
  return [...(result.results || [])];
}

export function registrationAttemptRecordFromRow(row: SqliteJsonRow): Record<string, unknown> {
  const raw = row.record_json;
  if (typeof raw !== 'string') throw new Error('registration attempt record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('registration attempt record_json invalid');
  return parsed;
}

export async function insertEmailOtpAuthState(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<void> {
  const record = {
    version: 'email_otp_auth_state_v1',
    walletId: 'email-wallet.testnet',
    providerUserId: 'google:email-user',
    orgId: input.orgId,
    createdAtMs: 750,
    updatedAtMs: 800,
    lastEmailOtpLoginAtMs: 800,
  };
  await input.database
    .prepare(
      `INSERT INTO email_otp_auth_states (
        namespace, org_id, project_id, env_id, wallet_id, provider_user_id, record_org_id,
        record_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.providerUserId,
      record.orgId,
      JSON.stringify(record),
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

export async function insertEmailOtpRecoveryEscrow(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
}): Promise<void> {
  const record = emailOtpRecoveryEscrowRecord(input);
  await input.database
    .prepare(
      `INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
        namespace, org_id, project_id, env_id, wallet_id, recovery_key_id, recovery_key_status,
        record_json, issued_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.walletId,
      record.recoveryKeyId,
      record.recoveryKeyStatus,
      JSON.stringify(record),
      record.issuedAtMs,
      record.updatedAtMs,
    )
    .run();
}

export async function insertEmailOtpGrant(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly grantToken: string;
  readonly appSessionVersion: string;
}): Promise<void> {
  const record = emailOtpGrantRecord(input);
  await input.database
    .prepare(
      `INSERT INTO email_otp_grants (
        namespace, org_id, project_id, env_id, grant_token, user_id, wallet_id, record_org_id,
        challenge_id, action, record_json, issued_at_ms, expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.grantToken,
      record.userId,
      record.walletId,
      record.orgId,
      record.challengeId,
      record.action,
      JSON.stringify(record),
      record.issuedAtMs,
      record.expiresAtMs,
    )
    .run();
}

export function emailOtpGrantRecord(input: {
  readonly orgId: string;
  readonly grantToken: string;
  readonly appSessionVersion: string;
}) {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: 'google:email-user',
    walletId: 'email-wallet.testnet',
    orgId: input.orgId,
    challengeId: `challenge-${input.grantToken}`,
    otpChannel: 'email_otp',
    sessionHash: 'session-hash-a',
    appSessionVersion: input.appSessionVersion,
    action: 'wallet_email_otp_unseal',
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: Date.now() + 60_000,
  };
}

export function emailOtpRecoveryEscrowRecord(input: {
  readonly orgId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
}) {
  return {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: 'chacha20poly1305-hkdf-sha256-v1',
    secretKind: 'email_otp_device_enrollment_escrow',
    escrowKind: 'recovery_wrapped_enrollment_escrow',
    walletId: 'email-wallet.testnet',
    userId: 'google:email-user',
    authSubjectId: 'google:email-user',
    authMethod: 'google_sso_email_otp',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryKeyId: input.recoveryKeyId,
    recoveryKeyStatus: input.recoveryKeyStatus,
    nonceB64u: `nonce-${input.recoveryKeyId}`,
    wrappedDeviceEnrollmentEscrowB64u: `wrapped-${input.recoveryKeyId}`,
    aadHashB64u: `aad-${input.recoveryKeyId}`,
    issuedAtMs: input.issuedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(input.recoveryKeyStatus === 'consumed' ? { consumedAtMs: input.updatedAtMs } : {}),
    ...(input.recoveryKeyStatus === 'revoked' ? { revokedAtMs: input.updatedAtMs } : {}),
  };
}

export type RecoveryRotationEscrowInput = {
  readonly recoveryKeyId: string;
  readonly nonceB64u: string;
  readonly wrappedDeviceEnrollmentEscrowB64u: string;
  readonly aadHashB64u: string;
};

export type RecoveryWrappedEnrollmentEscrowInput = {
  readonly version: 'email_otp_recovery_wrapped_enrollment_escrow_v1';
  readonly alg: typeof EMAIL_OTP_RECOVERY_WRAP_ALG;
  readonly secretKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND;
  readonly escrowKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND;
  readonly walletId: string;
  readonly userId: string;
  readonly authSubjectId: string;
  readonly authMethod: 'google_sso_email_otp';
  readonly enrollmentId: string;
  readonly enrollmentVersion: string;
  readonly enrollmentSealKeyVersion: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active';
  readonly nonceB64u: string;
  readonly wrappedDeviceEnrollmentEscrowB64u: string;
  readonly aadHashB64u: string;
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
};

export function makeRecoveryRotationEscrowInputs(): RecoveryRotationEscrowInput[] {
  const inputs: RecoveryRotationEscrowInput[] = [];
  for (let index = 1; index <= 10; index += 1) {
    inputs.push(recoveryRotationEscrowInput(index));
  }
  return inputs;
}

export function recoveryRotationEscrowInput(index: number): RecoveryRotationEscrowInput {
  const recoveryKeyId = `rotated-recovery-${index}`;
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: 'email-wallet.testnet',
    userId: 'google:email-user',
    authSubjectId: 'google:email-user',
    authMethod: 'google_sso_email_otp',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    recoveryKeyId,
  });
  return {
    recoveryKeyId,
    nonceB64u: base64UrlEncode(new Uint8Array(12).fill(index)),
    wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(new Uint8Array(32).fill(index + 10)),
    aadHashB64u: base64UrlEncode(
      createHash('sha256').update(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)).digest(),
    ),
  };
}

export function makeRecoveryWrappedEnrollmentEscrows(input: {
  readonly walletId: string;
  readonly userId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly enrollmentVersion?: string;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly issuedAtMs?: number;
}): RecoveryWrappedEnrollmentEscrowInput[] {
  const enrollmentVersion = input.enrollmentVersion || 'enrollment-v1';
  const signingRootId = input.signingRootId || 'project-a:env-a';
  const signingRootVersion = input.signingRootVersion || 'root-v1';
  const issuedAtMs = input.issuedAtMs || Date.now();
  const records: RecoveryWrappedEnrollmentEscrowInput[] = [];
  for (let index = 1; index <= EMAIL_OTP_RECOVERY_KEY_COUNT; index += 1) {
    records.push(
      recoveryWrappedEnrollmentEscrowInput({
        index,
        walletId: input.walletId,
        userId: input.userId,
        enrollmentId: input.enrollmentId,
        enrollmentVersion,
        enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
        signingRootId,
        signingRootVersion,
        issuedAtMs,
      }),
    );
  }
  return records;
}

export function recoveryWrappedEnrollmentEscrowInput(input: {
  readonly index: number;
  readonly walletId: string;
  readonly userId: string;
  readonly enrollmentId: string;
  readonly enrollmentVersion: string;
  readonly enrollmentSealKeyVersion: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly issuedAtMs: number;
}): RecoveryWrappedEnrollmentEscrowInput {
  const recoveryKeyId = `enrollment-recovery-${input.index}`;
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: input.walletId,
    userId: input.userId,
    authSubjectId: input.userId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: input.enrollmentId,
    enrollmentVersion: input.enrollmentVersion,
    enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    recoveryKeyId,
  });
  return {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId: input.walletId,
    userId: input.userId,
    authSubjectId: input.userId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: input.enrollmentId,
    enrollmentVersion: input.enrollmentVersion,
    enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    recoveryKeyId,
    recoveryKeyStatus: 'active',
    nonceB64u: base64UrlEncode(new Uint8Array(12).fill(input.index)),
    wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(new Uint8Array(48).fill(input.index + 20)),
    aadHashB64u: recoveryEscrowAadHashB64u(binding),
    issuedAtMs: input.issuedAtMs,
    updatedAtMs: input.issuedAtMs,
  };
}

export function recoveryEscrowAadHashB64u(
  binding: ReturnType<typeof buildEmailOtpRecoveryWrapBinding>,
): string {
  return base64UrlEncode(
    createHash('sha256').update(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)).digest(),
  );
}

export async function readRecoveryEscrowStatusCounts(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
}): Promise<Record<string, number>> {
  const result = await input.database
    .prepare(
      `SELECT recovery_key_status, COUNT(*) AS count
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        GROUP BY recovery_key_status`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, 'email-wallet.testnet')
    .all<SqliteJsonRow>();
  const counts: Record<string, number> = {};
  for (const row of result.results || []) {
    const status = String(row.recovery_key_status || '').trim();
    if (status) counts[status] = toInteger(row.count);
  }
  return counts;
}

export async function countActiveRecoveryWrappedEnrollmentEscrows(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
}): Promise<number> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS active_count
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_status = 'active'`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, input.walletId)
    .first<SqliteJsonRow>();
  return toInteger(row?.active_count);
}

export async function insertRecoverySession(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly sessionId: string;
  readonly status?: 'prepared' | 'verified' | 'near_recovered' | 'failed';
  readonly metadata?: Record<string, unknown>;
}): Promise<void> {
  const record = recoverySessionRecord(input);
  await input.database
    .prepare(
      `INSERT INTO recovery_sessions (
        namespace, org_id, project_id, env_id, session_id, near_account_id, record_json,
        expires_at_ms, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      record.sessionId,
      record.nearAccountId,
      JSON.stringify(record),
      record.expiresAtMs,
      record.createdAtMs,
      record.updatedAtMs,
    )
    .run();
}

export function recoverySessionRecord(input: {
  readonly sessionId: string;
  readonly status?: 'prepared' | 'verified' | 'near_recovered' | 'failed';
  readonly metadata?: Record<string, unknown>;
}) {
  return {
    version: 'recovery_session_v1',
    sessionId: input.sessionId,
    userId: 'recovery-user',
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    status: input.status || 'prepared',
    createdAtMs: 1_000,
    updatedAtMs: 1_100,
    expiresAtMs: Date.now() + 60_000,
    newNearPublicKey: 'ed25519:new-public-key',
    newEvmOwnerAddress: '0x00000000000000000000000000000000000000aa',
    recoveryDeadlineEpochSeconds: Math.floor(Date.now() / 1_000) + 3_600,
    recoveryEmailPayloadHash: 'recovery-payload-hash',
    ...(input.metadata ? { metadata: input.metadata } : {}),
  };
}
