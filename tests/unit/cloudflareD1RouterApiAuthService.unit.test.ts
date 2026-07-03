import { expect, test } from '@playwright/test';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash } from 'node:crypto';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload
} from '../../packages/sdk-server-ts/src/core/registrationContracts';
import type { ThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { buildD1ThresholdEd25519RegistrationSessionPolicy } from '../../packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { normalizeRuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/cipher';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type SqliteJsonRow = Record<string, unknown>;
type TestEcdsaClientSharePublicKey =
  WalletRegistrationEcdsaClientBootstrap['hssClientSharePublicKey33B64u'];
type TestEcdsaRelayerPublicKey =
  EcdsaHssServerBootstrapResponse['publicIdentity']['relayerPublicKey33B64u'];

const EMAIL_OTP_SERVER_SEAL_KEY_VERSION = 'kek-s-email-otp-test';
const EMAIL_OTP_SHAMIR_PRIME_B64U = encodePositiveBigIntB64u(257n);
const EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(3n);
const EMAIL_OTP_SERVER_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(171n);
const EMAIL_OTP_CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
const EMAIL_OTP_CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(205n);

type WebAuthnAssertionFixture = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly privateKey: CryptoKey;
};

const TEST_COMBINED_NEAR_ACCOUNT_ID =
  '0000000000000000000000000000000000000000000000000000000000000001';
const TEST_ED25519_APPLICATION_BINDING_DIGEST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function googleEmailOtpD1RegistrationAttemptBoundaryFixture(input: {
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

function testEd25519PreparedServerState() {
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

function testEd25519RespondedServerState() {
  const prepared = testEd25519PreparedServerState();
  return {
    context: prepared.context,
    preparedServerSession: {
      ...prepared.preparedServerSession,
      serverEvalStateB64u: '',
    },
  };
}

function testEvmFamilyRegistrationSignerSet() {
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

function testCombinedRegistrationSignerSet() {
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

function requireParsedDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid test domain id');
  return result.value;
}

test('D1 Ed25519 registration session policy requires bound passkey authority', () => {
  const rpId = requireParsedDomainId(parseWebAuthnRpId('localhost'));
  const walletId = 'jade-orchid-2caqh9';
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: 'cred-d1-passkey',
  });
  const built = buildD1ThresholdEd25519RegistrationSessionPolicy({
    requestedSessionPolicy: {
      version: 'threshold_session_v1',
      authority,
      thresholdSessionId: 'tsess-d1-passkey',
      signingGrantId: 'wss-d1-passkey',
      participantIds: [1, 2],
      ttlMs: 600_000,
      remainingUses: 3,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'local-signing-worker',
      },
    },
    walletId,
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: 'near-ed25519-signing-key-id',
    relayerKeyId: 'ed25519:relayer',
    authority,
  });
  expect(built.ok).toBe(true);
  if (!built.ok) throw new Error(built.message);
  expect(built.value.authority).toEqual(authority);
  expect(Object.prototype.hasOwnProperty.call(built.value, 'rpId')).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(built.value, 'authorityScope')).toBe(false);
});

test('D1 Ed25519 registration session policy rejects root passkey RP ID', () => {
  const rpId = requireParsedDomainId(parseWebAuthnRpId('localhost'));
  const walletId = 'jade-orchid-2caqh9';
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: 'cred-d1-passkey',
  });
  const built = buildD1ThresholdEd25519RegistrationSessionPolicy({
    requestedSessionPolicy: {
      version: 'threshold_session_v1',
      authority,
      rpId: 'localhost',
      thresholdSessionId: 'tsess-d1-passkey',
      signingGrantId: 'wss-d1-passkey',
      ttlMs: 600_000,
      remainingUses: 3,
    },
    walletId,
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: 'near-ed25519-signing-key-id',
    relayerKeyId: 'ed25519:relayer',
    authority,
  });
  expect(built).toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'threshold_ed25519.session_policy.rpId belongs in authority',
  });
});

class RecordingEmailOtpDeliveryProvider {
  readonly calls: CloudflareD1EmailOtpDeliveryProviderInput[] = [];

  constructor(private readonly result: CloudflareD1EmailOtpDeliveryProviderResult = { ok: true }) {}

  async deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    this.calls.push(input);
    return this.result;
  }
}

class ThrowingDurableObjectStub implements CloudflareDurableObjectStubLike {
  async fetch(): Promise<Response> {
    throw new Error('Unexpected Durable Object fetch in threshold wiring test');
  }
}

class ThrowingDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  private readonly stub = new ThrowingDurableObjectStub();

  idFromName(name: string): string {
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    return this.stub;
  }
}

class RecordingDurableObjectStub implements CloudflareDurableObjectStubLike {
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
}

class RecordingDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
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

function parseRecordingDurableObjectRequest(
  body: BodyInit | null | undefined,
): Record<string, unknown> {
  if (typeof body !== 'string') return {};
  const parsed: unknown = JSON.parse(body);
  return isSqliteJsonRow(parsed) ? parsed : {};
}

function recordingDurableObjectJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function isActiveRecordingReplayGuard(value: unknown): boolean {
  if (!isSqliteJsonRow(value)) return false;
  return Number(value.expiresAtMs || 0) > Date.now();
}

function isRecordingDurableObjectReplayReservationRequest(
  request: Record<string, unknown>,
): boolean {
  return String(request.op || '') === 'authReserveReplayGuard';
}

function recordingDurableObjectRequestKey(request: Record<string, unknown>): string {
  return String(request.key || '').trim();
}

function recordingDurableObjectRequestOp(request: Record<string, unknown>): string {
  return String(request.op || '').trim();
}

function countRecordingDurableObjectRequests(input: {
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

function recordingDurableObjectRequestsIncludeKey(
  requests: readonly Record<string, unknown>[],
  key: string,
): boolean {
  for (const request of requests) {
    if (recordingDurableObjectRequestKey(request) === key) return true;
  }
  return false;
}

function walletRegistrationDoKey(input: {
  readonly prefix: string;
  readonly scope: 'intent' | 'preparation' | 'ceremony';
  readonly id: string;
}): string {
  return `${input.prefix}:wallet-registration:${input.scope}:${input.id}`;
}

function requireRecordingDurableObjectRecord(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly key: string;
}): Record<string, unknown> {
  const record = input.durableObjects.stub.values.get(input.key);
  if (!isSqliteJsonRow(record)) throw new Error(`Missing Durable Object record ${input.key}`);
  return record;
}

function replaceRecordingDurableObjectRecord(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly key: string;
  readonly record: Record<string, unknown>;
}): void {
  input.durableObjects.stub.values.set(input.key, input.record);
}

function recordingDurableObjectKeysWithPrefix(input: {
  readonly durableObjects: RecordingDurableObjectNamespace;
  readonly prefix: string;
}): string[] {
  const matches: string[] = [];
  for (const key of input.durableObjects.stub.values.keys()) {
    if (key.startsWith(input.prefix)) matches.push(key);
  }
  return matches;
}

function requireNestedRecordingDurableObjectRecord(input: {
  readonly record: Record<string, unknown>;
  readonly field: string;
}): Record<string, unknown> {
  const nested = input.record[input.field];
  if (!isSqliteJsonRow(nested)) {
    throw new Error(`Durable Object record field ${input.field} is missing`);
  }
  return nested;
}

function testEcdsaClientBootstrap(
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

function testEcdsaServerBootstrapResponse(
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

async function testEd25519PrepareForRegistration() {
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

async function testEd25519RespondForRegistration() {
  return {
    ok: true as const,
    contextBindingB64u: 'ed25519-context-binding',
    serverInputDeliveryB64u: 'ed25519-server-input-delivery',
    serverState: testEd25519RespondedServerState(),
  };
}

async function testEd25519FinalizeForRegistration() {
  return {
    ok: true as const,
    publicKey: 'ed25519:combined-test-public-key',
    nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
    relayerKeyId: 'combined-test-relayer-key',
    finalizedReport: {
      kind: 'threshold_ed25519_hss_finalized_report_v1',
    },
  };
}

async function testEd25519RegistrationKeygenFromRegistrationMaterial() {
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

async function testEcdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
  return {
    ok: true as const,
    value: testEcdsaServerBootstrapResponse(request),
  };
}

function testGetCombinedRegistrationSchemeModule(schemeId: string) {
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

async function testThresholdSchemeHealthz() {
  return { ok: true };
}

async function testThresholdSchemeSession() {
  return { ok: false as const, code: 'unsupported', message: 'not used by this test' };
}

const testCombinedRegistrationThresholdSigningService = {
  ed25519Hss: {
    prepareForRegistration: testEd25519PrepareForRegistration,
    respondForRegistration: testEd25519RespondForRegistration,
    finalizeForRegistration: testEd25519FinalizeForRegistration,
  },
  ecdsaHssRoleLocalBootstrap: testEcdsaHssRoleLocalBootstrap,
  getSchemeModule: testGetCombinedRegistrationSchemeModule,
} as unknown as ThresholdSigningService;

function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

function arrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function concatBytes(...inputs: readonly Uint8Array[]): Uint8Array {
  const length = inputs.reduce((total, item) => total + item.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const item of inputs) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

function derIntegerBytes(input: Uint8Array): Uint8Array {
  const bytes = [...input];
  while (bytes.length > 1 && bytes[0] === 0 && ((bytes[1] || 0) & 0x80) === 0) bytes.shift();
  if (((bytes[0] || 0) & 0x80) !== 0) bytes.unshift(0);
  return new Uint8Array([0x02, bytes.length, ...bytes]);
}

function rawP256SignatureToDer(input: Uint8Array): Uint8Array {
  if (input.length !== 64) throw new Error('Expected raw P-256 signature to be 64 bytes');
  const r = derIntegerBytes(input.slice(0, 32));
  const s = derIntegerBytes(input.slice(32));
  const body = concatBytes(r, s);
  if (body.length >= 128) throw new Error('Unexpected long-form DER signature length');
  return new Uint8Array([0x30, body.length, ...body]);
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBufferCopy(input)));
}

function hexBytes(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

async function createWebAuthnAssertionFixture(): Promise<WebAuthnAssertionFixture> {
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

async function createWebAuthnAssertion(input: {
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

function jsonBase64Url(input: Record<string, unknown>): string {
  return base64UrlEncode(utf8Bytes(JSON.stringify(input)));
}

function fakeWebAuthnRegistrationCredential(input: {
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

function encodePositiveBigIntB64u(value: bigint): string {
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

function addEmailOtpClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

function removeEmailOtpClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.removeServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_CLIENT_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

function addEmailOtpServerSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
    }),
  );
}

async function generateGoogleOidcTestKey(kid: string): Promise<{
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

async function makeSignedGoogleIdToken(input: {
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

let googleJwksFetchMockPublicJwk: JsonWebKey | null = null;
let oidcJwksFetchMockUrl = '';
let oidcJwksFetchMockPublicJwk: JsonWebKey | null = null;

async function googleJwksFetchMock(input: RequestInfo | URL): Promise<Response> {
  expect(String(input)).toBe('https://www.googleapis.com/oauth2/v3/certs');
  return new Response(JSON.stringify({ keys: [googleJwksFetchMockPublicJwk] }), {
    status: 200,
    headers: { 'cache-control': 'public, max-age=300' },
  });
}

function installGoogleJwksFetchMock(publicJwk: JsonWebKey): typeof globalThis.fetch {
  const originalFetch = globalThis.fetch;
  googleJwksFetchMockPublicJwk = publicJwk;
  globalThis.fetch = googleJwksFetchMock;
  return originalFetch;
}

function restoreGoogleJwksFetchMock(originalFetch: typeof globalThis.fetch): void {
  globalThis.fetch = originalFetch;
  googleJwksFetchMockPublicJwk = null;
}

async function oidcJwksFetchMock(input: RequestInfo | URL): Promise<Response> {
  expect(String(input)).toBe(oidcJwksFetchMockUrl);
  return new Response(JSON.stringify({ keys: [oidcJwksFetchMockPublicJwk] }), {
    status: 200,
    headers: { 'cache-control': 'public, max-age=300' },
  });
}

function installOidcJwksFetchMock(input: {
  readonly jwksUrl: string;
  readonly publicJwk: JsonWebKey;
}): typeof globalThis.fetch {
  const originalFetch = globalThis.fetch;
  oidcJwksFetchMockUrl = input.jwksUrl;
  oidcJwksFetchMockPublicJwk = input.publicJwk;
  globalThis.fetch = oidcJwksFetchMock;
  return originalFetch;
}

function restoreOidcJwksFetchMock(originalFetch: typeof globalThis.fetch): void {
  globalThis.fetch = originalFetch;
  oidcJwksFetchMockUrl = '';
  oidcJwksFetchMockPublicJwk = null;
}

function applySignerMigrations(database: D1DatabaseLike): Promise<void> {
  return applyD1MigrationFiles(database, listD1MigrationFiles('d1-signer'));
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

async function insertIdentity(input: {
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

async function insertWebAuthn(input: {
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

async function readWebAuthnChallengeRow(input: {
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

async function readWebAuthnAuthenticatorRow(input: {
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

async function insertNearPublicKey(input: {
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

async function insertSignerWallet(input: {
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

type TestWalletAuthMethodRecord =
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

type TestWalletAuthMethodIdentity = {
  readonly walletAuthMethodId: string;
  readonly rpId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
};

function testWalletAuthMethodIdentity(
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

async function insertWalletAuthMethod(input: {
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

async function readWalletAuthMethodRecord(input: {
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

async function readSignerWalletRecord(input: {
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

async function readWalletSignerRecord(input: {
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

async function insertEmailOtpEnrollment(input: {
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

async function listGoogleEmailOtpRegistrationAttemptRows(input: {
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

function registrationAttemptRecordFromRow(row: SqliteJsonRow): Record<string, unknown> {
  const raw = row.record_json;
  if (typeof raw !== 'string') throw new Error('registration attempt record_json missing');
  const parsed: unknown = JSON.parse(raw);
  if (!isSqliteJsonRow(parsed)) throw new Error('registration attempt record_json invalid');
  return parsed;
}

async function insertEmailOtpAuthState(input: {
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

async function insertEmailOtpRecoveryEscrow(input: {
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

async function insertEmailOtpGrant(input: {
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

function emailOtpGrantRecord(input: {
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

function emailOtpRecoveryEscrowRecord(input: {
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

type RecoveryRotationEscrowInput = {
  readonly recoveryKeyId: string;
  readonly nonceB64u: string;
  readonly wrappedDeviceEnrollmentEscrowB64u: string;
  readonly aadHashB64u: string;
};

type RecoveryWrappedEnrollmentEscrowInput = {
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

function makeRecoveryRotationEscrowInputs(): RecoveryRotationEscrowInput[] {
  const inputs: RecoveryRotationEscrowInput[] = [];
  for (let index = 1; index <= 10; index += 1) {
    inputs.push(recoveryRotationEscrowInput(index));
  }
  return inputs;
}

function recoveryRotationEscrowInput(index: number): RecoveryRotationEscrowInput {
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

function makeRecoveryWrappedEnrollmentEscrows(input: {
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

function recoveryWrappedEnrollmentEscrowInput(input: {
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

function recoveryEscrowAadHashB64u(
  binding: ReturnType<typeof buildEmailOtpRecoveryWrapBinding>,
): string {
  return base64UrlEncode(
    createHash('sha256').update(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)).digest(),
  );
}

async function readRecoveryEscrowStatusCounts(input: {
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

async function countActiveRecoveryWrappedEnrollmentEscrows(input: {
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

async function insertRecoverySession(input: {
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

function recoverySessionRecord(input: {
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

test('Cloudflare D1 Router API auth service reads signer metadata with tenant scope', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      userId: 'wallet-a',
    };
    await insertIdentity({ database, ...scope, subject: 'google:alice' });
    await insertIdentity({ database, ...scope, orgId: 'org-b', subject: 'google:bob' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'linked.testnet',
      subject: 'wallet:oidc:linked',
    });
    await insertWebAuthn({ database, ...scope });
    await insertNearPublicKey({ database, ...scope });
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 880,
      updatedAtMs: 920,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-revoked',
      recoveryKeyStatus: 'revoked',
      issuedAtMs: 890,
      updatedAtMs: 930,
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-valid',
      appSessionVersion: 'grant-session-v1',
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-mismatch',
      appSessionVersion: 'grant-session-v2',
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });

    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice'],
    });
    await expect(
      service.identity.linkIdentity({ userId: 'wallet-b', subject: 'google:alice' }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.linkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice', 'google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:alice' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toMatchObject({ ok: false, code: 'cannot_unlink_last_identity' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-solo',
      subject: 'google:solo',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:solo',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toEqual({ ok: true, movedFromUserId: 'wallet-solo' });
    await expect(service.identity.listIdentities({ userId: 'wallet-solo' })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-a',
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-b',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:many-a',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.resolveOidcWalletId({
        providerSubject: 'oidc:linked',
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'v1',
        },
      }),
    ).resolves.toBe('linked.testnet');
    const derivedOidcWalletId = await service.identity.resolveOidcWalletId({
      providerSubject: 'oidc:new-user',
      email: 'new-user@example.test',
      runtimePolicyScope: {
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        signingRootVersion: 'v1',
      },
    });
    expect(derivedOidcWalletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relay\.local$/);
    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId: 'email-wallet.testnet',
        providerUserId: 'google:email-user',
        orgId: scope.orgId,
        verifiedEmail: 'alice@example.test',
      },
    });
    await expect(
      service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        providerUserId: 'google:other-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'provider_identity_mismatch' });
    await expect(
      service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: 'org-b',
        providerUserId: 'google:email-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'tenant_scope_mismatch' });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
    });
    await insertEmailOtpAuthState({ database, ...scope });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
    });
    const strongAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(strongAuth.ok).toBe(true);
    if (!strongAuth.ok) throw new Error(strongAuth.message);
    expect(strongAuth.lastStrongAuthAtMs).toBeGreaterThanOrEqual(800);
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
      lastStrongAuthAtMs: strongAuth.lastStrongAuthAtMs,
    });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:not-enrolled',
        walletId: 'missing-email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'not_enrolled',
      walletId: 'missing-email-wallet.testnet',
      enrollmentId: '',
      enrollmentSealKeyVersion: '',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 0,
      consumedRecoveryCodeCount: 0,
      revokedRecoveryCodeCount: 0,
      totalRecoveryCodeCount: 0,
      issuedAtMs: null,
    });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'incomplete',
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 1,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 3,
      issuedAtMs: 880,
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: 'challenge-grant-valid',
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'wrong-session',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: 'challenge-grant-mismatch',
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v2',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    const session = await service.sessionVersions.getOrCreateAppSessionVersion({ userId: scope.userId });
    expect(session.ok).toBe(true);
    if (!session.ok) throw new Error(session.message);
    await expect(
      service.sessionVersions.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toEqual({ ok: true });
    const rotated = await service.sessionVersions.rotateAppSessionVersion({ userId: scope.userId });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    await expect(
      service.sessionVersions.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_session_version' });
    await expect(
      service.webAuthn.listWebAuthnAuthenticatorsForUser({ userId: scope.userId, rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: true,
      authenticators: [
        {
          credentialIdB64u: 'credential-a',
          signerSlot: 2,
          publicKey: 'ed25519:public',
          createdAtMs: 200,
          updatedAtMs: 300,
        },
      ],
    });
    const webAuthnFixture = await createWebAuthnAssertionFixture();
    await insertWebAuthn({
      database,
      ...scope,
      credentialIdB64u: webAuthnFixture.credentialIdB64u,
      credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
      signerSlot: 4,
    });
    const loginOptions = await service.webAuthn.createWebAuthnLoginOptions({
      userId: scope.userId,
      rpId: 'example.com',
      ttlMs: 60_000,
    });
    expect(loginOptions.ok).toBe(true);
    if (!loginOptions.ok) throw new Error(loginOptions.message);
    const loginChallengeId = String(loginOptions.challengeId || '');
    expect(loginChallengeId).not.toBe('');
    expect(loginOptions.challengeB64u).toEqual(expect.any(String));
    expect(loginOptions.expiresAtMs).toBeGreaterThan(Date.now());
    const loginChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: loginChallengeId,
    });
    expect(loginChallengeRow?.challenge_kind).toBe('login');
    expect(loginChallengeRow?.created_at_ms).toEqual(expect.any(Number));
    expect(loginChallengeRow?.expires_at_ms).toBe(loginOptions.expiresAtMs);
    const rawLoginChallengeRecord = loginChallengeRow?.record_json;
    if (typeof rawLoginChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn login challenge record_json');
    }
    const loginChallengeRecord: unknown = JSON.parse(rawLoginChallengeRecord);
    expect(loginChallengeRecord).toMatchObject({
      version: 'webauthn_login_challenge_v1',
      challengeId: loginChallengeId,
      userId: scope.userId,
      rpId: 'example.com',
      challengeB64u: loginOptions.challengeB64u,
      expiresAtMs: loginOptions.expiresAtMs,
    });
    const loginAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(loginOptions.challengeB64u || ''),
      counter: 1,
    });
    await expect(
      service.webAuthn.verifyWebAuthnLogin({
        challengeId: loginChallengeId,
        webauthn_authentication: loginAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: scope.userId,
      rpId: 'example.com',
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 1 });
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({ userId: 'bad user', rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Invalid userId',
    });
    const syncOptions = await service.webAuthn.createWebAuthnSyncAccountOptions({
      rp_id: 'example.com',
      account_id: scope.userId,
      ttl_ms: 60_000,
    });
    expect(syncOptions.ok).toBe(true);
    if (!syncOptions.ok) throw new Error(syncOptions.message);
    const syncChallengeId = String(syncOptions.challengeId || '');
    expect(syncChallengeId).not.toBe('');
    expect(syncOptions.challengeB64u).toEqual(expect.any(String));
    expect(syncOptions.credentialIds).toEqual(['credential-a', webAuthnFixture.credentialIdB64u]);
    expect(syncOptions.walletBinding).toEqual({
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      signerSlot: 2,
    });
    const syncChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: syncChallengeId,
    });
    expect(syncChallengeRow?.challenge_kind).toBe('sync');
    expect(syncChallengeRow?.expires_at_ms).toBe(syncOptions.expiresAtMs);
    const rawSyncChallengeRecord = syncChallengeRow?.record_json;
    if (typeof rawSyncChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn sync challenge record_json');
    }
    const syncChallengeRecord: unknown = JSON.parse(rawSyncChallengeRecord);
    expect(syncChallengeRecord).toMatchObject({
      version: 'webauthn_sync_challenge_v1',
      challengeId: syncChallengeId,
      rpId: 'example.com',
      expectedUserId: scope.userId,
      challengeB64u: syncOptions.challengeB64u,
      expiresAtMs: syncOptions.expiresAtMs,
    });
    const syncAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(syncOptions.challengeB64u || ''),
      counter: 2,
    });
    await expect(
      service.webAuthn.verifyWebAuthnSyncAccount({
        challengeId: syncChallengeId,
        webauthn_authentication: syncAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      verified: true,
      accountId: scope.userId,
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      signerSlot: 4,
      publicKey: 'ed25519:public',
      credentialIdB64u: webAuthnFixture.credentialIdB64u,
      credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 2 });
    await expect(
      service.webAuthn.createWebAuthnSyncAccountOptions({
        account_id: scope.userId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Missing rp_id',
    });
    await expect(service.nearFunding.listNearPublicKeysForUser({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      keys: [
        {
          publicKey: 'ed25519:near-public',
          kind: 'threshold',
          signerSlot: 1,
          createdAtMs: 400,
          updatedAtMs: 500,
          authBinding: {
            kind: 'passkey',
            rpId: 'example.com',
            credentialIdB64u: 'credential-a',
          },
        },
      ],
    });
    await expect(
      service.thresholdRuntime.listThresholdEcdsaKeyIdentityTargetsForUser({
        userId: scope.userId,
        rpId: 'example.com',
        keyTargets: [
          {
            keyHandle: 'ecdsa-key-handle-a',
            chainTarget: { namespace: 'eip155', reference: '1' },
          },
        ],
      }),
    ).resolves.toEqual({
      records: [],
      diagnostics: {
        userId: scope.userId,
        inputCount: 1,
        returnedCount: 0,
        thresholdServicePresent: false,
        rejected: { threshold_service_missing: 1 },
      },
    });
    await expect(
      service.thresholdRuntime.listWalletEcdsaKeyFactsInventory({
        walletId: scope.userId,
        rpId: 'example.com',
        keyTargets: [
          {
            keyHandle: 'ecdsa-key-handle-a',
            chainTarget: { namespace: 'eip155', reference: '1' },
          },
        ],
      }),
    ).resolves.toEqual({
      records: [],
      diagnostics: {
        userId: scope.userId,
        inputCount: 1,
        returnedCount: 0,
        thresholdServicePresent: false,
        rejected: { threshold_service_missing: 1 },
      },
    });
    expect(service.router.getConfiguredRelayerAccount()).toBe('relay.local');
    await expect(service.router.getRelayerAccount()).resolves.toEqual({
      accountId: 'relay.local',
      publicKey: 'relay-public-key',
    });
    expect(service.identity.getGoogleOidcPublicConfig()).toEqual({
      configured: true,
      clientId: 'google-client',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service revokes wallet auth methods through D1', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = 'wallet-auth.testnet';
    const rpId = 'example.com';
    const walletIdValue = walletIdFromString(walletId);
    const rpIdValue = requireParsedDomainId(parseWebAuthnRpId(rpId));
    const email = 'owner@example.test';
    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    const passkeyRecord: TestWalletAuthMethodRecord = {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId,
      rpId,
      credentialIdB64u: 'credential-a',
      credentialPublicKeyB64u: 'public-key-a',
      counter: 0,
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    };
    const emailOtpRecord: TestWalletAuthMethodRecord = {
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex,
      registrationAuthorityId: 'google:owner',
      createdAtMs: 1_100,
      updatedAtMs: 1_100,
    };
    await insertSignerWallet({ database, ...scope, walletId });
    await insertWalletAuthMethod({ database, ...scope, record: passkeyRecord });
    await insertWalletAuthMethod({ database, ...scope, record: emailOtpRecord });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    await expect(
      service.walletAuthMethods.revokeWalletAuthMethod({
        walletId: walletIdValue,
        target: { kind: 'email_otp', email },
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_revoke',
            walletId: walletIdValue,
            target: { kind: 'email_otp', email },
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toEqual({
      ok: true,
      walletId,
      authMethod: {
        kind: 'email_otp',
        status: 'revoked',
      },
    });

    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      kind: 'email_otp',
      status: 'revoked',
      walletId,
      emailHashHex,
    });

    await expect(
      service.walletAuthMethods.revokeWalletAuthMethod({
        walletId: walletIdValue,
        target: { kind: 'passkey', rpId: rpIdValue, credentialIdB64u: 'credential-a' },
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_revoke',
            walletId: walletIdValue,
            target: { kind: 'passkey', rpId: rpIdValue, credentialIdB64u: 'credential-a' },
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'wallet must retain at least one active auth method',
    });

    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: 'passkey:example.com:credential-a',
      }),
    ).resolves.toMatchObject({
      kind: 'passkey',
      status: 'active',
      walletId,
      credentialIdB64u: 'credential-a',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service wires threshold signing from Durable Object config', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const withoutThreshold = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
    });
    expect(withoutThreshold.thresholdRuntime.getThresholdSigningService()).toBeNull();

    const withThreshold = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new ThrowingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'seams-local-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const threshold = withThreshold.thresholdRuntime.getThresholdSigningService();
    expect(threshold).not.toBeNull();
    expect(withThreshold.thresholdRuntime.getThresholdSigningService()).toBe(threshold);
    expect(threshold?.getRouterAbNormalSigningWorkerId()).toBe('test-threshold-signing-worker');
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service stores wallet registration intents in Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2, 3],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2, 3],
          derivationVersion: 1,
        },
      ],
    });
    expect(parseServerAllocatedWalletId(registration.intent.walletId).ok).toBe(true);
    expect(String(registration.intent.walletId)).not.toMatch(/^seams-wallet-/);
    expect(Object.prototype.hasOwnProperty.call(registration.intent, 'rpId')).toBe(false);
    expect(registration.intent.authMethod).toMatchObject({ kind: 'passkey', rpId: 'example.com' });
    expect(registration.intent.runtimePolicyScope).toEqual({
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    });
    const parsedStoredSignerSetIntent = parseD1RegistrationIntent({
      version: 'registration_intent_v1',
      walletId: registration.intent.walletId,
      authMethod: { kind: 'passkey', rpId },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: implicitNearAccountProvisioning(),
            signerSlot: 1,
            participantIds: [1, 2, 3],
            derivationVersion: 1,
          },
        ],
      },
      runtimePolicyScope: registration.intent.runtimePolicyScope,
      nonceB64u: 'stored-nonce',
    });
    expect(parsedStoredSignerSetIntent?.signerSelection).toEqual(
      registration.intent.signerSelection,
    );

    const addSigner = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [3, 2, 1],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    expect(addSigner.ok).toBe(true);
    if (!addSigner.ok) throw new Error(addSigner.message);

    const addAuthMethod = await service.walletAuthMethods.createAddAuthMethodIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        authMethod: { kind: 'email_otp', email: 'owner@example.test' },
      },
    });
    expect(addAuthMethod.ok).toBe(true);
    if (!addAuthMethod.ok) throw new Error(addAuthMethod.message);

    const prefix = 'intent-test:wallet-registration:';
    const registrationRecord = durableObjects.stub.values.get(
      `${prefix}intent:${registration.registrationIntentGrant}`,
    );
    expect(registrationRecord).toMatchObject({
      kind: 'intent_allocated',
      digestB64u: registration.registrationIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      intent: registration.intent,
    });
    const serverAllocatedWalletReservationRequest = durableObjects.stub.requests.find(
      isRecordingDurableObjectReplayReservationRequest,
    );
    expect(recordingDurableObjectRequestKey(serverAllocatedWalletReservationRequest || {})).toBe(
      `${prefix}server-allocated-wallet-reservation:${registration.intent.walletId}`,
    );

    const providedWalletId = walletIdFromString('frost-fjord-rgcmpa');
    const providedRegistration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'provided', walletId: providedWalletId },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2, 3],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(providedRegistration.ok).toBe(true);
    if (!providedRegistration.ok) throw new Error(providedRegistration.message);
    expect(providedRegistration.intent.walletId).toBe(providedWalletId);
    expect(parseServerAllocatedWalletId(providedRegistration.intent.walletId).ok).toBe(true);
    expect(
      recordingDurableObjectRequestsIncludeKey(
        durableObjects.stub.requests,
        `${prefix}server-allocated-wallet-reservation:${providedWalletId}`,
      ),
    ).toBe(true);

    const addSignerRecord = durableObjects.stub.values.get(
      `${prefix}add-signer-intent:${addSigner.addSignerIntentGrant}`,
    );
    expect(addSignerRecord).toMatchObject({
      kind: 'add_signer_intent_allocated',
      digestB64u: addSigner.addSignerIntentDigestB64u,
      orgId: scope.orgId,
      intent: addSigner.intent,
    });
    expect(addSigner.intent.signerSelection).toEqual({
      mode: 'ecdsa',
      ecdsa: {
        participantIds: [3, 2, 1],
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      },
    });

    const addAuthMethodRecord = durableObjects.stub.values.get(
      `${prefix}add-auth-method-intent:${addAuthMethod.addAuthMethodIntentGrant}`,
    );
    expect(addAuthMethodRecord).toMatchObject({
      kind: 'add_auth_method_intent_allocated',
      digestB64u: addAuthMethod.addAuthMethodIntentDigestB64u,
      orgId: scope.orgId,
      intent: addAuthMethod.intent,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects passkey registration challenge and origin mismatches before signer state', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService: {
        async ecdsaHssRoleLocalBootstrap() {
          throw new Error('threshold bootstrap must not run after passkey authority rejection');
        },
      } as unknown as ThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: 'wrong-registration-challenge',
            origin: 'https://app.example.com',
          }),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_mismatch',
      message: 'Registration challenge mismatch',
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: registration.registrationIntentDigestB64u,
            origin: 'https://attacker.example.net',
          }),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_origin',
      message: 'WebAuthn origin is not within rpId',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stored registration intent wallet mismatch before HSS preparation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService: {
        ed25519Hss: {
          async prepareForRegistration() {
            throw new Error('Ed25519 HSS prepare must not run after intent wallet mismatch');
          },
        },
      } as unknown as ThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const intentKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'intent',
      id: registration.registrationIntentGrant,
    });
    const intentRecord = requireRecordingDurableObjectRecord({ durableObjects, key: intentKey });
    const storedIntent = requireNestedRecordingDurableObjectRecord({
      record: intentRecord,
      field: 'intent',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: intentKey,
      record: {
        ...intentRecord,
        intent: {
          ...storedIntent,
          walletId: walletIdFromString('stored-intent-mismatch.testnet'),
        },
      },
    });

    await expect(
      service.walletRegistration.prepareWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: registration.registrationIntentDigestB64u,
            origin: 'https://app.example.com',
          }),
        },
        prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
        work: { kind: 'ed25519_hss' },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'registration intent walletId mismatch',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stored registration preparation wallet mismatch before ceremony start', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService: testCombinedRegistrationThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const preparationKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'preparation',
      id: prepared.registrationPreparationId,
    });
    const preparationRecord = requireRecordingDurableObjectRecord({
      durableObjects,
      key: preparationKey,
    });
    const preparationAuthority = requireNestedRecordingDurableObjectRecord({
      record: preparationRecord,
      field: 'authority',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: preparationKey,
      record: {
        ...preparationRecord,
        authority: {
          ...preparationAuthority,
          walletId: walletIdFromString('registration-preparation-mismatch.testnet'),
        },
      },
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        registrationPreparationId: prepared.registrationPreparationId,
        intent: registration.intent,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'scope_mismatch',
      message: 'registration preparation walletId mismatch',
    });
    expect(
      recordingDurableObjectKeysWithPrefix({
        durableObjects,
        prefix: 'intent-test:wallet-registration:ceremony:',
      }),
    ).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(Object.prototype.hasOwnProperty.call(registration.intent, 'rpId')).toBe(false);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.intent).toEqual(registration.intent);
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: registration.intent.walletId,
        signingRootId: `${scope.projectId}:${scope.envId}`,
        signingRootVersion: 'root-v1',
        keyScope: 'evm-family',
        remainingUses: 3,
        participantIds: [1, 2, 3],
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'root-v1',
        },
      },
    });
    expect(started.ecdsa?.prepare.evmFamilySigningKeySlotId).toContain(
      encodeURIComponent(`${scope.projectId}:${scope.envId}`),
    );
    expect(started.ecdsa?.prepare.ecdsaThresholdKeyId).toMatch(/^ehss-/);
    expect(started.ecdsa?.prepare.relayerKeyId).toMatch(/^ehss-relayer-/);
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}intent:${registration.registrationIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      intent: registration.intent,
      digestB64u: registration.registrationIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      authority: {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        walletId: registration.intent.walletId,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
      },
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'evm_family_ecdsa_prepared',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            hssKind: 'evm_family_ecdsa_keygen',
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
            prepare: started.ecdsa?.prepare,
          },
        ],
      },
    });

    const ceremonyKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'ceremony',
      id: started.registrationCeremonyId,
    });
    const ceremonyRecord = requireRecordingDurableObjectRecord({
      durableObjects,
      key: ceremonyKey,
    });
    const ceremonyAuthority = requireNestedRecordingDurableObjectRecord({
      record: ceremonyRecord,
      field: 'authority',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: ceremonyKey,
      record: {
        ...ceremonyRecord,
        authority: {
          ...ceremonyAuthority,
          walletId: walletIdFromString('registration-ceremony-mismatch.testnet'),
        },
      },
    });
    await expect(
      service.walletRegistration.respondWalletRegistrationHss({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          clientBootstrap: testEcdsaClientBootstrap(started.ecdsa.prepare),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'scope_mismatch',
      message: 'registration ceremony walletId mismatch',
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'email_otp',
          emailOtpRegistrationProof: {
            version: 'email_otp_registration_proof_v1',
            proofKind: 'otp_challenge',
            providerSubject,
            email,
            challengeId: challenge.challenge.challengeId,
            otpCode: outbox.otpCode,
            otpChannel: 'email_otp',
            registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
            appSessionVersion,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_grant',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts and responds to combined Ed25519 and ECDSA registration ceremonies', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService: testCombinedRegistrationThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testCombinedRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss_and_ecdsa' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);
    expect(prepared.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    });

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    });
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      prepare: {
        walletId: registration.intent.walletId,
        signingRootId: `${scope.projectId}:${scope.envId}`,
        signingRootVersion: 'root-v1',
        keyScope: 'evm-family',
      },
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}intent:${registration.registrationIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}preparation:${prepared.registrationPreparationId}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_prepared',
            branchKey: 'near_ed25519:slot:1',
            ceremonyHandle: 'ed25519-ceremony-handle',
          },
          {
            kind: 'evm_family_ecdsa_prepared',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            prepare: started.ecdsa?.prepare,
          },
        ],
      },
    });

    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');
    const clientBootstrap = testEcdsaClientBootstrap(started.ecdsa.prepare);
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'ed25519-client-request',
        },
      },
      ecdsa: {
        clientBootstrap,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ok).toBe(true);
    expect(responded.ed25519).toEqual({
      contextBindingB64u: 'ed25519-context-binding',
      serverInputDeliveryB64u: 'ed25519-server-input-delivery',
    });
    expect(responded.ecdsa?.bootstrap).toMatchObject({
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      thresholdSessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
    });
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_responded',
            branchKey: 'near_ed25519:slot:1',
            responded: {
              serverInputDeliveryB64u: 'ed25519-server-input-delivery',
            },
          },
          {
            kind: 'evm_family_ecdsa_responded',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            responded: {
              bootstrap: {
                thresholdSessionId: clientBootstrap.thresholdSessionId,
              },
            },
          },
        ],
      },
    });

    const enrollmentSealKeyVersion = 'combined-registration-seal-v1';
    const unlockKeyVersion = 'combined-registration-unlock-v1';
    const recoveryCodesIssuedAtMs = Date.now();
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 9;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId: registration.intent.walletId,
      userId: providerSubject,
      enrollmentId: `email-otp-device-enrollment-v1:${registration.intent.walletId}`,
      enrollmentSealKeyVersion,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      issuedAtMs: recoveryCodesIssuedAtMs,
    });

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'combined-registration-finalize-replay-a',
      ed25519: {
        evaluationResult: {
          contextBindingB64u: 'ed25519-context-binding',
          stagedEvaluatorArtifactB64u: 'ed25519-staged-evaluator-artifact',
        },
      },
      ecdsa: {
        expectedKeyHandles: ['unexpected-key-handle', 'test-add-signer-ecdsa-key-handle'],
      },
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        recoveryCodesIssuedAtMs,
        backupActionKind: 'copy',
        acknowledgedAtMs: recoveryCodesIssuedAtMs + 1,
        idempotencyKey: 'combined-registration-backup-ack-a',
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      authMethod: {
        kind: 'email_otp',
        registrationAuthorityId: challenge.challenge.challengeId,
      },
      resolvedAccount: {
        kind: 'implicit_account',
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      },
      ed25519: {
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
        publicKey: 'ed25519:combined-test-public-key',
        relayerKeyId: 'combined-test-relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId: registration.intent.walletId,
            evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
            keyHandle: 'test-add-signer-ecdsa-key-handle',
          },
        ],
      },
    });
    expect(Object.prototype.hasOwnProperty.call(finalized, 'rpId')).toBe(false);

    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId: registration.intent.walletId,
        signerFamily: 'ed25519',
        signerId: `ed25519:${TEST_COMBINED_NEAR_ACCOUNT_ID}:1`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ed25519_v1',
      walletId: registration.intent.walletId,
      signerSlot: 1,
      nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      publicKey: 'ed25519:combined-test-public-key',
      relayerKeyId: 'combined-test-relayer-key',
    });
    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId: registration.intent.walletId,
        signerFamily: 'ecdsa',
        signerId: 'ecdsa:evm:eip155:8453',
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: started.ecdsa.prepare.ecdsaThresholdKeyId,
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toBeUndefined();
    const ceremonyKey = `${prefix}ceremony:${started.registrationCeremonyId}`;
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'del',
        key: ceremonyKey,
      }),
    ).toBe(1);
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'getdel',
        key: ceremonyKey,
      }),
    ).toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts and responds to Ed25519-only signer-set registration ceremonies', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const thresholdSigningService = {
      ed25519Hss: {
        async prepareForRegistration() {
          return {
            ok: true as const,
            ceremonyHandle: 'ed25519-only-ceremony-handle',
            preparedSession: {
              contextBindingB64u: 'ed25519-only-context-binding',
              evaluatorDriverStateB64u: 'ed25519-only-evaluator-driver-state',
            },
            clientOtOfferMessageB64u: 'ed25519-only-client-ot-offer',
            serverState: testEd25519PreparedServerState(),
          };
        },
        async respondForRegistration() {
          return {
            ok: true as const,
            contextBindingB64u: 'ed25519-only-context-binding',
            serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
            serverState: testEd25519RespondedServerState(),
          };
        },
      },
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-only-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-only-client-ot-offer',
    });
    expect(started.ecdsa).toBeUndefined();

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_prepared',
            branchKey: 'near_ed25519:slot:1',
            ceremonyHandle: 'ed25519-only-ceremony-handle',
          },
        ],
      },
    });

    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'ed25519-only-client-request',
        },
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ed25519).toEqual({
      contextBindingB64u: 'ed25519-only-context-binding',
      serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
    });
    expect(responded.ecdsa).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_responded',
            branchKey: 'near_ed25519:slot:1',
            responded: {
              serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
            },
          },
        ],
      },
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service responds to ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    let bootstrapRequest: EcdsaHssClientBootstrapRequest | null = null;
    const thresholdSigningService = {
      async ecdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
        bootstrapRequest = request;
        return {
          ok: true as const,
          value: testEcdsaServerBootstrapResponse(request),
        };
      },
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');

    const clientBootstrap = testEcdsaClientBootstrap(started.ecdsa.prepare);
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstrap,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ecdsa?.bootstrap).toMatchObject({
      keyHandle: 'test-add-signer-ecdsa-key-handle',
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      thresholdSessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
    });
    expect(bootstrapRequest).toMatchObject({
      sessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
      runtimePolicyScope: registration.intent.runtimePolicyScope,
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'evm_family_ecdsa_responded',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            hssKind: 'evm_family_ecdsa_keygen',
            prepare: started.ecdsa.prepare,
            responded: {
              bootstrap: {
                keyHandle: 'test-add-signer-ecdsa-key-handle',
                thresholdSessionId: clientBootstrap.thresholdSessionId,
                signingGrantId: clientBootstrap.signingGrantId,
              },
            },
          },
        ],
      },
    });

    await expect(
      service.walletRegistration.respondWalletRegistrationHss({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          clientBootstrap,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service finalizes ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const thresholdSigningService = {
      async ecdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
        return {
          ok: true as const,
          value: testEcdsaServerBootstrapResponse(request),
        };
      },
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');

    const clientBootstrap = testEcdsaClientBootstrap(started.ecdsa.prepare);
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstrap,
      },
    });
    if (!responded.ok) throw new Error(responded.message);

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['wrong-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'key_handle_mismatch',
    });

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration finalize requires emailOtpEnrollment',
    });

    const enrollmentSealKeyVersion = 'registration-seal-v1';
    const unlockKeyVersion = 'registration-unlock-v1';
    const recoveryCodesIssuedAtMs = Date.now();
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 7;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId: registration.intent.walletId,
      userId: providerSubject,
      enrollmentId: `email-otp-device-enrollment-v1:${registration.intent.walletId}`,
      enrollmentSealKeyVersion,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      issuedAtMs: recoveryCodesIssuedAtMs,
    });

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'registration-finalize-replay-a',
      ecdsa: {
        expectedKeyHandles: ['unexpected-key-handle', 'test-add-signer-ecdsa-key-handle'],
      },
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        recoveryCodesIssuedAtMs,
        backupActionKind: 'copy',
        acknowledgedAtMs: recoveryCodesIssuedAtMs + 1,
        idempotencyKey: 'registration-backup-ack-a',
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(Object.prototype.hasOwnProperty.call(finalized, 'rpId')).toBe(false);
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      authMethod: {
        kind: 'email_otp',
        registrationAuthorityId: challenge.challenge.challengeId,
      },
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId: registration.intent.walletId,
            evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
            keyHandle: 'test-add-signer-ecdsa-key-handle',
            ecdsaThresholdKeyId: started.ecdsa.prepare.ecdsaThresholdKeyId,
            signingRootId: `${scope.projectId}:${scope.envId}`,
            signingRootVersion: 'root-v1',
            thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
            relayerKeyId: started.ecdsa.prepare.relayerKeyId,
            participantIds: [1, 2, 3],
          },
        ],
      },
    });

    const walletRecord = await readSignerWalletRecord({
      database,
      ...scope,
      walletId: registration.intent.walletId,
    });
    expect(walletRecord).toMatchObject({
      version: 'wallet_v1',
      walletId: registration.intent.walletId,
      createdAtMs: expect.any(Number),
      updatedAtMs: expect.any(Number),
    });
    expect(Object.prototype.hasOwnProperty.call(walletRecord, 'rpId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(walletRecord, 'rp_id')).toBe(false);

    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${registration.intent.walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: registration.intent.walletId,
      emailHashHex,
      registrationAuthorityId: challenge.challenge.challengeId,
    });
    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId: registration.intent.walletId,
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId: registration.intent.walletId,
        providerUserId: providerSubject,
        orgId: scope.orgId,
        verifiedEmail: email,
        recoveryWrappedEnrollmentEscrowCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        enrollmentSealKeyVersion,
        unlockKeyVersion,
      },
    });
    await expect(
      countActiveRecoveryWrappedEnrollmentEscrows({
        database,
        namespace: scope.namespace,
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        walletId: registration.intent.walletId,
      }),
    ).resolves.toBe(EMAIL_OTP_RECOVERY_KEY_COUNT);

    const signerRecord = await readWalletSignerRecord({
      database,
      ...scope,
      walletId: registration.intent.walletId,
      signerFamily: 'ecdsa',
      signerId: 'ecdsa:evm:eip155:8453',
    });
    expect(signerRecord).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: started.ecdsa.prepare.ecdsaThresholdKeyId,
        thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
      },
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toBeUndefined();
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        idempotencyKey: 'registration-finalize-replay-a',
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId: registration.intent.walletId,
      ecdsa: {
        walletKeys: [
          {
            keyHandle: 'test-add-signer-ecdsa-key-handle',
          },
        ],
      },
    });
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service adds Email OTP wallet auth methods through D1 and Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-auth-wallet.testnet');
    const rpId = 'example.com';
    const providerSubject = 'google:add-auth-user';
    const email = 'add.auth@example.test';
    const appSessionVersion = 'add-auth-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    await insertSignerWallet({ database, ...scope, walletId });
    await insertWalletAuthMethod({
      database,
      ...scope,
      record: {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId,
        rpId,
        credentialIdB64u: 'existing-passkey-credential',
        credentialPublicKeyB64u: 'existing-passkey-public-key',
        counter: 0,
        createdAtMs: 1_000,
        updatedAtMs: 1_000,
      },
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const intent = await service.walletAuthMethods.createAddAuthMethodIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        authMethod: { kind: 'email_otp', email },
      },
    });
    expect(intent.ok).toBe(true);
    if (!intent.ok) throw new Error(intent.message);
    expect(Object.prototype.hasOwnProperty.call(intent.intent, 'rpId')).toBe(false);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: intent.addAuthMethodIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletAuthMethods.startWalletAddAuthMethod({
      walletId,
      addAuthMethodIntentGrant: intent.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: intent.addAuthMethodIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_auth_method_provision',
          walletId,
          authMethod: intent.intent.authMethod,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: intent.addAuthMethodIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.intent).toEqual(intent.intent);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(
        `${prefix}add-auth-method-intent:${intent.addAuthMethodIntentGrant}`,
      ),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}add-auth-method:${started.addAuthMethodCeremonyId}`),
    ).toMatchObject({
      digestB64u: intent.addAuthMethodIntentDigestB64u,
      orgId: scope.orgId,
      intent: intent.intent,
      auth: { kind: 'app_session' },
      authority: {
        kind: 'email_otp',
        walletId,
        email,
      },
    });

    const finalized = await service.walletAuthMethods.finalizeWalletAddAuthMethod({
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    });
    expect(finalized).toEqual({
      ok: true,
      walletId,
      authMethod: {
        kind: 'email_otp',
        status: 'active',
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}add-auth-method:${started.addAuthMethodCeremonyId}`),
    ).toBeUndefined();

    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex,
      registrationAuthorityId: challenge.challenge.challengeId,
    });
    await expect(
      service.walletAuthMethods.finalizeWalletAddAuthMethod({
        addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts ECDSA add-signer ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-signer-wallet.testnet');
    const rpId = 'example.com';
    const durableObjects = new RecordingDurableObjectNamespace();
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [1, 2, 3],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    expect(intent.ok).toBe(true);
    if (!intent.ok) throw new Error(intent.message);
    expect(Object.prototype.hasOwnProperty.call(intent.intent, 'rpId')).toBe(false);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const started = await service.walletAuthMethods.startWalletAddSigner({
      walletId,
      addSignerIntentGrant: intent.addSignerIntentGrant,
      addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId,
          signerSelection: intent.intent.signerSelection,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    expect(started.ok).toBe(true);
    expect(started.intent).toEqual(intent.intent);
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId,
        signingRootId: `${scope.projectId}:${scope.envId}`,
        signingRootVersion: 'root-v1',
        keyScope: 'evm-family',
        remainingUses: 3,
        participantIds: [1, 2, 3],
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'root-v1',
        },
      },
    });
    expect(started.ecdsa?.prepare.evmFamilySigningKeySlotId).toContain(
      encodeURIComponent(`${scope.projectId}:${scope.envId}`),
    );
    expect(started.ecdsa?.prepare.ecdsaThresholdKeyId).toMatch(/^ehss-/);
    expect(started.ecdsa?.prepare.relayerKeyId).toMatch(/^ehss-relayer-/);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer-intent:${intent.addSignerIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toMatchObject({
      intent: intent.intent,
      digestB64u: intent.addSignerIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      auth: { kind: 'app_session' },
      signerState: {
        kind: 'ecdsa_add_signer_prepared',
        hssKind: 'evm_family_ecdsa_keygen',
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
        prepare: started.ecdsa?.prepare,
      },
    });

    await expect(
      service.walletAuthMethods.startWalletAddSigner({
        walletId,
        addSignerIntentGrant: intent.addSignerIntentGrant,
        addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
        intent: intent.intent,
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_signer_provision',
            walletId,
            signerSelection: intent.intent.signerSelection,
            runtimePolicyScope,
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_grant',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service responds to and finalizes ECDSA add-signer ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-signer-respond-wallet.testnet');
    const rpId = 'example.com';
    const durableObjects = new RecordingDurableObjectNamespace();
    let bootstrapRequest: EcdsaHssClientBootstrapRequest | null = null;
    const thresholdSigningService = {
      async ecdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
        bootstrapRequest = request;
        return {
          ok: true as const,
          value: testEcdsaServerBootstrapResponse(request),
        };
      },
    } as unknown as ThresholdSigningService;
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [1, 2, 3],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    if (!intent.ok) throw new Error(intent.message);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const started = await service.walletAuthMethods.startWalletAddSigner({
      walletId,
      addSignerIntentGrant: intent.addSignerIntentGrant,
      addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId,
          signerSelection: intent.intent.signerSelection,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA add-signer start payload');

    const clientBootstrap = testEcdsaClientBootstrap(started.ecdsa.prepare);
    const responded = await service.walletAuthMethods.respondWalletAddSignerHss({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        clientBootstrap,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ecdsa?.bootstrap).toMatchObject({
      keyHandle: 'test-add-signer-ecdsa-key-handle',
      walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      thresholdSessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
    });
    expect(bootstrapRequest).toMatchObject({
      sessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
      runtimePolicyScope,
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'ecdsa_add_signer_responded',
        hssKind: 'evm_family_ecdsa_keygen',
        prepare: started.ecdsa.prepare,
        responded: {
          bootstrap: {
            keyHandle: 'test-add-signer-ecdsa-key-handle',
            thresholdSessionId: clientBootstrap.thresholdSessionId,
            signingGrantId: clientBootstrap.signingGrantId,
          },
        },
      },
    });

    await expect(
      service.walletAuthMethods.respondWalletAddSignerHss({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          clientBootstrap,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
    });

    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['wrong-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'key_handle_mismatch',
    });

    const finalized = await service.walletAuthMethods.finalizeWalletAddSigner({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: ['unexpected-key-handle', 'test-add-signer-ecdsa-key-handle'],
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      walletId,
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId,
            evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
            keyHandle: 'test-add-signer-ecdsa-key-handle',
            ecdsaThresholdKeyId: started.ecdsa.prepare.ecdsaThresholdKeyId,
            signingRootId: `${scope.projectId}:${scope.envId}`,
            signingRootVersion: 'root-v1',
            thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
            relayerKeyId: started.ecdsa.prepare.relayerKeyId,
            participantIds: [1, 2, 3],
          },
        ],
      },
    });

    const signerRecord = await readWalletSignerRecord({
      database,
      ...scope,
      walletId,
      signerFamily: 'ecdsa',
      signerId: 'ecdsa:evm:eip155:8453',
    });
    expect(signerRecord).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      evmFamilySigningKeySlotId: started.ecdsa.prepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: started.ecdsa.prepare.ecdsaThresholdKeyId,
        thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toBeUndefined();

    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies Google OIDC tokens and links identity', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  const key = await generateGoogleOidcTestKey('google-kid-success');
  const originalFetch = installGoogleJwksFetchMock(key.publicJwk);
  try {
    await applySignerMigrations(database);
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const nowSec = Math.floor(Date.now() / 1000);
    const idToken = await makeSignedGoogleIdToken({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://accounts.google.com',
        aud: 'google-client',
        sub: 'subject-123',
        email: 'Alice@Example.Test',
        email_verified: true,
        name: 'Alice Example',
        given_name: 'Alice',
        family_name: 'Example',
        hd: 'example.test',
        iat: nowSec,
        exp: nowSec + 300,
      },
    });

    const verified = await service.identity.verifyGoogleLogin({ idToken });
    expect(verified).toMatchObject({
      ok: true,
      verified: true,
      userId: 'google:subject-123',
      providerSubject: 'google:subject-123',
      sub: 'subject-123',
      email: 'Alice@Example.Test',
      emailVerified: true,
      hostedDomain: 'example.test',
    });
    await expect(service.identity.listIdentities({ userId: 'google:subject-123' })).resolves.toEqual({
      ok: true,
      subjects: ['google:subject-123'],
    });

    const parts = idToken.split('.');
    const tamperedPayloadB64u = jsonBase64Url({
      iss: 'https://accounts.google.com',
      aud: 'google-client',
      sub: 'subject-999',
      iat: nowSec,
      exp: nowSec + 300,
    });
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;
    await expect(service.identity.verifyGoogleLogin({ idToken: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'invalid_signature',
    });
  } finally {
    restoreGoogleJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies generic OIDC exchange tokens', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  const key = await generateGoogleOidcTestKey('oidc-kid-success');
  const jwksUrl = 'https://issuer.example.com/.well-known/jwks.json';
  const originalFetch = installOidcJwksFetchMock({
    jwksUrl,
    publicJwk: key.publicJwk,
  });
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const providerSubject = 'oidc:https://issuer.example.com:subject-123';
    await insertIdentity({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      userId: 'linked-oidc-wallet.testnet',
      subject: providerSubject,
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
      oidcExchange: {
        clockSkewSec: 0,
        issuers: [
          {
            issuer: 'https://issuer.example.com/',
            audiences: ['wallet-app'],
            jwksUrl,
          },
        ],
      },
    });
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await makeSignedGoogleIdToken({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        email: 'oidc-user@example.test',
        name: 'OIDC User',
        given_name: 'OIDC',
        family_name: 'User',
        iat: nowSec,
        exp: nowSec + 300,
      },
    });

    await expect(service.identity.verifyOidcJwtExchange({ token })).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: 'linked-oidc-wallet.testnet',
      providerSubject,
      iss: 'https://issuer.example.com',
      aud: ['wallet-app'],
      sub: 'subject-123',
      email: 'oidc-user@example.test',
      name: 'OIDC User',
      given_name: 'OIDC',
      family_name: 'User',
    });
    await expect(service.identity.listIdentities({ userId: 'linked-oidc-wallet.testnet' })).resolves.toEqual(
      {
        ok: true,
        subjects: [providerSubject],
      },
    );

    const parts = token.split('.');
    const tamperedPayloadB64u = jsonBase64Url({
      iss: 'https://issuer.example.com',
      aud: 'wallet-app',
      sub: 'subject-999',
      iat: nowSec,
      exp: nowSec + 300,
    });
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;
    await expect(service.identity.verifyOidcJwtExchange({ token: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'invalid_signature',
    });
  } finally {
    restoreOidcJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service applies and removes Email OTP server seals', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
      emailOtpServerSeal: {
        keyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
        shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
        serverEncryptExponentB64u: EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U,
        serverDecryptExponentB64u: EMAIL_OTP_SERVER_DECRYPT_EXPONENT_B64U,
      },
    });
    const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
    const clientWrappedCiphertext = addEmailOtpClientSeal(plaintextSecretB64u);

    const applied = await service.emailOtp.applyEmailOtpServerSeal({
      wrappedCiphertext: clientWrappedCiphertext,
    });
    expect(applied).toMatchObject({
      ok: true,
      enrollmentSealKeyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
    });
    if (!applied.ok) return;
    expect(applied.ciphertext).not.toBe(clientWrappedCiphertext);
    expect(removeEmailOtpClientSeal(applied.ciphertext)).toBe(
      addEmailOtpServerSeal(plaintextSecretB64u),
    );

    const removed = await service.emailOtp.removeEmailOtpServerSeal({
      wrappedCiphertext: applied.ciphertext,
    });
    expect(removed).toMatchObject({
      ok: true,
      enrollmentSealKeyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
    });
    if (!removed.ok) return;
    expect(removed.ciphertext).not.toBe(applied.ciphertext);
    expect(removeEmailOtpClientSeal(removed.ciphertext)).toBe(plaintextSecretB64u);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service fails closed when Email OTP server seal is unconfigured', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    await expect(
      service.emailOtp.applyEmailOtpServerSeal({
        wrappedCiphertext: addEmailOtpClientSeal(encodePositiveBigIntB64u(23n)),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_configured',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Google Email OTP registration attempt parser rejects legacy auth providers', () => {
  const canonical = parseGoogleEmailOtpRegistrationAttemptRecord(
    googleEmailOtpD1RegistrationAttemptBoundaryFixture({ authProvider: 'google' }),
  );
  expect(canonical).toMatchObject({ authProvider: 'google' });

  const legacy = parseGoogleEmailOtpRegistrationAttemptRecord(
    googleEmailOtpD1RegistrationAttemptBoundaryFixture({ authProvider: 'google_oidc' }),
  );
  expect(legacy).toBeNull();
});

test('Cloudflare D1 Router API auth service starts, reuses, and restarts Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const appSession = await service.sessionVersions.getOrCreateAppSessionVersion({
      userId: 'google:register-user',
    });
    expect(appSession.ok).toBe(true);
    if (!appSession.ok) throw new Error(appSession.message);

    const rateLimit = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:register-user',
      clientIp: '203.0.113.10',
    });
    expect(rateLimit).toEqual({ ok: true });

    const first = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(first.ok).toBe(true);
    expect(first.mode).toBe('register_started');
    if (!first.ok || first.mode !== 'register_started') return;
    expect(parseServerAllocatedWalletId(first.walletId).ok).toBe(true);
    expect(first.email).toBe('alice@example.test');
    expect(first.offer.candidates).toHaveLength(5);
    expect(first.offer.selectedCandidateId).toBe(first.offer.candidates[0].candidateId);

    const reused = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(reused.ok).toBe(true);
    expect(reused.mode).toBe('register_started');
    if (!reused.ok || reused.mode !== 'register_started') return;
    expect(reused.registrationAttemptId).toBe(first.registrationAttemptId);
    expect(reused.walletId).toBe(first.walletId);

    const rowsAfterReuse = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterReuse).toHaveLength(1);
    expect(rowsAfterReuse[0].state).toBe('started');
    expect(rowsAfterReuse[0].app_session_version).toBe(appSession.appSessionVersion);
    expect(rowsAfterReuse[0].runtime_org_id).toBe(scope.orgId);
    expect(rowsAfterReuse[0].runtime_policy_key).toBe(
      `${scope.orgId}\n${scope.projectId}\n${scope.envId}\nroot-v1`,
    );
    const stored = registrationAttemptRecordFromRow(rowsAfterReuse[0]);
    expect(stored.providerSubject).toBe('google:register-user');
    expect(stored.walletId).toBe(first.walletId);
    expect(stored.authProvider).toBe('google');
    expect(stored.runtimePolicyScope).toEqual(runtimePolicyScope);

    const restarted = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
      restartRegistrationOffer: true,
    });
    expect(restarted.ok).toBe(true);
    expect(restarted.mode).toBe('register_started');
    if (!restarted.ok || restarted.mode !== 'register_started') return;
    expect(restarted.registrationAttemptId).not.toBe(first.registrationAttemptId);

    const rowsAfterRestart = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterRestart).toHaveLength(2);
    const states: unknown[] = [];
    for (const row of rowsAfterRestart) states.push(row.state);
    states.sort();
    expect(states).toEqual(['abandoned', 'started']);

    await expect(
      service.identity.linkIdentity({
        userId: first.walletId,
        subject: 'wallet:google:register-user',
      }),
    ).resolves.toEqual({ ok: true });
    const cleaned = await service.emailOtp.cleanupGoogleEmailOtpDevRegistrationState({
      providerSubject: 'google:register-user',
      walletId: first.walletId,
      orgId: scope.orgId,
      nowMs: Date.now() + 31 * 60_000,
    });
    expect(cleaned).toEqual({
      ok: true,
      providerSubject: 'google:register-user',
      expiredRegistrationAttemptsDeleted: 2,
      linkedWalletId: first.walletId,
      orphanedWalletMappingRemoved: true,
    });
    await expect(service.identity.listIdentities({ userId: first.walletId })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await expect(
      listGoogleEmailOtpRegistrationAttemptRows({
        database,
        ...scope,
      }),
    ).resolves.toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts Google Email OTP wallet registration', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const email = 'sso-registration@example.test';
    const providerSubject = 'google:sso-registration-user';
    const durableObjects = new RecordingDurableObjectNamespace();
    const thresholdSigningService = {
      ed25519Hss: {
        async prepareForRegistration() {
          return {
            ok: true as const,
            ceremonyHandle: 'google-sso-ed25519-ceremony-handle',
            preparedSession: {
              contextBindingB64u: 'google-sso-ed25519-context-binding',
              evaluatorDriverStateB64u: 'google-sso-ed25519-evaluator-driver-state',
            },
            clientOtOfferMessageB64u: 'google-sso-ed25519-client-ot-offer',
            serverState: testEd25519PreparedServerState(),
          };
        },
      },
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
      relayerAccount: 'relay.local',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const appSession = await service.sessionVersions.getOrCreateAppSessionVersion({
      userId: providerSubject,
    });
    expect(appSession.ok).toBe(true);
    if (!appSession.ok) throw new Error(appSession.message);

    const resolved = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject,
      email,
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(resolved.ok).toBe(true);
    expect(resolved.mode).toBe('register_started');
    if (!resolved.ok || resolved.mode !== 'register_started') return;
    const selected = resolved.offer.candidates[0];
    expect(selected).toBeTruthy();
    if (!selected) return;

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'provided', walletId: walletIdFromString(selected.walletId) },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          email,
          appSessionJwt: 'google-sso-app-session-jwt',
          googleEmailOtpRegistrationAttemptId: resolved.registrationAttemptId,
          googleEmailOtpRegistrationOfferId: resolved.offer.offerId,
          googleEmailOtpRegistrationCandidateId: selected.candidateId,
        },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.ok).toBe(true);

    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'google_sso_registration' as const,
        providerSubject,
        email,
        googleEmailOtpRegistrationAttemptId: resolved.registrationAttemptId,
        googleEmailOtpRegistrationOfferId: resolved.offer.offerId,
        googleEmailOtpRegistrationCandidateId: selected.candidateId,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion: appSession.appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'google-sso-ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'google-sso-ed25519-client-ot-offer',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rate-limits Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGoogleRegistrationAttemptRateLimitMax: 1,
      emailOtpGoogleRegistrationAttemptRateLimitWindowMs: 60_000,
    });

    const first = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(first).toEqual({ ok: true });

    const second = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.code).toBe('rate_limited');
    expect(second.retryAfterMs).toBeGreaterThan(0);
    expect(second.resetAtMs).toBeGreaterThan(Date.now());
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rotates Email OTP recovery keys after fresh auth', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 920,
      updatedAtMs: 930,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const rotated = await service.emailOtp.rotateEmailOtpRecoveryKeys({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    expect(rotated).toMatchObject({
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      activeRecoveryCodeCount: 10,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 10, consumed: 1, revoked: 1 });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      status: 'ready',
      activeRecoveryCodeCount: 10,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stale Email OTP recovery-key rotation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
      }),
    ).resolves.toMatchObject({ ok: false, code: 'fresh_auth_required' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects invalid Email OTP recovery-key rotation payloads', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const duplicateInputs = makeRecoveryRotationEscrowInputs();
    duplicateInputs[1] = {
      ...duplicateInputs[1],
      recoveryKeyId: duplicateInputs[0].recoveryKeyId,
      aadHashB64u: duplicateInputs[0].aadHashB64u,
    };
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: duplicateInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const badAadInputs = makeRecoveryRotationEscrowInputs();
    badAadInputs[0] = {
      ...badAadInputs[0],
      aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(250)),
    };
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: badAadInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service tracks recovery sessions and executions', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertRecoverySession({
      database,
      ...scope,
      sessionId: 'recovery-session-a',
      metadata: { source: 'fixture' },
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const initial = await service.recovery.getRecoverySession({ sessionId: 'recovery-session-a' });
    expect(initial.ok).toBe(true);
    if (!initial.ok) throw new Error(initial.message);
    expect(initial.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'prepared',
      nearAccountId: 'alice.testnet',
      metadata: { source: 'fixture' },
    });

    const updated = await service.recovery.updateRecoverySessionStatus({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadataPatch: {
        verifiedAtMs: 1_250,
      },
    });
    expect(updated.ok).toBe(true);
    if (!updated.ok) throw new Error(updated.message);
    expect(updated.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadata: { source: 'fixture', verifiedAtMs: 1_250 },
    });
    expect(updated.record.updatedAtMs).toBeGreaterThanOrEqual(updated.record.createdAtMs);

    const pending = await service.recovery.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'NEAR:TESTNET',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
      metadata: {
        expectedNewNearPublicKey: 'ed25519:new-public-key',
      },
    });
    expect(pending.ok).toBe(true);
    if (!pending.ok) throw new Error(pending.message);
    expect(pending.record).toMatchObject({
      sessionId: 'recovery-session-a',
      userId: 'recovery-user',
      nearAccountId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
    });

    const submitted = await service.recovery.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.ok).toBe(true);
    if (!submitted.ok) throw new Error(submitted.message);
    expect(submitted.record).toMatchObject({
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.record.createdAtMs).toBe(pending.record.createdAtMs);

    const executionRow = await database
      .prepare(
        `SELECT status, record_json
           FROM recovery_executions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND session_id = ?
            AND chain_id_key = ?
            AND account_address = ?
            AND action = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'recovery-session-a',
        'near:testnet',
        'alice.testnet',
        'near_email_recovery',
      )
      .first<SqliteJsonRow>();
    expect(executionRow?.status).toBe('submitted');
    expect(JSON.parse(String(executionRow?.record_json || '{}'))).toMatchObject({
      transactionHash: 'near-tx-a',
    });

    await expect(
      service.recovery.recordRecoveryExecution({
        sessionId: 'missing-session',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        action: 'near_email_recovery',
        status: 'pending',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_args' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues and verifies login Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpMaxAttempts: 2,
    });

    const challenge = await service.emailOtp.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'dev_d1_outbox',
      emailHint: 'a***e@e***e.test',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    expect(outbox.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: '000000' === outbox.otpCode ? '111111' : '000000',
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_otp', attemptsRemaining: 1 });

    const verified = await service.emailOtp.verifyEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.loginGrant).toMatch(/^[A-Za-z0-9_-]+$/);

    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });

    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: challenge.challenge.challengeId,
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues registration Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      email: 'Register.User@Example.Test',
      otpChannel: 'email_otp',
      sessionHash: 'registration-session-hash',
      appSessionVersion: 'registration-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.challenge).toMatchObject({
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });
    expect(challenge.delivery).toEqual({
      status: 'sent',
      mode: 'dev_d1_outbox',
      emailHint: 'r***r@e***e.test',
    });

    const challengeRow = await database
      .prepare(
        `SELECT action, operation, record_json
           FROM email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND challenge_id = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        challenge.challenge.challengeId,
      )
      .first<SqliteJsonRow>();
    expect(challengeRow).toMatchObject({
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });
    const challengeRecord = JSON.parse(String(challengeRow?.record_json || '{}'));
    expect(challengeRecord).toMatchObject({
      challengeSubjectId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      email: 'register.user@example.test',
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    expect(outbox.otpCode).toMatch(/^[0-9]{6}$/);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies registration Email OTP enrollment', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = 'registration-wallet.testnet';
    const providerSubject = 'google:registration-user';
    const sessionHash = 'registration-session-hash';
    const appSessionVersion = 'registration-session-v1';
    const enrollmentSealKeyVersion = 'seal-v1';
    const unlockKeyVersion = 'unlock-v1';
    await insertSignerWallet({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      walletId,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId,
      orgId: scope.orgId,
      email: 'Register.User@Example.Test',
      otpChannel: 'email_otp',
      sessionHash,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 7;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId,
      userId: providerSubject,
      enrollmentId: 'email-otp-device-enrollment-v1:registration-wallet:google-user',
      enrollmentSealKeyVersion,
      signingRootId: 'project-a:env-a',
      signingRootVersion: 'root-v1',
    });

    const verified = await service.emailOtp.verifyEmailOtpEnrollment({
      providerSubject,
      walletId,
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash,
      appSessionVersion,
      proofEmail: 'register.user@example.test',
      recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u: publicKeyB64u,
      unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified).toMatchObject({
      walletId,
      otpChannel: 'email_otp',
      enrollment: {
        enrollmentSealKeyVersion,
        unlockKeyVersion,
      },
    });

    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId,
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId,
        providerUserId: providerSubject,
        orgId: scope.orgId,
        verifiedEmail: 'register.user@example.test',
        recoveryWrappedEnrollmentEscrowCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        enrollmentSealKeyVersion,
        unlockKeyVersion,
      },
    });
    await expect(
      countActiveRecoveryWrappedEnrollmentEscrows({
        database,
        namespace: scope.namespace,
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        walletId,
      }),
    ).resolves.toBe(EMAIL_OTP_RECOVERY_KEY_COUNT);
    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: providerSubject,
        walletId,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(
      service.emailOtp.verifyEmailOtpEnrollment({
        providerSubject,
        walletId,
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash,
        appSessionVersion,
        proofEmail: 'register.user@example.test',
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service delivers Email OTP through configured provider', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    const provider = new RecordingEmailOtpDeliveryProvider();

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpDeliveryProvider: provider,
      emailOtpProduction: true,
    });

    const challenge = await service.emailOtp.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'email_provider',
      emailHint: 'a***e@e***e.test',
    });
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]).toMatchObject({
      challengeId: challenge.challenge.challengeId,
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      orgId: scope.orgId,
      email: 'alice@example.test',
      emailHint: 'a***e@e***e.test',
      otpChannel: 'email_otp',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
      expiresAtMs: challenge.challenge.expiresAtMs,
    });
    expect(provider.calls[0]?.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service fails closed when Email OTP provider is missing', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpProduction: true,
    });

    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'email_otp_delivery_not_configured',
    });

    const challengeRows = await database
      .prepare(
        `SELECT challenge_id
           FROM email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?`,
      )
      .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
      .all<SqliteJsonRow>();
    expect(challengeRows.results || []).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues and verifies device recovery Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 880,
      updatedAtMs: 920,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpRecoveryKeyAttemptRateLimitMax: 1,
      emailOtpRecoveryKeyAttemptRateLimitWindowMs: 60_000,
    });

    const challenge = await service.emailOtp.createEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.challenge).toMatchObject({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      action: 'wallet_email_otp_device_recovery',
      operation: 'wallet_unlock',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_purpose_mismatch' });

    const verified = await service.emailOtp.verifyEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.recoveryConsumeGrant).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verified.recoveryWrappedEnrollmentEscrows).toHaveLength(1);
    expect(verified.recoveryWrappedEnrollmentEscrows[0]).toMatchObject({
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      enrollmentId: 'enrollment-a',
      nonceB64u: 'nonce-recovery-active',
    });
    expect(
      Object.prototype.hasOwnProperty.call(
        verified.recoveryWrappedEnrollmentEscrows[0],
        'recoveryKeyId',
      ),
    ).toBe(false);
    expect(verified.enrollment).toMatchObject({
      walletId: 'email-wallet.testnet',
      providerUserId: 'google:email-user',
      recoveryWrappedEnrollmentEscrowCount: 3,
    });

    const grantRow = await database
      .prepare(
        `SELECT action
           FROM email_otp_grants
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND grant_token = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        verified.recoveryConsumeGrant,
      )
      .first<SqliteJsonRow>();
    expect(grantRow?.action).toBe('wallet_email_otp_device_recovery');

    const failureReport = await service.emailOtp.recordEmailOtpRecoveryKeyAttemptFailure({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      clientIp: '203.0.113.42',
    });
    expect(failureReport.ok).toBe(true);
    if (!failureReport.ok) throw new Error(failureReport.message);
    expect(failureReport.walletId).toBe('email-wallet.testnet');
    expect(failureReport.recordedAtMs).toBeGreaterThan(0);

    await expect(
      service.emailOtp.recordEmailOtpRecoveryKeyAttemptFailure({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        clientIp: '203.0.113.42',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });

    const consumed = await service.emailOtp.consumeEmailOtpRecoveryKey({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      recoveryKeyId: 'recovery-active',
    });
    expect(consumed.ok).toBe(true);
    if (!consumed.ok) throw new Error(consumed.message);
    expect(consumed).toMatchObject({
      walletId: 'email-wallet.testnet',
      recoveryKeyId: 'recovery-active',
      activeRecoveryWrappedEnrollmentEscrowCount: 0,
    });
    expect(consumed.consumedAtMs).toBeGreaterThan(0);

    const consumedEscrowRow = await database
      .prepare(
        `SELECT recovery_key_status
           FROM email_otp_recovery_wrapped_enrollment_escrows
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'email-wallet.testnet',
        'recovery-active',
      )
      .first<SqliteJsonRow>();
    expect(consumedEscrowRow?.recovery_key_status).toBe('consumed');

    await expect(
      service.emailOtp.consumeEmailOtpRecoveryKey({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        recoveryKeyId: 'recovery-active',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'recovery_consume_grant_invalid_or_expired',
    });

    await expect(
      service.emailOtp.verifyEmailOtpDeviceRecoveryChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service enforces Email OTP challenge rate limits', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpChallengeRateLimitMax: 1,
      emailOtpChallengeRateLimitWindowMs: 60_000,
    });

    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-b',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies Email OTP unlock proofs once', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 1;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    await insertEmailOtpEnrollment({
      database,
      ...scope,
      clientUnlockPublicKeyB64u: publicKeyB64u,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const challenge = await service.walletUnlock.createEmailOtpUnlockChallenge({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.unlockKeyVersion).toBe('unlock-v1');

    const signature65 = await signSecp256k1Recoverable(
      base64UrlDecode(challenge.challengeB64u),
      privateKey32,
    );
    const verified = await service.walletUnlock.verifyEmailOtpUnlockProof({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challengeId,
      unlockProof: {
        publicKey: publicKeyB64u,
        signature: base64UrlEncode(signature65),
      },
    });
    expect(verified).toEqual({
      ok: true,
      verified: true,
      userId: 'email-wallet.testnet',
      walletId: 'email-wallet.testnet',
      unlockKeyVersion: 'unlock-v1',
    });

    await expect(
      service.walletUnlock.verifyEmailOtpUnlockProof({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challengeId,
        unlockProof: {
          publicKey: publicKeyB64u,
          signature: base64UrlEncode(signature65),
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
