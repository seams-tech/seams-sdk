import { expect } from '@playwright/test';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { D1DatabaseLike } from '../../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaDerivationServerBootstrapResponse,
} from '../../../packages/sdk-server-ts/src/core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
} from '../../../packages/sdk-server-ts/src/core/registrationContracts';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1/emailOtp/d1GoogleEmailOtpRegistrationRecords';
import { parseD1RegistrationIntent } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords';
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
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/evmCryptoWasm';
import { ensureSigningSessionSealShamir3PassWasm } from '../../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/shamir3PassWasm';
import {
  shamir3pass_add_lock,
  shamir3pass_destroy_lock_key_handle,
  shamir3pass_generate_lock_key_handle,
  shamir3pass_remove_lock,
} from '../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../../helpers/sqliteD1';

export type SqliteJsonRow = Record<string, unknown>;
export type TestEcdsaClientSharePublicKey =
  WalletRegistrationEcdsaClientBootstrap['derivationClientSharePublicKey33B64u'];
export type TestEcdsaRelayerPublicKey =
  EcdsaDerivationServerBootstrapResponse['publicIdentity']['relayerPublicKey33B64u'];

export const EMAIL_OTP_SERVER_SEAL_KEY_VERSION = 'kek-s-email-otp-test';
export const EMAIL_OTP_SERVER_SEAL_ROOT_SECRET_B64U = Buffer.alloc(32, 0x42).toString('base64url');

export type WebAuthnAssertionFixture = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly privateKey: CryptoKey;
};

export const TEST_COMBINED_NEAR_ACCOUNT_ID =
  '0000000000000000000000000000000000000000000000000000000000000001';

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
  private readonly rejectedSetKeys = new Set<string>();
  private readonly rejectedGetDelKeys = new Set<string>();
  private readonly rejectedDeleteKeys = new Set<string>();
  private readonly lostSetResponsePrefixes = new Set<string>();

  rejectNextSet(key: string): void {
    this.rejectedSetKeys.add(key);
  }

  rejectNextGetDel(key: string): void {
    this.rejectedGetDelKeys.add(key);
  }

  rejectNextDelete(key: string): void {
    this.rejectedDeleteKeys.add(key);
  }

  loseNextSetResponseForPrefix(prefix: string): void {
    this.lostSetResponsePrefixes.add(prefix);
  }

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
    if (this.rejectedSetKeys.delete(key)) {
      return recordingDurableObjectJson({
        ok: false,
        code: 'injected_set_failure',
        message: 'Injected Durable Object set failure',
      });
    }
    this.values.set(key, request.value);
    for (const prefix of this.lostSetResponsePrefixes) {
      if (key.startsWith(prefix)) {
        this.lostSetResponsePrefixes.delete(prefix);
        throw new Error('Injected Durable Object set response loss');
      }
    }
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
    if (this.rejectedGetDelKeys.delete(key)) {
      return recordingDurableObjectJson({
        ok: false,
        code: 'injected_getdel_failure',
        message: 'Injected Durable Object getdel failure',
      });
    }
    const value = this.values.get(key) ?? null;
    this.values.delete(key);
    return recordingDurableObjectJson({ ok: true, value });
  }

  private handleDel(request: Record<string, unknown>): Response {
    const key = String(request.key || '').trim();
    if (this.rejectedDeleteKeys.delete(key)) {
      return recordingDurableObjectJson({
        ok: false,
        code: 'injected_delete_failure',
        message: 'Injected Durable Object delete failure',
      });
    }
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
    registrationPreparationId: prepare.registrationPreparationId,
    derivationClientSharePublicKey33B64u:
      'test-client-share-public-key' as TestEcdsaClientSharePublicKey,
    clientShareRetryCounter: 0,
    contextBinding32B64u: 'test-context-binding-32',
    requestId: prepare.requestId,
    thresholdSessionId: prepare.thresholdSessionId,
    ttlMs: prepare.ttlMs,
    remainingUses: prepare.remainingUses,
    participantIds: prepare.participantIds,
    runtimePolicyScope: prepare.runtimePolicyScope,
  };
}

export function requireSingleEcdsaPrepare(
  ecdsa: WalletRegistrationEcdsaPreparePayload,
): WalletRegistrationEcdsaPreparePayload['prepare'] {
  expect(ecdsa.chainTargets).toHaveLength(1);
  return ecdsa.prepare;
}

export function testEcdsaClientBootstrapTargets(ecdsa: WalletRegistrationEcdsaPreparePayload): {
  chainTarget: WalletRegistrationEcdsaPreparePayload['chainTargets'][number];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
}[] {
  return ecdsa.chainTargets.map((chainTarget) => ({
    chainTarget,
    clientBootstrap: testEcdsaClientBootstrap(ecdsa.prepare),
  }));
}

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

class EmailOtpClientSealFixture {
  constructor(private readonly handle: number) {}

  addLock(ciphertextB64u: string): string {
    return shamir3pass_add_lock(this.handle, ciphertextB64u);
  }

  removeLock(ciphertextB64u: string): string {
    return shamir3pass_remove_lock(this.handle, ciphertextB64u);
  }

  destroy(): void {
    shamir3pass_destroy_lock_key_handle(this.handle);
  }
}

export async function createEmailOtpClientSealFixture(): Promise<EmailOtpClientSealFixture> {
  await ensureSigningSessionSealShamir3PassWasm();
  return new EmailOtpClientSealFixture(shamir3pass_generate_lock_key_handle('rfc2409-group2'));
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

export async function expireD1VersionedJsonClaims(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly recordKeyPrefix: string;
}): Promise<void> {
  await input.database
    .prepare(
      `UPDATE router_ab_yao_versioned_json_records
          SET record_json = json_set(record_json, '$.claimedAtMs', 0)
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_key LIKE ?5`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, `${input.recordKeyPrefix}%`)
    .run();
}

export async function countD1VersionedJsonRecords(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly recordKeyPrefix: string;
}): Promise<number> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM router_ab_yao_versioned_json_records
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_key LIKE ?5`,
    )
    .bind(input.namespace, input.orgId, input.projectId, input.envId, `${input.recordKeyPrefix}%`)
    .first<{ readonly count: number }>();
  return Number(row?.count || 0);
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

function emailOtpRecoveryEscrowRecord(input: {
  readonly orgId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
}) {
  const walletId = 'email-wallet.testnet';
  const timestamps =
    input.recoveryKeyStatus === 'consumed'
      ? { consumedAtMs: input.updatedAtMs }
      : input.recoveryKeyStatus === 'revoked'
        ? { revokedAtMs: input.updatedAtMs }
        : {};
  return {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: 'chacha20poly1305-hkdf-sha256-v1',
    secretKind: 'email_otp_device_enrollment_escrow',
    escrowKind: 'recovery_wrapped_enrollment_escrow',
    walletId,
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
    nonceB64u: 'nonce-email-otp-recovery',
    wrappedDeviceEnrollmentEscrowB64u: 'wrapped-email-otp-recovery',
    aadHashB64u: 'hash-email-otp-recovery',
    issuedAtMs: input.issuedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...timestamps,
  };
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
    action: 'wallet_email_otp_factor_release',
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: Date.now() + 60_000,
  };
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
