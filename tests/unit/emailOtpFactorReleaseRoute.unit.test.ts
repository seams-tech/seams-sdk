import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parsePrincipalId, parseTenantId } from '@shared/authorization/capabilityKinds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { sealEmailOtpFactorSecretForWorker } from '@server/router/domains/emailOtp/emailOtpRouteHandlers';
import type {
  RouterApiServiceBag,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '@server/router/framework/authServicePort';
import type { FetchRouterApiContext } from '@server/router/transport/fetch/fetchRouter.types';
import { handleWalletEmailOtpFactorRelease } from '@server/router/transport/fetch/routes/sessions';
import { buildExactWalletSessionAuthorizationFixture } from './helpers/exactWalletSessionAuthorization.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const FACTOR_RELEASE_AAD_DOMAIN = 'seams/email-otp/factor-release/v1';
const EXACT_WALLET_ID = 'wallet-a';
const EXACT_EMAIL = 'user@example.com';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

async function exactEmailOtpAdmission(input: {
  readonly label: string;
  readonly emailHashHex: string;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
}): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const walletAuthMethodId = required(parseWalletAuthMethodId(`wallet-auth-method:${input.label}`));
  const authorityFixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: input.label,
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: input.keyFamily,
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: EXACT_WALLET_ID,
      authorityId: `authority:${input.label}`,
      walletAuthMethodId: String(walletAuthMethodId),
      rpId: 'wallet.example.test',
    },
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId: authorityFixture.authority.walletId,
    walletAuthorityId: authorityFixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: input.emailHashHex,
    registrationAuthorityId: `registration-authority:${input.label}`,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  if (authMethod.kind !== 'email_otp' || authMethod.status !== 'active') {
    throw new Error('Email OTP auth-method fixture changed branch');
  }
  return {
    authorization: buildExactWalletSessionAuthorizationFixture({
      label: input.label,
      tenantId: required(parseTenantId('tenant:email-otp-factor-release')),
      principalId: required(parsePrincipalId(`principal:${input.label}`)),
      authority: authorityFixture.authority,
      walletAuthMethodId,
      issuedAtMs: 300,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 10,
    }),
    authority: authorityFixture.authority,
    authMethod,
    retiredAtMs: null,
  };
}

class WalletSessionFactorReleaseHarness {
  removeSealCalls = 0;

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
    readonly factorSecret32B64u: string,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async readEnrollment() {
    return {
      ok: true as const,
      enrollment: {
        version: 'email_otp_wallet_enrollment_v1' as const,
        walletId: EXACT_WALLET_ID,
        orgId: 'org-a',
        providerUserId: 'google:provider-user',
        verifiedEmail: EXACT_EMAIL,
        enrollmentId: 'email_otp:wallet-a:google:provider-user',
        enrollmentVersion: 'v1',
        enrollmentSealKeyVersion: 'seal-v1',
        clientUnlockPublicKeyB64u: 'client-unlock-public-key',
        unlockKeyVersion: 'unlock-v1',
        serverSealedFactorCiphertextB64u: 'stored-server-sealed-factor',
        createdAtMs: 1,
        updatedAtMs: 2,
      },
    };
  }

  async removeServerSeal() {
    this.removeSealCalls += 1;
    return {
      ok: true as const,
      ciphertext: this.factorSecret32B64u,
      enrollmentSealKeyVersion: 'seal-v1',
    };
  }

  service(): RouterApiServiceBag {
    return {
      authorizedOperations: { tenantId: 'org-a' },
      authorizationSessions: {
        tenantId: 'tenant:email-otp-factor-release',
        readWalletSessionAuthorizationV2ByOperationCredential: this.readExactAdmission.bind(this),
      },
      emailOtp: {
        readActiveEmailOtpEnrollment: this.readEnrollment.bind(this),
        removeEmailOtpServerSeal: this.removeServerSeal.bind(this),
      },
    } as unknown as RouterApiServiceBag;
  }
}

async function workerPublicKey65B64u(): Promise<string> {
  const workerKeyPair = (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  )) as CryptoKeyPair;
  return base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', workerKeyPair.publicKey)),
  );
}

async function invokeWalletSessionFactorRelease(
  harness: WalletSessionFactorReleaseHarness,
): Promise<Response> {
  const url = new URL('https://router.example.test/wallet/email-otp/factor-release');
  const request = new Request(url, {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-operation-credential',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      kind: 'wallet_session',
      walletId: EXACT_WALLET_ID,
      workerEphemeralPublicKey65B64u: await workerPublicKey65B64u(),
    }),
  });
  const response = await handleWalletEmailOtpFactorRelease({
    request,
    url,
    pathname: url.pathname,
    method: request.method,
    runtime: { kind: 'inline' },
    service: harness.service(),
    opts: {},
    logger: {},
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext);
  if (!response) throw new Error('Email OTP factor-release route did not match');
  return response;
}

function factorReleaseAad(): Uint8Array {
  return new TextEncoder().encode(
    [
      FACTOR_RELEASE_AAD_DOMAIN,
      'wallet-a',
      'email_otp:wallet-a:google:provider-user',
      'seal-v1',
      'challenge-1',
    ].join('\0'),
  );
}

test('Email OTP factor release encrypts the stored factor to the requesting worker', async () => {
  const factorSecret32 = new Uint8Array(32).fill(7);
  const workerKeyPair = (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  )) as CryptoKeyPair;
  const workerPublicKey65 = new Uint8Array(
    await crypto.subtle.exportKey('raw', workerKeyPair.publicKey),
  );

  const response = await sealEmailOtpFactorSecretForWorker({
    factorSecret32B64u: base64UrlEncode(factorSecret32),
    workerEphemeralPublicKey65B64u: base64UrlEncode(workerPublicKey65),
    walletId: 'wallet-a',
    enrollmentId: 'email_otp:wallet-a:google:provider-user',
    enrollmentSealKeyVersion: 'seal-v1',
    challengeId: 'challenge-1',
  });

  expect(response.ok).toBe(true);
  if (!response.ok) throw new Error(response.message);
  const body = response;
  expect(JSON.stringify(body)).not.toContain(base64UrlEncode(factorSecret32));
  const serverPublicKey = await crypto.subtle.importKey(
    'raw',
    base64UrlDecode(String(body.serverEphemeralPublicKey65B64u)),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPublicKey },
    workerKeyPair.privateKey,
    256,
  );
  const decryptionKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64UrlDecode(String(body.nonce12B64u)),
        additionalData: factorReleaseAad(),
        tagLength: 128,
      },
      decryptionKey,
      base64UrlDecode(String(body.ciphertextB64u)),
    ),
  );
  expect(decrypted).toEqual(factorSecret32);
});

test('Wallet Session factor release admits the exact Email OTP method and Ed25519 subject', async () => {
  const admission = await exactEmailOtpAdmission({
    label: 'email-otp-factor-release-exact',
    emailHashHex: await sha256HexUtf8(EXACT_EMAIL),
    keyFamily: 'ed25519',
  });
  const harness = new WalletSessionFactorReleaseHarness(
    admission,
    base64UrlEncode(new Uint8Array(32).fill(9)),
  );

  const response = await invokeWalletSessionFactorRelease(harness);
  const body = (await response.json()) as { readonly challengeId?: string };

  expect(response.status).toBe(200);
  expect(body.challengeId).toBe(
    `wallet-session:${admission.authorization.session.walletSessionId}`,
  );
  expect(harness.removeSealCalls).toBe(1);
});

test('Wallet Session factor release rejects a different Email OTP enrollment before unsealing', async () => {
  const admission = await exactEmailOtpAdmission({
    label: 'email-otp-factor-release-other-enrollment',
    emailHashHex: 'f'.repeat(64),
    keyFamily: 'ed25519',
  });
  const harness = new WalletSessionFactorReleaseHarness(
    admission,
    base64UrlEncode(new Uint8Array(32).fill(9)),
  );

  const response = await invokeWalletSessionFactorRelease(harness);

  expect(response.status).toBe(401);
  expect(harness.removeSealCalls).toBe(0);
});

test('Wallet Session factor release rejects an exact session without an Ed25519 sign subject', async () => {
  const admission = await exactEmailOtpAdmission({
    label: 'email-otp-factor-release-ecdsa-only',
    emailHashHex: await sha256HexUtf8(EXACT_EMAIL),
    keyFamily: 'ecdsa_secp256k1',
  });
  const harness = new WalletSessionFactorReleaseHarness(
    admission,
    base64UrlEncode(new Uint8Array(32).fill(9)),
  );

  const response = await invokeWalletSessionFactorRelease(harness);

  expect(response.status).toBe(401);
  expect(harness.removeSealCalls).toBe(0);
});

test('Wallet Session factor release rejects missing exact state without legacy lookup', async () => {
  const harness = new WalletSessionFactorReleaseHarness(
    null,
    base64UrlEncode(new Uint8Array(32).fill(9)),
  );

  const response = await invokeWalletSessionFactorRelease(harness);

  expect(response.status).toBe(401);
  expect(harness.removeSealCalls).toBe(0);
});
