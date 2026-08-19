/**
 * Refactor 103 Phase 6 — server boundaries of the Email OTP target factor.
 *
 * These tests own the invariants the composed flow never isolates: the derived
 * per-enrollment owner identity, approval provenance against the wallet's base
 * factor, the one-time verification grant's exact bindings, and revocation
 * that retires one linked device without touching the base factor or its
 * siblings.
 */
import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
} from '@shared/device-linking/parsers';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking/digests';
import {
  buildLinkedOwnerEmailOtpAuthBindingV1,
  linkedOwnerEmailOtpBaseAuthMethodIdV1,
} from '@shared/device-linking/ownerAuthBinding';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '@shared/signing-lanes/ids';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
import { parseWalletAuthMethodId, parseWalletId } from '@shared/utils/domainIds';
import {
  computeLinkedDeviceEmailOtpAuthorityDigestV1,
  computeLinkedDeviceEmailOtpGrantTokenDigestV1,
  parseLinkedDeviceEmailOtpGrantRecordV1,
  type LinkedDeviceEmailOtpGrantRecordV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceEmailOtpGrant';
import { admitLinkedOwnerEnrollmentProvenanceV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedOwnerEnrollmentProvenance';
import {
  D1LinkedDeviceEmailOtpGrantStoreV1,
  createLinkedDeviceEmailOtpRegistrationPortV1,
  deriveLinkedDeviceEmailOtpOwnerAuthMethodIdV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceEmailOtpGrantStore';
import {
  D1LinkedDeviceOwnerAuthBindingStoreV1,
  assertOwnerAuthBindingBatchApplied,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore';
import { CloudflareD1WalletAuthMethodService } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService';
import type { D1LinkedDeviceSessionScopeV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import type {
  D1DatabaseLike,
  D1ResultLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  buildR103DeviceLinkFixture,
  buildR103EmailOtpTargetCredentialFixture,
  buildR103TargetPreparationFixture,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { buildActiveEmailOtpWalletAuthMethodFixtureV1 } from './helpers/linkedOwnerAuthBinding.fixtures';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};

const NOW_MS = 1_800_000_000_000;
const EMAIL_HASH_HEX = 'ab'.repeat(32);
const WALLET_ID = 'wallet:r103';

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

async function migratedDatabase(): Promise<D1DatabaseLike> {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return temporary.database;
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function emailFixture(input: { readonly deviceId?: string; readonly enrollmentId?: string } = {}) {
  return buildR103DeviceLinkFixture({
    targetFactor: { kind: 'email_otp' },
    ...(input.deviceId === undefined ? {} : { deviceId: input.deviceId }),
    ...(input.enrollmentId === undefined ? {} : { enrollmentId: input.enrollmentId }),
  });
}

test('two linked devices sharing one base email receive distinct derived authorities', async () => {
  const walletId = required(parseWalletId(WALLET_ID));
  const base = linkedOwnerEmailOtpBaseAuthMethodIdV1({
    walletId,
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  const deviceA = deriveLinkedDeviceEmailOtpOwnerAuthMethodIdV1({
    walletId,
    enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:a')),
    deviceId: required(parseLinkedDeviceId('device:a')),
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  const deviceB = deriveLinkedDeviceEmailOtpOwnerAuthMethodIdV1({
    walletId,
    enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:b')),
    deviceId: required(parseLinkedDeviceId('device:b')),
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  expect(String(deviceA)).not.toBe(String(deviceB));
  expect(String(deviceA)).not.toBe(String(base));
  expect(String(deviceB)).not.toBe(String(base));

  const digestA = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
    walletId,
    enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:a')),
    deviceId: required(parseLinkedDeviceId('device:a')),
    linkedOwnerAuthMethodId: deviceA,
    baseWalletAuthMethodId: base,
  });
  const digestB = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
    walletId,
    enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:b')),
    deviceId: required(parseLinkedDeviceId('device:b')),
    linkedOwnerAuthMethodId: deviceB,
    baseWalletAuthMethodId: base,
  });
  expect(String(digestA)).not.toBe(String(digestB));
});

test('an email approval is refused when the wallet has no active base factor and admitted against it', async () => {
  const fixture = emailFixture();
  const ceremonies = {
    getAddAuthMethodCeremony: async () => {
      throw new Error('email approvals never read the passkey ceremony store');
    },
  };

  const withoutFactor = await admitLinkedOwnerEnrollmentProvenanceV1({
    approval: fixture.approval,
    ceremonies,
    emailOtpBaseFactors: { readActiveEmailOtpBaseFactorV1: async () => null },
    requestedAtMs: 3_000,
  });
  expect(withoutFactor).toEqual({ ok: false, reason: 'email_otp_base_factor_unavailable' });

  if (fixture.approval.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1') {
    throw new Error('expected an email owner enrollment fixture');
  }
  const ceremony = fixture.approval.ownerEnrollment;
  const matching = await admitLinkedOwnerEnrollmentProvenanceV1({
    approval: fixture.approval,
    ceremonies,
    emailOtpBaseFactors: {
      readActiveEmailOtpBaseFactorV1: async () => ({
        baseWalletAuthMethodId: ceremony.baseWalletAuthMethodId,
        maskedEmailHint: ceremony.maskedEmailHint,
      }),
    },
    requestedAtMs: 3_000,
  });
  expect(matching).toEqual({ ok: true });

  const substituted = await admitLinkedOwnerEnrollmentProvenanceV1({
    approval: fixture.approval,
    ceremonies,
    emailOtpBaseFactors: {
      readActiveEmailOtpBaseFactorV1: async () => ({
        baseWalletAuthMethodId: required(
          parseWalletAuthMethodId(`email_otp:${WALLET_ID}:${'cd'.repeat(32)}`),
        ),
        maskedEmailHint: ceremony.maskedEmailHint,
      }),
    },
    requestedAtMs: 3_000,
  });
  expect(substituted).toEqual({ ok: false, reason: 'email_otp_base_factor_does_not_match' });
});

type GrantScenario = {
  readonly database: D1DatabaseLike;
  readonly grants: D1LinkedDeviceEmailOtpGrantStoreV1;
  readonly port: ReturnType<typeof createLinkedDeviceEmailOtpRegistrationPortV1>;
  readonly fixture: ReturnType<typeof emailFixture>;
  readonly preparation: Awaited<
    ReturnType<typeof buildR103TargetPreparationFixture>
  >;
  readonly grantRecord: LinkedDeviceEmailOtpGrantRecordV1;
  readonly grantToken: string;
  readonly registration: Awaited<
    ReturnType<typeof buildR103EmailOtpTargetCredentialFixture>
  >['registration'];
};

async function grantScenario(): Promise<GrantScenario> {
  const database = await migratedDatabase();
  const fixture = emailFixture();
  const preparation = await buildR103TargetPreparationFixture(fixture);
  const targetPreparationDigestB64u = parseDigestB64u(
    await computeLinkedDeviceTargetPreparationDigestV1(preparation),
  );
  const approval = fixture.approval;
  const linkedOwnerAuthMethodId = deriveLinkedDeviceEmailOtpOwnerAuthMethodIdV1({
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  const baseWalletAuthMethodId = linkedOwnerEmailOtpBaseAuthMethodIdV1({
    walletId: approval.walletId,
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  const authorityDigestB64u = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    linkedOwnerAuthMethodId,
    baseWalletAuthMethodId,
  });
  const grantToken = base64UrlEncode(new Uint8Array(32).fill(21));
  const grantRecord = parseLinkedDeviceEmailOtpGrantRecordV1({
    kind: 'linked_device_email_otp_grant_record_v1',
    grantId: 'grant:r103p6',
    grantTokenDigestB64u: await computeLinkedDeviceEmailOtpGrantTokenDigestV1(grantToken),
    walletId: approval.walletId,
    linkSessionId: approval.linkSessionId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    targetFactor: { kind: 'email_otp' },
    targetPreparationDigestB64u,
    baseWalletAuthMethodId,
    linkedOwnerAuthMethodId,
    authorityDigestB64u,
    challengeId: 'challenge:r103p6',
    state: { kind: 'issued' },
    issuedAtMs: NOW_MS,
    expiresAtMs: NOW_MS + 60_000,
  });
  const grants = new D1LinkedDeviceEmailOtpGrantStoreV1({ database, scope });
  const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({ database, scope });
  const port = createLinkedDeviceEmailOtpRegistrationPortV1({
    grants,
    bindingWriter: bindingStore,
    resolveBaseEmailOtpFactorV1: async () => ({
      emailHashHex: EMAIL_HASH_HEX,
      registrationAuthorityId: 'google',
    }),
    tenantId: required(parseTenantId('tenant:r103p6')),
  });
  const targetCredential = await buildR103EmailOtpTargetCredentialFixture({
    fixture,
    verificationGrant: {
      kind: 'linked_device_email_otp_verification_grant_v1',
      grantId: grantRecord.grantId,
      grantToken,
      challengeId: grantRecord.challengeId,
      linkSessionId: approval.linkSessionId,
      walletId: approval.walletId,
      enrollmentId: approval.enrollmentId,
      deviceId: approval.deviceId,
      targetPreparationDigestB64u,
      baseWalletAuthMethodId,
      linkedOwnerAuthMethodId,
      authorityDigestB64u,
      issuedAtMs: grantRecord.issuedAtMs,
      expiresAtMs: grantRecord.expiresAtMs,
    },
    registeredAtMs: NOW_MS + 5,
  });
  return {
    database,
    grants,
    port,
    fixture,
    preparation,
    grantRecord,
    grantToken,
    registration: targetCredential.registration,
  };
}

test('the verification grant admits exactly its own binding and refuses every substitution', async () => {
  const scenario = await grantScenario();
  await scenario.grants.issueV1(scenario.grantRecord);

  const verified = await scenario.port.verifyRegistrationGrantV1({
    preparation: scenario.preparation,
    registration: scenario.registration,
    requestedAtMs: NOW_MS + 10,
  });
  expect(verified.kind).toBe('verified');
  if (verified.kind !== 'verified') throw new Error('expected verification');
  expect(String(verified.grant.linkedOwnerAuthMethodId)).toBe(
    String(scenario.grantRecord.linkedOwnerAuthMethodId),
  );

  // Wrong bearer token: same grant id, different secret.
  const wrongToken = {
    ...scenario.registration,
    emailOtpVerificationGrant: {
      ...scenario.registration.emailOtpVerificationGrant!,
      grantToken: base64UrlEncode(new Uint8Array(32).fill(9)),
    },
  } as typeof scenario.registration;
  expect(
    await scenario.port.verifyRegistrationGrantV1({
      preparation: scenario.preparation,
      registration: wrongToken,
      requestedAtMs: NOW_MS + 10,
    }),
  ).toEqual({ kind: 'rejected', message: 'email OTP verification grant token is invalid' });

  // A Passkey artifact must fail against an Email OTP session before anything
  // is created.
  const passkeyFixture = await buildR103TargetCredentialFixture(buildR103DeviceLinkFixture());
  expect(
    (
      await scenario.port.verifyRegistrationGrantV1({
        preparation: scenario.preparation,
        registration: passkeyFixture.registration,
        requestedAtMs: NOW_MS + 10,
      })
    ).kind,
  ).toBe('rejected');

  // Unknown grant id.
  const unknownGrant = {
    ...scenario.registration,
    emailOtpVerificationGrant: {
      ...scenario.registration.emailOtpVerificationGrant!,
      grantId: 'grant:someone-else',
    },
  } as typeof scenario.registration;
  expect(
    await scenario.port.verifyRegistrationGrantV1({
      preparation: scenario.preparation,
      registration: unknownGrant,
      requestedAtMs: NOW_MS + 10,
    }),
  ).toEqual({ kind: 'rejected', message: 'email OTP verification grant is unknown' });

  // Expired grant.
  expect(
    await scenario.port.verifyRegistrationGrantV1({
      preparation: scenario.preparation,
      registration: scenario.registration,
      requestedAtMs: scenario.grantRecord.expiresAtMs,
    }),
  ).toEqual({ kind: 'rejected', message: 'email OTP verification grant is expired' });
});

test('a grant bound to another device or enrollment refuses this completion', async () => {
  const scenario = await grantScenario();
  const otherDevice = parseLinkedDeviceEmailOtpGrantRecordV1({
    ...scenario.grantRecord,
    deviceId: required(parseLinkedDeviceId('device:intruder')),
  });
  await scenario.grants.issueV1(otherDevice);
  expect(
    await scenario.port.verifyRegistrationGrantV1({
      preparation: scenario.preparation,
      registration: scenario.registration,
      requestedAtMs: NOW_MS + 10,
    }),
  ).toEqual({
    kind: 'rejected',
    message: 'email OTP verification grant is bound to a different enrollment',
  });
});

test('a grant is consumed exactly once, and a consumed grant admits nothing', async () => {
  const scenario = await grantScenario();
  await scenario.grants.issueV1(scenario.grantRecord);

  const consume = scenario.grants.buildConsumeStatementsV1({
    grantId: scenario.grantRecord.grantId,
    consumedAtMs: NOW_MS + 20,
  });
  await scenario.database.batch<D1ResultLike>([...consume]);

  const stored = await scenario.grants.readByIdV1(scenario.grantRecord.grantId);
  expect(stored?.state).toEqual({ kind: 'consumed', consumedAtMs: NOW_MS + 20 });

  // The CAS guard takes the whole batch down on a second consumption.
  await expect(
    scenario.database.batch<D1ResultLike>([
      ...scenario.grants.buildConsumeStatementsV1({
        grantId: scenario.grantRecord.grantId,
        consumedAtMs: NOW_MS + 30,
      }),
    ]),
  ).rejects.toThrow();

  expect(
    await scenario.port.verifyRegistrationGrantV1({
      preparation: scenario.preparation,
      registration: scenario.registration,
      requestedAtMs: NOW_MS + 40,
    }),
  ).toEqual({ kind: 'rejected', message: 'email OTP verification grant is already consumed' });
});

test('revoking one linked email device leaves the base factor and its sibling active', async () => {
  const database = await migratedDatabase();
  const walletId = required(parseWalletId(WALLET_ID));
  const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({ database, scope });
  const baseWalletAuthMethodId = linkedOwnerEmailOtpBaseAuthMethodIdV1({
    walletId,
    emailHashHex: EMAIL_HASH_HEX,
    registrationAuthorityId: 'google',
  });
  const walletAuthMethods = new D1WalletAuthMethodStore({ database, ...scope });
  await walletAuthMethods.put(
    buildActiveEmailOtpWalletAuthMethodFixtureV1({
      walletId: WALLET_ID,
      emailHashHex: EMAIL_HASH_HEX,
      registrationAuthorityId: 'google',
      createdAtMs: NOW_MS,
    }),
  );

  const bindingFor = (enrollment: string, device: string) =>
    buildLinkedOwnerEmailOtpAuthBindingV1({
      tenantId: required(parseTenantId('tenant:r103p6')),
      walletId,
      enrollmentId: required(parseLinkedDeviceEnrollmentId(enrollment)),
      deviceId: required(parseLinkedDeviceId(device)),
      keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7))),
      activatedAtMs: NOW_MS,
      emailHashHex: EMAIL_HASH_HEX,
      registrationAuthorityId: 'google',
      baseWalletAuthMethodId,
    });
  const deviceA = bindingFor('enrollment:a', 'device:a');
  const deviceB = bindingFor('enrollment:b', 'device:b');
  assertOwnerAuthBindingBatchApplied(
    await database.batch<D1ResultLike>([
      bindingStore.buildInsertV1(deviceA).statement,
      bindingStore.buildInsertV1(deviceB).statement,
    ]),
    2,
  );

  const revokedSessions: string[] = [];
  const service = new CloudflareD1WalletAuthMethodService({
    emailOtpChallengeVerifier: undefined as never,
    getRegistrationCeremonyIntentStore: () => {
      throw new Error('unused');
    },
    getWalletAuthMethodStore: () => walletAuthMethods,
    googleEmailOtpRegistrationAttempts: undefined as never,
    passkeyCustodyEnvelopes: undefined as never,
    sha256Bytes: async () => new Uint8Array(32),
    webAuthnStore: undefined as never,
    linkedDeviceOwnerAuthBindingStore: bindingStore,
    revokeOwnerWalletSessions: async (input) => {
      revokedSessions.push(String(input.walletAuthMethodId));
    },
  });

  const revoked = await service.revokeWalletAuthMethodForOwnerSessionV1({
    walletId,
    walletAuthMethodId: deviceA.walletAuthMethodId,
    requestedAtMs: NOW_MS + 1_000,
  });
  expect(revoked).toEqual({ kind: 'applied' });
  expect(revokedSessions).toEqual([String(deviceA.walletAuthMethodId)]);

  const storedA = await bindingStore.readByEnrollmentV1({
    walletId,
    enrollmentId: deviceA.enrollmentId,
  });
  expect(storedA?.lifecycle.state).toBe('revoked');
  expect(storedA?.revocationEpoch).toBe(1);

  const storedB = await bindingStore.readByEnrollmentV1({
    walletId,
    enrollmentId: deviceB.enrollmentId,
  });
  expect(storedB?.lifecycle.state).toBe('active');

  const baseRow = await database
    .prepare(
      `SELECT status FROM wallet_auth_methods
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_auth_method_id = ?5`,
    )
    .bind(...[scope.namespace, scope.orgId, scope.projectId, scope.envId], String(baseWalletAuthMethodId))
    .first<{ readonly status?: unknown }>();
  expect(baseRow?.status).toBe('active');

  const replayed = await service.revokeWalletAuthMethodForOwnerSessionV1({
    walletId,
    walletAuthMethodId: deviceA.walletAuthMethodId,
    requestedAtMs: NOW_MS + 2_000,
  });
  expect(replayed).toEqual({ kind: 'replayed' });
});

// The approval fixture parser correlates the ceremony with the factor, so a
// cross-branch approval is unrepresentable end to end; assert it here so the
// invariant survives fixture refactors.
test('a passkey ceremony cannot ride an email approval', async () => {
  const passkey = buildR103DeviceLinkFixture();
  const email = emailFixture();
  expect(() =>
    buildLinkedDeviceApprovalV1({
      ...email.approval,
      ownerEnrollment: passkey.approval.ownerEnrollment,
    } as never),
  ).toThrow();
});
