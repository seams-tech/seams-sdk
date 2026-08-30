import {
  isActiveRecoveredWalletAuthorityV1,
  parseWalletAuthorityV1,
  walletAuthorityDigestsMatchV1,
  type ActiveRecoveredWalletAuthorityV1,
} from '../authorization/walletAuthority';
import { parseDeviceId, type DeviceId } from '../authorization/capabilityKinds';
import {
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type EmailOtpProviderUserId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WalletRecoveryOperationId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '../utils/domainIds';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../utils/registrationIntent';

export type WalletRecoveryEmailOtpEnrollmentReferenceV1 = {
  readonly kind: 'email_otp_enrollment_reference_v1';
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
};

type WalletRecoveryCommittedProjectionCommonV1 = {
  readonly version: 'wallet_recovery_committed_projection_v1';
  readonly storeVersion: string;
  readonly walletId: WalletId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly authority: ActiveRecoveredWalletAuthorityV1;
};

export type WalletRecoveryCommittedProjectionV1 =
  | (WalletRecoveryCommittedProjectionCommonV1 & {
      readonly kind: 'passkey';
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'passkey'; readonly status: 'active' }
      >;
      readonly target: {
        readonly kind: 'passkey';
        readonly rpId: WebAuthnRpId;
        readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      };
    })
  | (WalletRecoveryCommittedProjectionCommonV1 & {
      readonly kind: 'google_email_otp';
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'email_otp'; readonly status: 'active' }
      >;
      readonly target: {
        readonly kind: 'google_email_otp';
        readonly provider: 'google';
        readonly providerSubject: EmailOtpProviderUserId;
        readonly emailHashHex: string;
        readonly registrationAuthorityId: string;
        readonly enrollment: WalletRecoveryEmailOtpEnrollmentReferenceV1;
      };
    });

export type WalletRecoveryCommittedProjectionExpectationV1 =
  | {
      readonly kind: 'passkey';
      readonly walletId: WalletId;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly walletId: WalletId;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly providerSubject: EmailOtpProviderUserId;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly enrollment: WalletRecoveryEmailOtpEnrollmentReferenceV1;
    };

export type WalletRecoveryCommittedProjectionBuilderInputV1 =
  | {
      readonly kind: 'passkey';
      readonly storeVersion: string;
      readonly walletId: WalletId;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly authority: ActiveRecoveredWalletAuthorityV1;
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'passkey'; readonly status: 'active' }
      >;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly storeVersion: string;
      readonly walletId: WalletId;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly authority: ActiveRecoveredWalletAuthorityV1;
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'email_otp'; readonly status: 'active' }
      >;
      readonly providerSubject: EmailOtpProviderUserId;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly enrollment: WalletRecoveryEmailOtpEnrollmentReferenceV1;
    };

export function buildWalletRecoveryCommittedProjectionV1(
  input: Extract<WalletRecoveryCommittedProjectionBuilderInputV1, { readonly kind: 'passkey' }>,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>;
export function buildWalletRecoveryCommittedProjectionV1(
  input: Extract<
    WalletRecoveryCommittedProjectionBuilderInputV1,
    { readonly kind: 'google_email_otp' }
  >,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'google_email_otp' }>;
export function buildWalletRecoveryCommittedProjectionV1(
  input: WalletRecoveryCommittedProjectionBuilderInputV1,
): WalletRecoveryCommittedProjectionV1 {
  if (input.kind === 'passkey') {
    return buildPasskeyProjection(input);
  }
  return buildGoogleEmailOtpProjection(input);
}

function buildPasskeyProjection(
  input: Extract<WalletRecoveryCommittedProjectionBuilderInputV1, { readonly kind: 'passkey' }>,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }> {
  const common = {
    version: 'wallet_recovery_committed_projection_v1' as const,
    storeVersion: requireNonEmptyString(input.storeVersion, 'storeVersion'),
    walletId: input.walletId,
    recoveryOperationId: input.recoveryOperationId,
    targetDeviceId: input.targetDeviceId,
    targetAuthorityId: input.targetAuthorityId,
    targetWalletAuthMethodId: input.targetWalletAuthMethodId,
    authority: input.authority,
  };
  const projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }> = {
    ...common,
    kind: 'passkey',
    authMethod: input.authMethod,
    target: {
      kind: 'passkey',
      rpId: input.authMethod.rpId,
      credentialIdB64u: input.authMethod.credentialIdB64u,
    },
  };
  assertProjectionShape(projection);
  return projection;
}

function buildGoogleEmailOtpProjection(
  input: Extract<
    WalletRecoveryCommittedProjectionBuilderInputV1,
    { readonly kind: 'google_email_otp' }
  >,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'google_email_otp' }> {
  const common = {
    version: 'wallet_recovery_committed_projection_v1' as const,
    storeVersion: requireNonEmptyString(input.storeVersion, 'storeVersion'),
    walletId: input.walletId,
    recoveryOperationId: input.recoveryOperationId,
    targetDeviceId: input.targetDeviceId,
    targetAuthorityId: input.targetAuthorityId,
    targetWalletAuthMethodId: input.targetWalletAuthMethodId,
    authority: input.authority,
  };
  const projection: Extract<
    WalletRecoveryCommittedProjectionV1,
    { readonly kind: 'google_email_otp' }
  > = {
    ...common,
    kind: 'google_email_otp',
    authMethod: input.authMethod,
    target: {
      kind: 'google_email_otp',
      provider: 'google',
      providerSubject: input.providerSubject,
      emailHashHex: requireEmailHash(input.emailHashHex),
      registrationAuthorityId: requireNonEmptyString(
        input.registrationAuthorityId,
        'registrationAuthorityId',
      ),
      enrollment: buildEnrollmentReference(input.enrollment),
    },
  };
  assertProjectionShape(projection);
  return projection;
}

export async function parseWalletRecoveryCommittedProjectionV1(
  raw: unknown,
  expected: WalletRecoveryCommittedProjectionExpectationV1,
): Promise<WalletRecoveryCommittedProjectionV1> {
  const record = requireRecord(raw, 'wallet recovery committed projection');
  requireExactFields(
    record,
    [
      'version',
      'kind',
      'storeVersion',
      'walletId',
      'recoveryOperationId',
      'targetDeviceId',
      'targetAuthorityId',
      'targetWalletAuthMethodId',
      'authority',
      'authMethod',
      'target',
    ],
    'wallet recovery committed projection',
  );
  if (record.version !== 'wallet_recovery_committed_projection_v1') {
    throw new Error('wallet recovery committed projection version is invalid');
  }
  if (record.kind !== expected.kind) {
    throw new Error('wallet recovery committed projection target changed');
  }
  const walletId = requireParsed(parseWalletId(record.walletId), 'walletId');
  const recoveryOperationId = requireParsed(
    parseWalletRecoveryOperationId(record.recoveryOperationId),
    'recoveryOperationId',
  );
  const targetDeviceId = requireParsed(parseDeviceId(record.targetDeviceId), 'targetDeviceId');
  const targetAuthorityId = requireParsed(
    parseWalletAuthorityId(record.targetAuthorityId),
    'targetAuthorityId',
  );
  const targetWalletAuthMethodId = requireParsed(
    parseWalletAuthMethodId(record.targetWalletAuthMethodId),
    'targetWalletAuthMethodId',
  );
  const authorityResult = parseWalletAuthorityV1(record.authority);
  if (!authorityResult.ok) throw new Error('wallet recovery authority projection is invalid');
  const authority = authorityResult.value;
  if (
    authority.state !== 'active' ||
    !isActiveRecoveredWalletAuthorityV1(authority) ||
    !(await walletAuthorityDigestsMatchV1(authority))
  ) {
    throw new Error('wallet recovery authority projection digest or lifecycle is invalid');
  }
  const authMethod = parseWalletAuthMethodRecordV2(record.authMethod);
  if (!authMethod || authMethod.status !== 'active') {
    throw new Error('wallet recovery auth method projection is invalid');
  }
  const common = {
    version: 'wallet_recovery_committed_projection_v1' as const,
    storeVersion: requireNonEmptyString(record.storeVersion, 'storeVersion'),
    walletId,
    recoveryOperationId,
    targetDeviceId,
    targetAuthorityId,
    targetWalletAuthMethodId,
    authority,
  };
  if (expected.kind === 'passkey') {
    if (authMethod.kind !== 'passkey') {
      throw new Error('wallet recovery target method family changed');
    }
    const target = parsePasskeyTarget(record.target);
    const projection: WalletRecoveryCommittedProjectionV1 = {
      ...common,
      kind: 'passkey',
      authMethod,
      target,
    };
    assertExpectedIdentity(projection, expected);
    assertProjectionShape(projection);
    return projection;
  }
  if (authMethod.kind !== 'email_otp') {
    throw new Error('wallet recovery target method family changed');
  }
  const target = parseGoogleEmailOtpTarget(record.target);
  const projection: WalletRecoveryCommittedProjectionV1 = {
    ...common,
    kind: 'google_email_otp',
    authMethod,
    target,
  };
  assertExpectedIdentity(projection, expected);
  assertProjectionShape(projection);
  return projection;
}

function parsePasskeyTarget(
  raw: unknown,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>['target'] {
  const record = requireRecord(raw, 'wallet recovery passkey target');
  requireExactFields(
    record,
    ['kind', 'rpId', 'credentialIdB64u'],
    'wallet recovery passkey target',
  );
  if (record.kind !== 'passkey') throw new Error('wallet recovery passkey target is invalid');
  return {
    kind: 'passkey',
    rpId: requireParsed(parseWebAuthnRpId(record.rpId), 'target.rpId'),
    credentialIdB64u: requireParsed(
      parseWebAuthnCredentialIdB64u(record.credentialIdB64u),
      'target.credentialIdB64u',
    ),
  };
}

function parseGoogleEmailOtpTarget(
  raw: unknown,
): Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'google_email_otp' }>['target'] {
  const record = requireRecord(raw, 'wallet recovery Google Email OTP target');
  requireExactFields(
    record,
    [
      'kind',
      'provider',
      'providerSubject',
      'emailHashHex',
      'registrationAuthorityId',
      'enrollment',
    ],
    'wallet recovery Google Email OTP target',
  );
  if (record.kind !== 'google_email_otp' || record.provider !== 'google') {
    throw new Error('wallet recovery Google Email OTP target is invalid');
  }
  return {
    kind: 'google_email_otp',
    provider: 'google',
    providerSubject: requireParsed(
      parseEmailOtpProviderUserId(record.providerSubject),
      'target.providerSubject',
    ),
    emailHashHex: requireEmailHash(record.emailHashHex),
    registrationAuthorityId: requireNonEmptyString(
      record.registrationAuthorityId,
      'target.registrationAuthorityId',
    ),
    enrollment: parseEnrollmentReference(record.enrollment),
  };
}

function parseEnrollmentReference(raw: unknown): WalletRecoveryEmailOtpEnrollmentReferenceV1 {
  const record = requireRecord(raw, 'wallet recovery Email OTP enrollment');
  requireExactFields(
    record,
    ['kind', 'enrollmentId', 'enrollmentSealKeyVersion'],
    'wallet recovery Email OTP enrollment',
  );
  if (record.kind !== 'email_otp_enrollment_reference_v1') {
    throw new Error('wallet recovery Email OTP enrollment is invalid');
  }
  return {
    kind: 'email_otp_enrollment_reference_v1',
    enrollmentId: requireNonEmptyString(record.enrollmentId, 'enrollment.enrollmentId'),
    enrollmentSealKeyVersion: requireNonEmptyString(
      record.enrollmentSealKeyVersion,
      'enrollment.enrollmentSealKeyVersion',
    ),
  };
}

function buildEnrollmentReference(
  value: WalletRecoveryEmailOtpEnrollmentReferenceV1,
): WalletRecoveryEmailOtpEnrollmentReferenceV1 {
  return parseEnrollmentReference(value);
}

function assertExpectedIdentity(
  projection: WalletRecoveryCommittedProjectionV1,
  expected: WalletRecoveryCommittedProjectionExpectationV1,
): void {
  if (
    projection.kind !== expected.kind ||
    projection.walletId !== expected.walletId ||
    projection.recoveryOperationId !== expected.recoveryOperationId ||
    projection.targetDeviceId !== expected.targetDeviceId ||
    projection.targetAuthorityId !== expected.targetAuthorityId ||
    projection.targetWalletAuthMethodId !== expected.targetWalletAuthMethodId
  ) {
    throw new Error('wallet recovery committed projection identity changed');
  }
  if (projection.kind === 'passkey' && expected.kind === 'passkey') {
    if (
      projection.target.rpId !== expected.rpId ||
      projection.target.credentialIdB64u !== expected.credentialIdB64u
    ) {
      throw new Error('wallet recovery passkey target changed');
    }
    return;
  }
  if (projection.kind !== 'google_email_otp' || expected.kind !== 'google_email_otp') {
    throw new Error('wallet recovery target identity changed');
  }
  if (
    projection.target.providerSubject !== expected.providerSubject ||
    projection.target.emailHashHex !== expected.emailHashHex ||
    projection.target.registrationAuthorityId !== expected.registrationAuthorityId ||
    projection.target.enrollment.enrollmentId !== expected.enrollment.enrollmentId ||
    projection.target.enrollment.enrollmentSealKeyVersion !==
      expected.enrollment.enrollmentSealKeyVersion
  ) {
    throw new Error('wallet recovery Google Email OTP target changed');
  }
}

function assertProjectionShape(projection: WalletRecoveryCommittedProjectionV1): void {
  if (
    projection.authority.walletId !== projection.walletId ||
    projection.authority.authorityId !== projection.targetAuthorityId ||
    projection.authority.principal.deviceId !== projection.targetDeviceId ||
    projection.authority.provenance.kind !== 'wallet_recovery' ||
    projection.authority.provenance.recoveryOperationId !== projection.recoveryOperationId ||
    projection.authority.provenance.continuityAuthorityId === projection.targetAuthorityId ||
    projection.authMethod.walletId !== projection.walletId ||
    projection.authMethod.walletAuthorityId !== projection.targetAuthorityId ||
    projection.authMethod.walletAuthMethodId !== projection.targetWalletAuthMethodId ||
    projection.authMethod.status !== 'active'
  ) {
    throw new Error('wallet recovery committed projection relations are invalid');
  }
  if (projection.kind === 'passkey') {
    if (
      projection.authMethod.kind !== 'passkey' ||
      projection.target.rpId !== projection.authMethod.rpId ||
      projection.target.credentialIdB64u !== projection.authMethod.credentialIdB64u
    ) {
      throw new Error('wallet recovery passkey projection relations are invalid');
    }
    return;
  }
  if (
    projection.authMethod.kind !== 'email_otp' ||
    projection.target.emailHashHex !== projection.authMethod.emailHashHex ||
    projection.target.registrationAuthorityId !== projection.authMethod.registrationAuthorityId
  ) {
    throw new Error('wallet recovery Google Email OTP projection relations are invalid');
  }
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireExactFields(
  record: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const expectedSet = new Set(expected);
  const actual = Object.keys(record);
  if (actual.length !== expected.length || actual.some((field) => !expectedSet.has(field))) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function requireParsed<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label} is invalid`);
  return result.value;
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} is invalid`);
  return value.trim();
}

function requireEmailHash(value: unknown): string {
  const hash = requireNonEmptyString(value, 'emailHashHex');
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('emailHashHex is invalid');
  return hash;
}
