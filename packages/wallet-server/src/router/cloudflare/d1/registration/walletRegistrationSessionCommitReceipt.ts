import type {
  WalletRegistrationFinalizeResponse,
  WalletRegistrationFinalizeSuccess,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationRouteDiagnostics,
  WalletRegistrationRouteTimingName,
} from '../../../../core/registrationContracts';
import { parseSessionOrigin } from '../../../../authorization/domain';
import type {
  WalletRegistrationActivateResponseV2,
  WalletRegistrationRouteErrorV2,
  WalletRegistrationCommittedInstallationProjectionV1,
  WalletRegistrationSessionCommitReceiptV2,
} from '../../../../core/threeRouteRegistrationContracts';
import type {
  RegistrationEstablishedSessionV2,
  RegistrationEstablishedSessionResultV2,
  RegistrationEstablishedSessionProjectionV2,
} from '@shared/utils/registrationEstablishedSession';
import {
  parseWalletSessionMintId,
  type WalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { parseWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { parseWalletId, parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletCustodyRegistrationOutcome } from '@shared/passkey-custody';

export type WalletRegistrationNearProvisioningFinalizeResponse =
  | WalletRegistrationFinalizeResponse
  | (Extract<WalletRegistrationFinalizeSuccess, { readonly kind: 'near_ed25519' }> & {
      readonly registrationEstablishedSession: RegistrationEstablishedSessionResultV2;
    });

export type RegistrationCommitExecution<T> =
  | { readonly kind: 'unissued'; readonly response: T }
  | { readonly kind: 'replayed'; readonly response: T }
  | {
      readonly kind: 'near_pending';
      readonly response: T;
      readonly expectedOrigin: string;
    }
  | {
      readonly kind: 'session_issued';
      readonly response: T;
      readonly issuedAtMs: number;
      readonly expectedOrigin: string;
      readonly installationProjection?: never;
    }
  | {
      readonly kind: 'session_issued_with_installation_projection';
      readonly response: T;
      readonly issuedAtMs: number;
      readonly expectedOrigin: string;
      readonly installationProjection: WalletRegistrationCommittedInstallationProjectionV1;
    };

export function unissuedRegistrationCommit<T>(response: T): RegistrationCommitExecution<T> {
  return { kind: 'unissued', response };
}

export function replayedRegistrationCommit<T>(response: T): RegistrationCommitExecution<T> {
  return { kind: 'replayed', response };
}

export function projectRegistrationEstablishedSessionV2(
  session: RegistrationEstablishedSessionV2,
): RegistrationEstablishedSessionProjectionV2 {
  return {
    kind: 'registration_established_wallet_session_projection_v2',
    walletId: session.walletId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    walletSession: session.walletSession,
    tokens: session.tokens,
  };
}

function projectRegistrationEstablishedSessionResultV2(
  result: RegistrationEstablishedSessionResultV2,
): RegistrationEstablishedSessionProjectionV2 {
  switch (result.kind) {
    case 'issued':
      return projectRegistrationEstablishedSessionV2(result.session);
    case 'already_committed':
      return result.session;
    default:
      return assertNeverRegistrationSessionResult(result);
  }
}

function assertNeverRegistrationSessionResult(value: never): never {
  throw new Error(`Unsupported registration session result: ${String(value)}`);
}

export function projectWalletRegistrationSessionCommitReceiptV2(input: {
  readonly operation: 'registration_activate' | 'near_provisioning';
  readonly operationFingerprint: string;
  readonly registrationCeremonyId: string;
  readonly execution: RegistrationCommitExecution<
    WalletRegistrationActivateResponseV2 | WalletRegistrationNearProvisioningFinalizeResponse
  >;
}): WalletRegistrationSessionCommitReceiptV2 {
  const response = input.execution.response;
  if (!response.ok) {
    if (input.execution.kind !== 'unissued') {
      throw new Error('Registration error receipt has an issued-session marker');
    }
    return {
      kind: 'wallet_registration_session_commit_receipt_v2',
      operation: input.operation,
      operationFingerprint: input.operationFingerprint,
      registrationCeremonyId: input.registrationCeremonyId,
      committed: { kind: 'error', error: response },
    };
  }
  if (input.execution.kind === 'unissued' || input.execution.kind === 'replayed') {
    throw new Error('Registration commit receipt requires an issued or pending response');
  }
  const expectedOrigin = input.execution.expectedOrigin;
  const metadata = {
    kind: 'wallet_registration_session_commit_receipt_v2' as const,
    operation: input.operation,
    operationFingerprint: input.operationFingerprint,
    registrationCeremonyId: input.registrationCeremonyId,
    walletId: response.walletId,
    authority: response.authority,
    authMethod: response.authMethod,
    expectedOrigin,
    ...('registrationDiagnostics' in response && response.registrationDiagnostics
      ? { registrationDiagnostics: response.registrationDiagnostics }
      : {}),
  };
  if (response.kind === 'near_ed25519' && !('registrationEstablishedSession' in response)) {
    if (input.execution.kind !== 'near_pending') {
      throw new Error('Pending registration commit receipt has an issued-session marker');
    }
    return {
      ...metadata,
      walletAuthMethodId: response.authority.bindingId,
      committed: {
        kind: 'near_pending',
        nearProvisioning: { status: 'near_pending' },
      },
    };
  }
  if (response.kind === 'evm_family_ecdsa') {
    if (!('registrationEstablishedSession' in response)) {
      throw new Error('ECDSA registration commit receipt is missing its session');
    }
    if (
      input.execution.kind !== 'session_issued' &&
      input.execution.kind !== 'session_issued_with_installation_projection'
    ) {
      throw new Error('ECDSA registration commit receipt is missing its issue identity');
    }
    if (response.foundingAuthMethod.walletAuthMethodId !== response.authority.bindingId) {
      throw new Error('ECDSA registration commit receipt has mismatched auth-method identity');
    }
    const installation =
      input.execution.kind === 'session_issued_with_installation_projection'
        ? input.execution.installationProjection
        : undefined;
    if (
      installation &&
      (installation.registrationCeremonyId !== input.registrationCeremonyId ||
        installation.walletId !== response.walletId ||
        installation.registrationAuthority.walletId !== response.walletId ||
        response.nearProvisioning?.status !== 'near_pending')
    ) {
      throw new Error('ECDSA registration commit receipt has an invalid installation projection');
    }
    const establishedSessionProjection = projectRegistrationEstablishedSessionResultV2(
      response.registrationEstablishedSession,
    );
    assertRegistrationCommitSessionTiming(establishedSessionProjection, input.execution.issuedAtMs);
    const readyMetadata = {
      ...metadata,
      walletAuthMethodId: response.foundingAuthMethod.walletAuthMethodId,
      foundingAuthority: response.foundingAuthority,
      foundingAuthMethod: response.foundingAuthMethod,
      mintId: registrationEstablishedMintId(input.registrationCeremonyId),
      issuedAtMs: input.execution.issuedAtMs,
      expiresAtMs: establishedSessionProjection.expiresAtMs,
      custodyKeyManifestDigestB64u: response.custodyKeyManifestDigestB64u,
      ...(response.walletCustody ? { walletCustody: response.walletCustody } : {}),
    };
    if (response.nearProvisioning && installation) {
      return {
        ...readyMetadata,
        committed: {
          kind: 'ecdsa_ready',
          ecdsa: response.ecdsa,
          session: establishedSessionProjection,
          nearProvisioning: response.nearProvisioning,
          installation,
        },
      };
    }
    if (response.nearProvisioning === undefined && installation === undefined) {
      return {
        ...readyMetadata,
        committed: {
          kind: 'ecdsa_ready',
          ecdsa: response.ecdsa,
          session: establishedSessionProjection,
        },
      };
    }
    throw new Error('ECDSA registration commit receipt has an incomplete installation projection');
  }
  if (response.kind !== 'near_ed25519' || !('registrationEstablishedSession' in response)) {
    throw new Error('Registration commit receipt has an unsupported success branch');
  }
  if (input.execution.kind !== 'session_issued') {
    throw new Error('NEAR registration commit receipt is missing its issue identity');
  }
  if (response.foundingAuthMethod.walletAuthMethodId !== response.authority.bindingId) {
    throw new Error('NEAR registration commit receipt has mismatched auth-method identity');
  }
  const establishedSessionProjection = projectRegistrationEstablishedSessionResultV2(
    response.registrationEstablishedSession,
  );
  assertRegistrationCommitSessionTiming(establishedSessionProjection, input.execution.issuedAtMs);
  return {
    ...metadata,
    walletAuthMethodId: response.foundingAuthMethod.walletAuthMethodId,
    foundingAuthority: response.foundingAuthority,
    foundingAuthMethod: response.foundingAuthMethod,
    mintId: registrationEstablishedMintId(input.registrationCeremonyId),
    issuedAtMs: input.execution.issuedAtMs,
    expiresAtMs: establishedSessionProjection.expiresAtMs,
    custodyKeyManifestDigestB64u: response.custodyKeyManifestDigestB64u,
    ...(response.walletCustody ? { walletCustody: response.walletCustody } : {}),
    committed: {
      kind: 'near_ready',
      authorityScope: response.authorityScope,
      accountProvisioning: response.accountProvisioning,
      resolvedAccount: response.resolvedAccount,
      ed25519: response.ed25519,
      session: establishedSessionProjection,
      nearProvisioning: { status: 'near_ready' },
    },
  };
}

type WalletRegistrationIdentityCommitReceiptV2 = Exclude<
  WalletRegistrationSessionCommitReceiptV2,
  { readonly committed: { readonly kind: 'error' } }
>;

export type RegistrationReplayAuthMethodFields =
  | {
      readonly kind: 'passkey';
      readonly authMethod: Extract<
        WalletRegistrationFinalizeAuthMethod,
        { readonly kind: 'passkey' }
      >;
      readonly rpId: string;
    }
  | {
      readonly kind: 'email_otp';
      readonly authMethod: Extract<
        WalletRegistrationFinalizeAuthMethod,
        { readonly kind: 'email_otp' }
      >;
      readonly rpId?: never;
    };

export function registrationReplayAuthMethodFields(
  receipt: WalletRegistrationIdentityCommitReceiptV2,
): RegistrationReplayAuthMethodFields {
  switch (receipt.authMethod.kind) {
    case 'passkey':
      if (receipt.authority.factor.kind !== 'passkey') {
        throw new Error('Registration commit receipt has mismatched passkey authority');
      }
      if (receipt.authority.factor.credentialIdB64u !== receipt.authMethod.credentialIdB64u) {
        throw new Error('Registration commit receipt has mismatched passkey credential');
      }
      if (receipt.authority.verifier.kind !== 'webauthn') {
        throw new Error('Registration commit receipt has mismatched WebAuthn verifier');
      }
      return {
        kind: 'passkey',
        authMethod: receipt.authMethod,
        rpId: receipt.authority.verifier.rpId,
      };
    case 'email_otp':
      if (receipt.authority.factor.kind !== 'email_otp') {
        throw new Error('Registration commit receipt has mismatched Email OTP authority');
      }
      return { kind: 'email_otp', authMethod: receipt.authMethod };
    default:
      return assertNeverRegistrationReplayAuthMethod(receipt.authMethod);
  }
}

function assertNeverRegistrationReplayAuthMethod(value: never): never {
  throw new Error(`Unsupported registration replay auth method: ${String(value)}`);
}

export function registrationEstablishedMintId(
  registrationCeremonyId: string,
): WalletSessionMintId {
  const parsed = parseWalletSessionMintId(
    `registration-established:${registrationCeremonyId}`,
  );
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export type RegistrationCommitReceiptCommittedParser = (
  raw: unknown,
) => WalletRegistrationSessionCommitReceiptV2['committed'] | null;

/**
 * Parses the one durable registration receipt shape. Nested signer payloads
 * are parsed by the caller's branch parser; this boundary owns the envelope,
 * identity checks, exact keys, and the credential deny-list.
 */
export function parseWalletRegistrationSessionCommitReceiptV2(
  raw: unknown,
  parseCommitted: RegistrationCommitReceiptCommittedParser,
): WalletRegistrationSessionCommitReceiptV2 | null {
  if (
    !isRecord(raw) ||
    raw.kind !== 'wallet_registration_session_commit_receipt_v2' ||
    containsPersistedRegistrationCredential(raw)
  ) {
    return null;
  }
  const operation = parseRegistrationOperation(raw.operation);
  const operationFingerprint = parseNonEmptyString(raw.operationFingerprint);
  const registrationCeremonyId = parseNonEmptyString(raw.registrationCeremonyId);
  if (
    operation === null ||
    operationFingerprint === null ||
    registrationCeremonyId === null ||
    !isRecord(raw.committed) ||
    typeof raw.committed.kind !== 'string'
  ) {
    return null;
  }
  if (raw.committed.kind === 'error') {
    const error = parseRegistrationRouteError(raw.committed.error);
    if (
      error === null ||
      !hasExactKeys(raw, [
        'kind',
        'operation',
        'operationFingerprint',
        'registrationCeremonyId',
        'committed',
      ]) ||
      !hasExactKeys(raw.committed, ['kind', 'error'])
    ) {
      return null;
    }
    return {
      kind: 'wallet_registration_session_commit_receipt_v2',
      operation,
      operationFingerprint,
      registrationCeremonyId,
      committed: { kind: 'error', error },
    };
  }
  const walletId = parseWalletId(raw.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(raw.walletAuthMethodId);
  const authority = parseWalletAuthAuthority(raw.authority);
  const authMethod = parseWalletRegistrationFinalizeAuthMethod(raw.authMethod);
  let expectedOrigin: string;
  try {
    expectedOrigin = parseSessionOrigin(raw.expectedOrigin);
  } catch {
    return null;
  }
  if (
    !walletId.ok ||
    !walletAuthMethodId.ok ||
    authority === null ||
    authMethod === null ||
    authority.walletId !== walletId.value ||
    authority.bindingId !== walletAuthMethodId.value ||
    !registrationAuthMethodMatchesAuthority(authMethod, authority)
  ) {
    return null;
  }
  const registrationDiagnostics = parseRegistrationDiagnostics(raw.registrationDiagnostics);
  if (raw.registrationDiagnostics !== undefined && registrationDiagnostics === null) return null;
  const common = {
    kind: 'wallet_registration_session_commit_receipt_v2' as const,
    operation,
    operationFingerprint,
    registrationCeremonyId,
    walletId: walletId.value,
    walletAuthMethodId: walletAuthMethodId.value,
    authority,
    authMethod,
    expectedOrigin,
    ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
  };
  if (raw.committed.kind === 'near_pending') {
    if (
      operation !== 'registration_activate' ||
      !hasExactKeys(raw, [
        'kind',
        'operation',
        'operationFingerprint',
        'registrationCeremonyId',
        'walletId',
        'walletAuthMethodId',
        'authority',
        'authMethod',
        'expectedOrigin',
        ...(registrationDiagnostics ? ['registrationDiagnostics'] : []),
        'committed',
      ]) ||
      !hasExactKeys(raw.committed, ['kind', 'nearProvisioning']) ||
      !isRecord(raw.committed.nearProvisioning) ||
      !hasExactKeys(raw.committed.nearProvisioning, ['status']) ||
      raw.committed.nearProvisioning.status !== 'near_pending'
    ) {
      return null;
    }
    return {
      ...common,
      committed: { kind: 'near_pending', nearProvisioning: { status: 'near_pending' } },
    };
  }
  if (raw.committed.kind !== 'ecdsa_ready' && raw.committed.kind !== 'near_ready') return null;
  if (
    (raw.committed.kind === 'ecdsa_ready' && operation !== 'registration_activate') ||
    (raw.committed.kind === 'near_ready' && operation !== 'near_provisioning')
  ) {
    return null;
  }
  const foundingAuthority = parseWalletAuthorityV1(raw.foundingAuthority);
  const foundingAuthMethod = parseWalletAuthMethodRecordV2(raw.foundingAuthMethod);
  const mintId = parseWalletSessionMintId(raw.mintId);
  const issuedAtMs = parsePositiveSafeInteger(raw.issuedAtMs);
  const expiresAtMs = parsePositiveSafeInteger(raw.expiresAtMs);
  let custodyKeyManifestDigestB64u: DigestB64u;
  try {
    custodyKeyManifestDigestB64u = parseDigestB64u(raw.custodyKeyManifestDigestB64u);
  } catch {
    return null;
  }
  let walletCustody;
  if (raw.walletCustody !== undefined) {
    try {
      walletCustody = parseWalletCustodyRegistrationOutcome(
        raw.walletCustody,
        'registration receipt',
      );
    } catch {
      return null;
    }
  }
  if (
    !hasExactKeys(raw, [
      'kind',
      'operation',
      'operationFingerprint',
      'registrationCeremonyId',
      'walletId',
      'walletAuthMethodId',
      'authority',
      'authMethod',
      'expectedOrigin',
      'foundingAuthority',
      'foundingAuthMethod',
      'mintId',
      'issuedAtMs',
      'expiresAtMs',
      'custodyKeyManifestDigestB64u',
      ...(registrationDiagnostics ? ['registrationDiagnostics'] : []),
      ...(walletCustody ? ['walletCustody'] : []),
      'committed',
    ]) ||
    !foundingAuthority.ok ||
    foundingAuthority.value.state !== 'active' ||
    !foundingAuthMethod ||
    foundingAuthMethod.status !== 'active' ||
    !mintId.ok ||
    mintId.value !== registrationEstablishedMintId(registrationCeremonyId) ||
    issuedAtMs === null ||
    expiresAtMs === null ||
    expiresAtMs <= issuedAtMs ||
    foundingAuthority.value.walletId !== walletId.value ||
    foundingAuthMethod.walletId !== walletId.value ||
    foundingAuthMethod.walletAuthorityId !== foundingAuthority.value.authorityId ||
    foundingAuthMethod.walletAuthMethodId !== walletAuthMethodId.value
  ) {
    return null;
  }
  const committed = parseCommitted(raw.committed);
  if (!committed || committed.kind !== raw.committed.kind) return null;
  if (
    'session' in committed &&
    (committed.session.walletId !== walletId.value ||
      committed.session.expiresAtMs !== expiresAtMs ||
      committed.session.remainingUses <= 0)
  ) {
    return null;
  }
  switch (committed.kind) {
    case 'ecdsa_ready':
      return {
        ...common,
        foundingAuthority: foundingAuthority.value,
        foundingAuthMethod,
        mintId: mintId.value,
        issuedAtMs,
        expiresAtMs,
        custodyKeyManifestDigestB64u,
        ...(walletCustody ? { walletCustody } : {}),
        committed,
      };
    case 'near_ready':
      return {
        ...common,
        foundingAuthority: foundingAuthority.value,
        foundingAuthMethod,
        mintId: mintId.value,
        issuedAtMs,
        expiresAtMs,
        custodyKeyManifestDigestB64u,
        ...(walletCustody ? { walletCustody } : {}),
        committed,
      };
    default:
      return assertNeverCommittedReceipt(committed);
  }
}

function registrationAuthMethodMatchesAuthority(
  authMethod: WalletRegistrationFinalizeAuthMethod,
  authority: WalletAuthAuthority,
): boolean {
  if (authMethod.kind === 'passkey') {
    return (
      authority.factor.kind === 'passkey' &&
      authority.factor.credentialIdB64u === authMethod.credentialIdB64u
    );
  }
  return authority.factor.kind === 'email_otp';
}

function assertNeverCommittedReceipt(value: never): never {
  throw new Error(`Unsupported registration commit receipt: ${String(value)}`);
}

function assertRegistrationCommitSessionTiming(
  session: Pick<RegistrationEstablishedSessionProjectionV2, 'expiresAtMs' | 'remainingUses'>,
  issuedAtMs: number,
): void {
  if (
    !Number.isSafeInteger(issuedAtMs) ||
    issuedAtMs <= 0 ||
    !Number.isSafeInteger(session.expiresAtMs) ||
    session.expiresAtMs <= issuedAtMs ||
    !Number.isSafeInteger(session.remainingUses) ||
    session.remainingUses <= 0
  ) {
    throw new Error('Registration commit receipt has invalid session timing');
  }
}

function parseRegistrationOperation(
  value: unknown,
): 'registration_activate' | 'near_provisioning' | null {
  return value === 'registration_activate' || value === 'near_provisioning' ? value : null;
}

function parseWalletRegistrationFinalizeAuthMethod(
  raw: unknown,
): WalletRegistrationFinalizeAuthMethod | null {
  if (!isRecord(raw) || typeof raw.kind !== 'string') return null;
  if (raw.kind === 'passkey') {
    if (!hasExactKeys(raw, ['kind', 'credentialIdB64u', 'credentialPublicKeyB64u'])) return null;
    const credentialIdB64u = parseNonEmptyString(raw.credentialIdB64u);
    const credentialPublicKeyB64u = parseNonEmptyString(raw.credentialPublicKeyB64u);
    return credentialIdB64u && credentialPublicKeyB64u
      ? { kind: 'passkey', credentialIdB64u, credentialPublicKeyB64u }
      : null;
  }
  if (raw.kind === 'email_otp') {
    if (!hasExactKeys(raw, ['kind', 'registrationAuthorityId'])) return null;
    const registrationAuthorityId = parseNonEmptyString(raw.registrationAuthorityId);
    return registrationAuthorityId ? { kind: 'email_otp', registrationAuthorityId } : null;
  }
  return null;
}

function parseRegistrationDiagnostics(
  raw: unknown,
): WalletRegistrationRouteDiagnostics | undefined | null {
  if (raw === undefined) return undefined;
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, ['kind', 'route', 'entries']) ||
    raw.kind !== 'wallet_registration_route_diagnostics_v1'
  ) {
    return null;
  }
  if (raw.route !== 'wallets_register_finalize' || !Array.isArray(raw.entries)) return null;
  const entries: WalletRegistrationRouteDiagnostics['entries'] = [];
  for (const entryRaw of raw.entries) {
    if (!isRecord(entryRaw) || !hasExactKeys(entryRaw, ['name', 'durationMs'])) return null;
    if (typeof entryRaw.name !== 'string') return null;
    const durationMs = entryRaw.durationMs;
    if (typeof durationMs !== 'number' || !Number.isFinite(durationMs) || durationMs < 0) {
      return null;
    }
    const name = parseRegistrationRouteTimingName(entryRaw.name);
    if (name === null) return null;
    entries.push({ name, durationMs });
  }
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: 'wallets_register_finalize',
    entries,
  };
}

function parseRegistrationRouteError(raw: unknown): WalletRegistrationRouteErrorV2 | null {
  if (!isRecord(raw)) return null;
  const code = parseNonEmptyString(raw.code);
  const message = parseNonEmptyString(raw.message);
  if (raw.ok !== false || code === null || message === null) {
    return null;
  }
  if (raw.retryAfterMs === undefined) {
    return hasExactKeys(raw, ['ok', 'code', 'message']) ? { ok: false, code, message } : null;
  }
  const retryAfterMs = parseNonNegativeSafeInteger(raw.retryAfterMs);
  if (retryAfterMs === null || !hasExactKeys(raw, ['ok', 'code', 'message', 'retryAfterMs'])) {
    return null;
  }
  return {
    ok: false,
    code,
    message,
    retryAfterMs,
  };
}

function parseRegistrationRouteTimingName(value: string): WalletRegistrationRouteTimingName | null {
  switch (value) {
    case 'registrationIntentLoadMs':
    case 'registrationIntentDigestMs':
    case 'registrationIntentConsumeMs':
    case 'registrationAttemptGateMs':
    case 'registrationPreparationPersistMs':
    case 'registrationPreparationLoadMs':
    case 'registrationPreparationConsumeMs':
    case 'registrationPreparationScopeCheckMs':
    case 'registrationAuthorityVerifyMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerPrepareTotalMs':
    case 'registerStartTotalMs':
    case 'registrationEcdsaRespondMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationEcdsaBootstrapVerifyMs':
    case 'sponsoredNearAccountCreateMs':
    case 'registrationKeygenMs':
    case 'registrationEmailOtpEnrollmentPlanMs':
    case 'relaySessionMintMs':
    case 'relayGoogleEmailOtpActivationPlanMs':
    case 'relayPersistenceMs':
    case 'registrationFinalizeReplayCacheMs':
    case 'registerFinalizeTotalMs':
    case 'registrationCeremonyInsertMs':
    case 'registerSetupTotalMs':
      return value;
    default:
      return null;
  }
}

function parseNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function parsePositiveSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function parseNonNegativeSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === expected.length && expected.every((key) => actual.includes(key));
}

function containsPersistedRegistrationCredential(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsPersistedRegistrationCredential);
  if (!isRecord(value)) return false;
  for (const [key, child] of Object.entries(value)) {
    if (
      key === 'walletSessionToken' ||
      key === 'primaryOperationCredential' ||
      key === 'childOperationCredential' ||
      key === 'operationCredential' ||
      key === 'clientRootProof' ||
      key === 'passkeyBootstrapAuthorization' ||
      key === 'response'
    ) {
      return true;
    }
    if (containsPersistedRegistrationCredential(child)) return true;
  }
  return false;
}
