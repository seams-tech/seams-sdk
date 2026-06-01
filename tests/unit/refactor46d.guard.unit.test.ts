import { expect, test } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DOMAIN_IDS_URL = new URL('../../shared/src/utils/domainIds.ts', import.meta.url);
const REGISTRATION_INTENT_URL = new URL(
  '../../shared/src/utils/registrationIntent.ts',
  import.meta.url,
);
const OPERATION_STATE_TYPES_URL = new URL(
  '../../client/src/core/signingEngine/session/operationState/types.ts',
  import.meta.url,
);
const UI_CONFIRM_SIGNING_URL = new URL(
  '../../client/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts',
  import.meta.url,
);
const EVM_FAMILY_PREPARED_SIGNING_URL = new URL(
  '../../client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
  import.meta.url,
);
const ECDSA_MATERIAL_STATE_URL = new URL(
  '../../client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
  import.meta.url,
);
const ECDSA_CHAIN_TARGET_URL = new URL(
  '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts',
  import.meta.url,
);
const BUDGET_URL = new URL('../../client/src/core/signingEngine/session/budget/budget.ts', import.meta.url);
const AUTH_SERVICE_URL = new URL('../../server/src/core/AuthService.ts', import.meta.url);
const SEAMS_PASSKEY_INDEX_URL = new URL(
  '../../client/src/core/SeamsPasskey/index.ts',
  import.meta.url,
);
const REGISTRATION_CEREMONY_STORE_URL = new URL(
  '../../server/src/core/RegistrationCeremonyStore.ts',
  import.meta.url,
);
const PASSKEY_ECDSA_BOOTSTRAP_URL = new URL(
  '../../client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  import.meta.url,
);
const ECDSA_SESSION_PROVISION_URL = new URL(
  '../../client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
  import.meta.url,
);

const EMAIL_OTP_ECDSA_SOURCE_URLS = [
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
  '../../client/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
  '../../client/src/core/signingEngine/session/emailOtp/workerRequests.ts',
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts',
].map((relativePath) => new URL(relativePath, import.meta.url));

const TEMPORARY_DIAGNOSTIC_STRINGS = [
  'unlock completed without Ed25519 session reconstruction',
  'unlock reconstructed Ed25519 signing session',
  '[Registration][postcondition] Ed25519 lane missing after registration',
  '[Registration][postcondition] ECDSA lane missing after registration',
] as const;

function readSource(url: URL): string {
  return readFileSync(url, 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('Refactor 46d hardening guards', () => {
  test('domain identity brands have one central source of truth', () => {
    const domainIds = readSource(DOMAIN_IDS_URL);
    expect(domainIds).toContain("export type WalletId = DomainId<'WalletId'>");
    expect(domainIds).toContain("export type ProviderSubject = DomainId<'ProviderSubject'>");
    expect(domainIds).toContain("export type ChallengeSubjectId = DomainId<'ChallengeSubjectId'>");
    expect(domainIds).toContain("export type EmailOtpChallengeId = DomainId<'EmailOtpChallengeId'>");
    expect(domainIds).toContain(
      "export type EmailOtpRegistrationAttemptId = DomainId<'EmailOtpRegistrationAttemptId'>",
    );
    expect(domainIds).toContain("export type OrgId = DomainId<'OrgId'>");
    expect(domainIds).toContain("export type AppSessionVersion = DomainId<'AppSessionVersion'>");
    expect(domainIds).toContain(
      "export type WalletSigningSessionId = DomainId<'WalletSigningSessionId'>",
    );
    expect(domainIds).toContain(
      "export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>",
    );
    expect(domainIds).toContain(
      "export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>",
    );

    const registrationIntent = readSource(REGISTRATION_INTENT_URL);
    expect(registrationIntent).toContain("export type { WalletId } from './domainIds'");
    expect(registrationIntent).toContain("import { parseWalletId } from './domainIds'");
    expect(registrationIntent).toContain('const parsed = parseWalletId(value)');
    expect(registrationIntent).not.toContain('__walletIdBrand');
    expect(registrationIntent).not.toContain('as WalletId');

    const operationStateTypes = readSource(OPERATION_STATE_TYPES_URL);
    expect(operationStateTypes).toContain("} from '@shared/utils/domainIds'");
    expect(operationStateTypes).not.toContain(
      "export type WalletSigningSessionId = Brand<string, 'WalletSigningSessionId'>",
    );
    expect(operationStateTypes).not.toContain(
      "export type ThresholdEd25519SessionId = Brand<string, 'ThresholdEd25519SessionId'>",
    );
    expect(operationStateTypes).not.toContain(
      "export type ThresholdEcdsaSessionId = Brand<string, 'ThresholdEcdsaSessionId'>",
    );
    expect(operationStateTypes).not.toContain(
      "export type EmailOtpChallengeId = Brand<string, 'EmailOtpChallengeId'>",
    );

    const centralBrandNames = [
      'WalletId',
      'ProviderSubject',
      'ChallengeSubjectId',
      'EmailOtpChallengeId',
      'EmailOtpRegistrationAttemptId',
      'OrgId',
      'AppSessionVersion',
      'WalletSigningSessionId',
      'ThresholdEd25519SessionId',
      'ThresholdEcdsaSessionId',
    ];
    const duplicateBrandDeclaration = new RegExp(
      `export\\s+type\\s+(?:${centralBrandNames.join('|')})\\s*=`,
    );
    const duplicateBrandFiles = ['client/src', 'server/src', 'shared/src']
      .flatMap(listSourceFiles)
      .filter((relativePath) => relativePath !== 'shared/src/utils/domainIds.ts')
      .filter((relativePath) =>
        duplicateBrandDeclaration.test(readFileSync(path.join(repoRoot, relativePath), 'utf8')),
      );

    expect(duplicateBrandFiles).toEqual([]);
  });

  test('identity boundary helpers use central domain-id parsers', () => {
    const domainIds = readSource(DOMAIN_IDS_URL);
    for (const parser of [
      'parseWalletId',
      'parseProviderSubject',
      'parseChallengeSubjectId',
      'parseEmailOtpChallengeId',
      'parseEmailOtpRegistrationAttemptId',
      'parseOrgId',
      'parseAppSessionVersion',
      'parseWalletSigningSessionId',
      'parseThresholdEd25519SessionId',
      'parseThresholdEcdsaSessionId',
      'parseThresholdSessionId',
    ]) {
      expect(domainIds).toContain(`export function ${parser}`);
    }

    const ecdsaChainTarget = readSource(ECDSA_CHAIN_TARGET_URL);
    expect(ecdsaChainTarget).toContain("from '@shared/utils/domainIds'");
    expect(ecdsaChainTarget).toContain('parseWalletId(value)');
    expect(ecdsaChainTarget).not.toContain('as WalletId');

    const authService = readSource(AUTH_SERVICE_URL);
    for (const parser of [
      'parseWalletId',
      'parseProviderSubject',
      'parseChallengeSubjectId',
      'parseEmailOtpChallengeId',
      'parseEmailOtpRegistrationAttemptId',
      'parseOrgId',
      'parseAppSessionVersion',
    ]) {
      expect(authService).toContain(parser);
    }

    const ceremonyStore = readSource(REGISTRATION_CEREMONY_STORE_URL);
    for (const parser of [
      'parseWalletId',
      'parseProviderSubject',
      'parseChallengeSubjectId',
      'parseEmailOtpChallengeId',
      'parseOrgId',
      'parseAppSessionVersion',
    ]) {
      expect(ceremonyStore).toContain(parser);
    }
  });

  test('Email OTP ECDSA runtime stays out of passkey PRF seal persistence', () => {
    for (const url of EMAIL_OTP_ECDSA_SOURCE_URLS) {
      const source = readSource(url);
      expect(source, url.pathname).not.toContain('ensureEcdsaPrfSealPersisted');
      expect(source, url.pathname).not.toContain('sealAndPersistWarmSessionMaterial');
      expect(source, url.pathname).not.toContain('touchConfirm.putWarmSessionMaterial');
      expect(source, url.pathname).not.toContain("from '../passkey/runtime'");
      expect(source, url.pathname).not.toContain("from './runtime'");
    }
  });

  test('Email OTP ECDSA sealed refresh uses the branch-specific persistence input', () => {
    const source = readSource(
      new URL(
        '../../client/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
        import.meta.url,
      ),
    );

    expect(source).toContain('EmailOtpEcdsaReadyPersistInput');
    expect(source).toContain("authMethod: 'email_otp'");
    expect(source).toContain("curve: 'ecdsa'");
    expect(source).toContain('chainTarget: args.primaryChain');
    expect(source).toContain('emailOtpAuthContext: args.emailOtpAuthContext');
    expect(source).toContain("kind: 'worker_handle'");
  });

  test('Email OTP ECDSA bootstrap cannot re-enter passkey warm persistence', () => {
    const provisionSource = readSource(ECDSA_SESSION_PROVISION_URL);
    const bootstrapSource = readSource(PASSKEY_ECDSA_BOOTSTRAP_URL);

    expect(provisionSource).toContain("request.kind !== 'email_otp_ecdsa_bootstrap'");
    expect(provisionSource).toContain('ensureEcdsaPrfSealPersisted');
    expect(bootstrapSource).toContain("normalizedRequest.kind !== 'email_otp_ecdsa_bootstrap'");
    expect(bootstrapSource).toContain('passkeyEcdsaPersistenceSource({');
    expect(bootstrapSource).toContain('request: normalizedRequest');
    expect(bootstrapSource).toContain('deps.touchConfirm.putWarmSessionMaterial');
  });

  test('passkey ECDSA warm persistence requires credential identity and typed seal material', () => {
    const bootstrapSource = readSource(PASSKEY_ECDSA_BOOTSTRAP_URL);
    const portSource = readSource(
      new URL(
        '../../client/src/core/signingEngine/session/warmCapabilities/persistencePorts.ts',
        import.meta.url,
      ),
    );

    expect(portSource).toContain("kind: 'ecdsa_prf_first'");
    expect(portSource).toContain('passkeyPrfFirstB64u: string');
    expect(portSource).toContain("kind: 'fresh_webauthn'");
    expect(portSource).toContain("kind: 'session_reconnect'");
    expect(portSource).toContain('restoredThresholdSessionId');
    expect(bootstrapSource).toContain('PasskeyEcdsaReadyPersistInput');
    expect(bootstrapSource).toContain('passkeyEcdsaPersistenceSource');
    expect(bootstrapSource).toContain("authMethod: 'passkey'");
    expect(bootstrapSource).toContain("curve: 'ecdsa'");
    expect(bootstrapSource).toContain("kind: 'ecdsa_prf_first'");
  });

  test('Email OTP unlock validates every configured ECDSA target', () => {
    const source = readSource(SEAMS_PASSKEY_INDEX_URL);
    const unlockPostcondition = source.slice(
      source.indexOf("source: 'wallet_unlock'"),
      source.indexOf("source: 'wallet_unlock'") + 700,
    );
    expect(source).toContain('configuredEmailOtpEcdsaSnapshotChainTargets');
    expect(unlockPostcondition).toContain('configuredEmailOtpEcdsaSnapshotChainTargets(this.configs)');
    expect(unlockPostcondition).not.toContain("{ curve: 'ecdsa', chainTarget }");
  });

  test('Email OTP UI-confirm plans cannot reach passkey credential lookup', () => {
    const source = readSource(UI_CONFIRM_SIGNING_URL);
    const transactionGuard = source.indexOf("stage: 'transaction_prompt'");
    const transactionLookup = source.indexOf(
      'collectAuthenticationCredentialForChallengeB64u',
      transactionGuard,
    );
    const intentGuard = source.indexOf("stage: 'intent_digest_prompt'");
    const intentLookup = source.indexOf('collectAuthenticationCredentialForChallengeB64u', intentGuard);

    expect(source).toContain("throw new Error('[SigningEngine] passkey_lookup_for_email_otp')");
    expect(transactionGuard).toBeGreaterThan(-1);
    expect(transactionLookup).toBeGreaterThan(transactionGuard);
    expect(intentGuard).toBeGreaterThan(transactionLookup);
    expect(intentLookup).toBeGreaterThan(intentGuard);
  });

  test('EVM-family signing prep does not hardcode passkey auth selection', () => {
    const source = readSource(EVM_FAMILY_PREPARED_SIGNING_URL);
    expect(source).toContain("authSelectionPolicy: { kind: 'any' }");
    expect(source).toContain('authMethod: primaryAuthMethod');
    expect(source).not.toContain("authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' }");
    expect(source).not.toContain("authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' }");
  });

  test('ECDSA budget status requires exact concrete lane identity', () => {
    const source = readSource(BUDGET_URL);
    expect(source).toContain("kind: 'ecdsa_lane_budget_status_check'");
    expect(source).toContain('keyHandle: EvmFamilyEcdsaKeyHandle');
    expect(source).toContain('chainTarget: ThresholdEcdsaChainTarget');
    expect(source).toContain('thresholdSessionId: ThresholdEcdsaSessionId');
    expect(source).toContain('ECDSA budget status requires concrete chain target');
  });

  test('EVM-family shared ECDSA state separates public identity from signing material', () => {
    const source = readSource(ECDSA_MATERIAL_STATE_URL);
    expect(source).toContain('export type EvmFamilySharedEcdsaReadyState');
    expect(source).toContain('export type EvmFamilySharedEcdsaPublicIdentityOnlyState');
    expect(source).toContain("kind: 'public_identity_only'");
    expect(source).toContain("kind: 'ready_to_sign'");
    expect(source).toContain("kind: 'source_chain_material'");
    expect(source).toContain('TargetSpecificEvmFamilyEcdsaLaneState');
    expect(source).toContain('sharedKeyState: EvmFamilySharedEcdsaReadyState');
    expect(source).toContain('signerMaterial?: never');
    expect(source).toContain('signerMaterial: EvmFamilySharedEcdsaSignerMaterial');
  });

  test('wallet-subject vocabulary is isolated to migration and delete-only boundaries', () => {
    const allowedFiles = new Set([
      'client/src/core/indexedDB/seamsWalletDB/schema.ts',
      'server/src/storage/postgres.ts',
    ]);
    const offenders = ['client/src', 'server/src', 'shared/src']
      .flatMap(listSourceFiles)
      .filter((relativePath) => !allowedFiles.has(relativePath))
      .filter((relativePath) => /walletSubject|wallet_subject/.test(readFileSync(path.join(repoRoot, relativePath), 'utf8')));

    expect(offenders).toEqual([]);
  });

  test('Email OTP challenge verification preserves branch-specific mismatch codes', () => {
    const source = readSource(AUTH_SERVICE_URL);
    expect(source).toContain('type EmailOtpRegistrationChallengeProof =');
    expect(source).toContain('function parseRawEmailOtpRegistrationChallengeProofInput');
    expect(source).toContain('function parseDirectEmailOtpRegistrationChallengeProof');
    expect(source).toContain('private async resolveEmailOtpRegistrationChallengeProof');
    expect(source).toContain('type EmailOtpChallengeBindingMismatchCode');
    expect(source).toContain("'challenge_purpose_mismatch'");
    expect(source).toContain("'challenge_subject_mismatch'");
    expect(source).toContain("'challenge_email_mismatch'");
    expect(source).toContain("'challenge_session_mismatch'");
    expect(source).toContain("'registration_attempt_missing'");
    expect(source).toContain("'registration_attempt_expired'");
    expect(source).toContain("'registrationAttemptId does not match walletId'");
    expect(source).toContain('registrationChallengeEmailMatches');
    expect(source).toContain('registrationChallengeCanFollowReroll');
    expect(source).toContain('[email-otp] challenge binding mismatch during verification');
  });

  test('temporary registration and unlock diagnostics stay out of runtime source', () => {
    const offenders = ['client/src', 'server/src', 'shared/src']
      .flatMap(listSourceFiles)
      .flatMap((relativePath) => {
        const source = readFileSync(path.join(repoRoot, relativePath), 'utf8');
        return TEMPORARY_DIAGNOSTIC_STRINGS.filter((needle) => source.includes(needle)).map(
          (needle) => ({ relativePath, needle }),
        );
      });

    expect(offenders).toEqual([]);
  });
});
