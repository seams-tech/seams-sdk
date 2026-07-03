import type {
  BudgetBlockedEvmFamilyEcdsaSigningSelection,
  EmailOtpEcdsaCommittedLane,
  EcdsaCommittedLane,
  EcdsaSelectionDiagnostics,
  ReadyPasskeyEcdsaCommittedLane,
  RecordBackedEcdsaCommittedLane,
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import { ecdsaCommittedLaneAuthMethod } from './ecdsaSelection';
import type { ReadyEcdsaMaterial } from './ecdsaMaterialState';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import type {
  EmailOtpAuthLane,
  EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  EmailOtpFactorIdentity,
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

declare const readyMaterial: ReadyEcdsaMaterial;
declare const reauthAnchor: ReauthAnchorIdentity;
declare const diagnostics: EcdsaSelectionDiagnostics;
declare const emailOtpAuthLane: EmailOtpAuthLane;
declare const emailOtpEcdsaAuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
declare const emailOtpRecord: ThresholdEcdsaSessionRecord;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const emailOtpFactor: EmailOtpFactorIdentity;
declare const passkeyAuthority: PasskeyWalletAuthAuthority;
declare const reauthLane: ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'];
declare const readyPasskeyCommittedLane: ReadyPasskeyEcdsaCommittedLane;
void (readyPasskeyCommittedLane.authority satisfies typeof passkeyAuthority);
void (ecdsaCommittedLaneAuthMethod(readyPasskeyCommittedLane) satisfies 'passkey');

const missingHotEmailOtpMaterial: ReauthRequiredEvmFamilyEcdsaSigningSelection['material'] = {
  kind: 'public_identity_unavailable',
  authMethod: 'email_otp',
  source: 'email_otp',
  chainTarget: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['material']['chainTarget'],
  identity: buildEcdsaSessionIdentity({
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  }),
  hasRecord: false,
};

const committedEmailOtpLane: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotEmailOtpMaterial,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
};
void committedEmailOtpLane;
void (committedEmailOtpLane satisfies EcdsaCommittedLane<EmailOtpWalletAuthAuthority>);

// @ts-expect-error committed ECDSA lane generics narrow by authority.factor.kind.
const emailOtpLaneAsPasskeyLane: EcdsaCommittedLane<PasskeyWalletAuthAuthority> =
  committedEmailOtpLane;
void emailOtpLaneAsPasskeyLane;

const resolverBackedCommittedEmailOtpLane: EmailOtpEcdsaCommittedLane = {
  source: 'resolver_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotEmailOtpMaterial,
  durableRestore: 'resolver_restore_metadata',
};
void resolverBackedCommittedEmailOtpLane;

// @ts-expect-error resolver-backed Email OTP ECDSA lanes must not pretend to be record-backed.
const resolverBackedLaneWithRecord: EmailOtpEcdsaCommittedLane = {
  source: 'resolver_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotEmailOtpMaterial,
  durableRestore: 'resolver_restore_metadata',
  record: emailOtpRecord,
};
void resolverBackedLaneWithRecord;

const resolverBackedLaneWithPureFactor: EmailOtpEcdsaCommittedLane = {
  source: 'resolver_backed',
  lane: reauthLane,
  // @ts-expect-error resolver-backed Email OTP ECDSA lanes require wallet-bound authority.
  authority: emailOtpFactor,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotEmailOtpMaterial,
  durableRestore: 'resolver_restore_metadata',
};
void resolverBackedLaneWithPureFactor;

const resolverBackedLaneWithAppSessionAuth: EmailOtpEcdsaCommittedLane = {
  source: 'resolver_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  // @ts-expect-error resolver-backed Email OTP ECDSA lanes require ECDSA signing-session auth.
  authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotEmailOtpMaterial,
  durableRestore: 'resolver_restore_metadata',
};
void resolverBackedLaneWithAppSessionAuth;

const recordBackedProjection: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority> =
  committedEmailOtpLane;
void recordBackedProjection;

// @ts-expect-error resolver-backed lanes cannot satisfy record-backed committed-lane consumers.
const resolverBackedRecordBackedProjection: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority> =
  resolverBackedCommittedEmailOtpLane;
void resolverBackedRecordBackedProjection;

const readySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: {} as ReadyEvmFamilyEcdsaSigningSelection['accountAuth'],
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: {} as ReadyEvmFamilyEcdsaSigningSelection['lane'],
  material: readyMaterial,
  committedLane: readyPasskeyCommittedLane,
  diagnostics: {} as ReadyEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void readySelection;

// @ts-expect-error passkey ready selections require a committed lane.
const invalidPasskeyReadySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  material: readyMaterial,
  diagnostics: readySelection.diagnostics,
};
void invalidPasskeyReadySelection;

const missingHotMaterialSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  lane: reauthLane,
  material: missingHotEmailOtpMaterial,
  reason: 'missing_hot_material',
  committedLane: committedEmailOtpLane,
  diagnostics: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void missingHotMaterialSelection;

// @ts-expect-error committed Email OTP ECDSA lanes require bound wallet authority.
const committedEmailOtpLaneWithoutBoundAuthority: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: missingHotMaterialSelection.lane,
  authLane: emailOtpEcdsaAuthLane,
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
};
void committedEmailOtpLaneWithoutBoundAuthority;

const committedEmailOtpLaneWithPureFactor: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: missingHotMaterialSelection.lane,
  // @ts-expect-error post-finalize ECDSA committed lanes require wallet-bound authority, not pure factor identity.
  authority: emailOtpFactor,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
};
void committedEmailOtpLaneWithPureFactor;

const committedEmailOtpLaneWithAppSessionAuth: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: missingHotMaterialSelection.lane,
  authority: emailOtpAuthority,
  // @ts-expect-error committed Email OTP ECDSA lanes require ECDSA signing-session auth.
  authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
};
void committedEmailOtpLaneWithAppSessionAuth;

const committedEmailOtpLaneWithCandidateCopy: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: missingHotMaterialSelection.lane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
  // @ts-expect-error committed ECDSA lanes do not carry a duplicate candidate identity.
  candidate: {},
};
void committedEmailOtpLaneWithCandidateCopy;

const committedEmailOtpLaneFromDurableExactAuthOnly: EmailOtpEcdsaCommittedLane = {
  // @ts-expect-error durable exact auth-lane-only state cannot form a committed Email OTP lane.
  source: 'durable_exact_lane',
  lane: missingHotMaterialSelection.lane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  material: missingHotMaterialSelection.material,
  // @ts-expect-error durable exact auth-lane-only state cannot form a committed Email OTP lane.
  durableRestore: 'durable_exact_auth_lane_only',
};
void committedEmailOtpLaneFromDurableExactAuthOnly;

const invalidMissingHotMaterialSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  lane: reauthLane,
  material: missingHotMaterialSelection.material,
  reason: 'missing_hot_material',
  // @ts-expect-error Email OTP reauth selections require committed lane authority.
  reauthAuthority: {
    kind: 'email_otp_signing_session',
    authLane: emailOtpAuthLane,
  },
  diagnostics: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['diagnostics'],
};
void invalidMissingHotMaterialSelection;

const expiredSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
  material: missingHotMaterialSelection.material,
  reason: 'expired',
  reauthAnchor,
  committedLane: readyPasskeyCommittedLane,
  diagnostics: readySelection.diagnostics,
};
void expiredSelection;

// @ts-expect-error passkey reauth selections require committed lane authority.
const invalidPasskeyReauthSelectionWithoutCommittedLane: ReauthRequiredEvmFamilyEcdsaSigningSelection =
  {
    kind: 'reauth_required',
    accountAuth: readySelection.accountAuth,
    authMethod: 'passkey',
    lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
    material: missingHotMaterialSelection.material,
    reason: 'missing_hot_material',
    diagnostics: readySelection.diagnostics,
  };
void invalidPasskeyReauthSelectionWithoutCommittedLane;

// @ts-expect-error exhausted/expired reauth selections require a ReauthAnchorIdentity.
const invalidExpiredSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: {} as ReauthRequiredEvmFamilyEcdsaSigningSelection['lane'],
  material: missingHotMaterialSelection.material,
  reason: 'expired',
  committedLane: readyPasskeyCommittedLane,
  diagnostics: readySelection.diagnostics,
};
void invalidExpiredSelection;

const invalidReadySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  // @ts-expect-error ready selections require ready-to-sign material
  material: missingHotMaterialSelection.material,
  diagnostics: readySelection.diagnostics,
};
void invalidReadySelection;

// @ts-expect-error Email OTP ready selections require the committed lane authority.
const invalidEmailOtpReadySelection: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  source: 'email_otp',
  lane: readySelection.lane,
  material: readyMaterial,
  diagnostics: readySelection.diagnostics,
};
void invalidEmailOtpReadySelection;

// @ts-expect-error Email OTP ready selections require an Email OTP committed lane.
const invalidReadySelectionAuthMismatch: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  source: 'email_otp',
  lane: readySelection.lane,
  material: readyMaterial,
  committedLane: readyPasskeyCommittedLane,
  diagnostics: readySelection.diagnostics,
};
void invalidReadySelectionAuthMismatch;

const diagnosticsAsReadySelectionMaterial: ReadyEvmFamilyEcdsaSigningSelection = {
  kind: 'ready',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  source: 'manual-bootstrap',
  lane: readySelection.lane,
  // @ts-expect-error diagnostics are observational and cannot satisfy ready material.
  material: diagnostics,
  diagnostics,
};
void diagnosticsAsReadySelectionMaterial;

const invalidBudgetBlockedSelection: BudgetBlockedEvmFamilyEcdsaSigningSelection = {
  kind: 'budget_blocked',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: readySelection.lane,
  material: readyMaterial,
  // @ts-expect-error exhausted budgets must route through reauth_required
  budget: { kind: 'exhausted', remainingUses: 0 },
  diagnostics: readySelection.diagnostics,
};
void invalidBudgetBlockedSelection;

export {};
