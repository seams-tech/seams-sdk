import type {
  BudgetBlockedEvmFamilyEcdsaSigningSelection,
  EmailOtpEcdsaCommittedLane,
  EmailOtpEcdsaPublicReauthLane,
  EcdsaCommittedLane,
  EcdsaSelectionDiagnostics,
  ReadyPasskeyEcdsaCommittedLane,
  PasskeyEcdsaPublicReauthLane,
  RecordBackedEcdsaCommittedLane,
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
  RestoreRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { EcdsaWalletSessionAuthority } from '../../session/identity/ecdsaWalletSessionAuthority';
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
  EvmFamilyEcdsaKeyHandle,
  EvmFamilySigningKeySlotId,
  ParticipantId,
  SigningGrantId,
  ThresholdEcdsaSessionId,
  WalletId,
  VerifiedWalletSessionJwt,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EcdsaRelayerKeyId } from '../../session/keyMaterialBrands';
import type { WalletSessionThresholdExpiresAtMs } from '@shared/utils/sessionTokens';
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
declare const restoreCandidate: RestoreRequiredEvmFamilyEcdsaSigningSelection['candidate'];
declare const restoreMaterial: RestoreRequiredEvmFamilyEcdsaSigningSelection['material'];
declare const restoreChainTarget: RestoreRequiredEvmFamilyEcdsaSigningSelection['restoreChainTarget'];
declare const readyPasskeyCommittedLane: ReadyPasskeyEcdsaCommittedLane;
declare const passkeyPublicReauthLane: PasskeyEcdsaPublicReauthLane;
declare const emailOtpPublicReauthLane: EmailOtpEcdsaPublicReauthLane;
declare const walletSessionJwt: VerifiedWalletSessionJwt;
declare const walletId: WalletId;
declare const evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const relayerKeyId: EcdsaRelayerKeyId;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const signingGrantId: SigningGrantId;
declare const thresholdExpiresAtMs: WalletSessionThresholdExpiresAtMs;
declare const participantIds: readonly ParticipantId[];
void (readyPasskeyCommittedLane.authority satisfies typeof passkeyAuthority);
void (ecdsaCommittedLaneAuthMethod(readyPasskeyCommittedLane) satisfies 'passkey');

const walletSessionAuthority = {
  kind: 'ecdsa_wallet_session_authority',
  walletSessionJwt,
  walletId,
  evmFamilySigningKeySlotId,
  keyHandle,
  relayerKeyId,
  thresholdSessionId,
  signingGrantId,
  thresholdExpiresAtMs,
  participantIds,
} satisfies EcdsaWalletSessionAuthority;

const invalidWalletSessionAuthorityWithRecordExpiry = {
  ...walletSessionAuthority,
  // @ts-expect-error committed ECDSA wallet-session authority requires JWT-derived branded expiry.
  thresholdExpiresAtMs: 1_900_000_000_000,
} satisfies EcdsaWalletSessionAuthority;
void invalidWalletSessionAuthorityWithRecordExpiry;

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
  walletSessionAuthority,
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

const durableAuthorityBackedCommittedEmailOtpLane: EmailOtpEcdsaCommittedLane = {
  source: 'durable_authority_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority,
  material: missingHotEmailOtpMaterial,
  durableRestore: 'sealed_record_authority',
};
void durableAuthorityBackedCommittedEmailOtpLane;

// @ts-expect-error durable-authority Email OTP ECDSA lanes cannot pretend to carry a runtime record.
const durableAuthorityBackedLaneWithRecord: EmailOtpEcdsaCommittedLane = {
  source: 'durable_authority_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority,
  material: missingHotEmailOtpMaterial,
  durableRestore: 'sealed_record_authority',
  record: emailOtpRecord,
};
void durableAuthorityBackedLaneWithRecord;

const durableAuthorityBackedLaneWithPureFactor: EmailOtpEcdsaCommittedLane = {
  source: 'durable_authority_backed',
  lane: reauthLane,
  // @ts-expect-error durable-authority Email OTP ECDSA lanes require wallet-bound authority.
  authority: emailOtpFactor,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority,
  material: missingHotEmailOtpMaterial,
  durableRestore: 'sealed_record_authority',
};
void durableAuthorityBackedLaneWithPureFactor;

const durableAuthorityBackedLaneWithAppSessionAuth: EmailOtpEcdsaCommittedLane = {
  source: 'durable_authority_backed',
  lane: reauthLane,
  authority: emailOtpAuthority,
  // @ts-expect-error durable-authority Email OTP ECDSA lanes require ECDSA signing-session auth.
  authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
  walletSessionAuthority,
  material: missingHotEmailOtpMaterial,
  durableRestore: 'sealed_record_authority',
};
void durableAuthorityBackedLaneWithAppSessionAuth;

const recordBackedProjection: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority> =
  committedEmailOtpLane;
void recordBackedProjection;

// @ts-expect-error durable-authority lanes cannot satisfy runtime-record-backed consumers.
const durableAuthorityBackedRecordProjection: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority> =
  durableAuthorityBackedCommittedEmailOtpLane;
void durableAuthorityBackedRecordProjection;

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

const restoreRequiredSelection: RestoreRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'restore_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: reauthLane,
  candidate: restoreCandidate,
  material: restoreMaterial,
  restoreChainTarget,
  diagnostics,
};
void restoreRequiredSelection;

const invalidRestoreRequiredReadyMaterial: RestoreRequiredEvmFamilyEcdsaSigningSelection = {
  ...restoreRequiredSelection,
  // @ts-expect-error restore-required selections cannot carry ready signer material.
  material: readyMaterial,
};
void invalidRestoreRequiredReadyMaterial;

const invalidEmailOtpRestoreRequiredSelection: RestoreRequiredEvmFamilyEcdsaSigningSelection = {
  ...restoreRequiredSelection,
  // @ts-expect-error exact sealed restore without committed material is passkey-only.
  authMethod: 'email_otp',
};
void invalidEmailOtpRestoreRequiredSelection;

const invalidRestoreRequiredSelectionWithCommittedLane: RestoreRequiredEvmFamilyEcdsaSigningSelection =
  {
    ...restoreRequiredSelection,
    // @ts-expect-error restore-required selections do not carry committed hot material.
    committedLane: readyPasskeyCommittedLane,
  };
void invalidRestoreRequiredSelectionWithCommittedLane;

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
  walletSessionAuthority,
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
  walletSessionAuthority,
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
  walletSessionAuthority,
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
  // @ts-expect-error committed ECDSA lanes do not carry a duplicate candidate identity.
  candidate: {},
};
void committedEmailOtpLaneWithCandidateCopy;

const committedEmailOtpLaneWithWalletIdCopy: EmailOtpEcdsaCommittedLane = {
  source: 'record_backed',
  lane: missingHotMaterialSelection.lane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority,
  material: missingHotMaterialSelection.material,
  record: emailOtpRecord,
  durableRestore: 'record_restore_metadata',
  // @ts-expect-error committed ECDSA lanes derive wallet identity from the bound authority and lane key.
  walletId: emailOtpAuthority.walletId,
};
void committedEmailOtpLaneWithWalletIdCopy;

const committedEmailOtpLaneFromDurableExactAuthOnly: EmailOtpEcdsaCommittedLane = {
  // @ts-expect-error durable exact auth-lane-only state cannot form a committed Email OTP lane.
  source: 'durable_exact_lane',
  lane: missingHotMaterialSelection.lane,
  authority: emailOtpAuthority,
  authLane: emailOtpEcdsaAuthLane,
  walletSessionAuthority,
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
  reauthLane: passkeyPublicReauthLane,
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

// @ts-expect-error expired selections require a public reauth lane and reject live committed authority.
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

// @ts-expect-error missing-hot-material selections require live committed authority.
const invalidMissingHotMaterialWithPublicAnchor: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'passkey',
  lane: reauthLane,
  material: missingHotMaterialSelection.material,
  reason: 'missing_hot_material',
  reauthLane: passkeyPublicReauthLane,
  diagnostics: readySelection.diagnostics,
};
void invalidMissingHotMaterialWithPublicAnchor;

const validEmailOtpExpiredSelection: ReauthRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'reauth_required',
  accountAuth: readySelection.accountAuth,
  authMethod: 'email_otp',
  lane: reauthLane,
  material: missingHotMaterialSelection.material,
  reason: 'exhausted',
  reauthLane: emailOtpPublicReauthLane,
  diagnostics: readySelection.diagnostics,
};
void validEmailOtpExpiredSelection;

const invalidPublicReauthLaneWithWalletSession: EmailOtpEcdsaPublicReauthLane = {
  ...emailOtpPublicReauthLane,
  // @ts-expect-error public reauth lanes reject old Wallet Session authority.
  walletSessionAuthority: committedEmailOtpLane.walletSessionAuthority,
};
void invalidPublicReauthLaneWithWalletSession;

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
