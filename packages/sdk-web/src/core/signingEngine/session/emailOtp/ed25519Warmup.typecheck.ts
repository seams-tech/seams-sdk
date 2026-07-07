import type { AccountId } from '@/core/types/accountIds';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type {
  EmailOtpRoutePlan,
  EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { EmailOtpEd25519SessionReconstructionPlan } from './provisioning';
import type { EmailOtpEd25519CommittedSessionRecord } from './ed25519CommittedLane';
import type { EmailOtpEd25519SigningSessionAuthority } from './ed25519SigningSessionAuthority';
import { buildEd25519SigningLane } from './ed25519Warmup';
import type {
  Ed25519SigningLane,
  EmailOtpEd25519Warmup,
  LoginEmailOtpEd25519CapabilityArgs,
} from './ed25519Warmup';

type LoginForSigningArgs = Parameters<EmailOtpEd25519Warmup['loginForSigning']>[0];

declare const nearAccountId: AccountId;
declare const walletSession: WalletSessionRef;
declare const routePlan: EmailOtpRoutePlan;
declare const committedLane: Ed25519SigningLane;
declare const record: ThresholdEd25519SessionRecord;
declare const committedRecord: EmailOtpEd25519CommittedSessionRecord;
declare const authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
declare const authority: EmailOtpWalletAuthAuthority;
declare const signingSessionAuthority: EmailOtpEd25519SigningSessionAuthority;
declare const ed25519SessionReconstruction: Extract<
  EmailOtpEd25519SessionReconstructionPlan,
  { kind: 'reconstruct' }
>;

const validEd25519Login: LoginEmailOtpEd25519CapabilityArgs = {
  walletSession,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ed25519SessionReconstruction,
};
void validEd25519Login;

// @ts-expect-error Ed25519 login core requires a committed route plan.
const invalidEd25519LoginWithoutRoutePlan: LoginEmailOtpEd25519CapabilityArgs = {
  walletSession,
  otpCode: '123456',
  emailHashHex: 'email-hash',
  ed25519SessionReconstruction,
};
void invalidEd25519LoginWithoutRoutePlan;

const invalidEd25519LoginWithRawAppSession: LoginEmailOtpEd25519CapabilityArgs = {
  walletSession,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ed25519SessionReconstruction,
  // @ts-expect-error Ed25519 login core must not accept raw app-session JWTs.
  appSessionJwt: 'app-session-jwt',
};
void invalidEd25519LoginWithRawAppSession;

const invalidEd25519LoginWithRawRouteAuth: LoginEmailOtpEd25519CapabilityArgs = {
  walletSession,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ed25519SessionReconstruction,
  // @ts-expect-error Ed25519 login core must not accept loose route auth.
  routeAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
};
void invalidEd25519LoginWithRawRouteAuth;

const invalidEd25519LoginWithSessionKind: LoginEmailOtpEd25519CapabilityArgs = {
  walletSession,
  otpCode: '123456',
  routePlan,
  emailHashHex: 'email-hash',
  ed25519SessionReconstruction,
  // @ts-expect-error Ed25519 login core receives session transport through routePlan.
  sessionKind: 'jwt',
};
void invalidEd25519LoginWithSessionKind;

const recordBackedSigningLane: Ed25519SigningLane = {
  source: 'record_backed',
  record: committedRecord,
  authority,
  authLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
};
void recordBackedSigningLane;

// @ts-expect-error Ed25519 committed lanes require the bound Email OTP authority.
const recordBackedSigningLaneWithoutAuthority: Ed25519SigningLane = {
  source: 'record_backed',
  record: committedRecord,
  authLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
};
void recordBackedSigningLaneWithoutAuthority;

const builtRecordBackedSigningLane = buildEd25519SigningLane({
  record,
  authority: signingSessionAuthority,
});
void builtRecordBackedSigningLane;

const buildRecordBackedSigningLaneWithLooseAuthLane = buildEd25519SigningLane({
  record,
  // @ts-expect-error Ed25519 committed lane construction requires the atomic signing-session authority.
  authLane,
});
void buildRecordBackedSigningLaneWithLooseAuthLane;

const loginForSigningWithCommittedLane: LoginForSigningArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  remainingUses: 3,
};
void loginForSigningWithCommittedLane;

// @ts-expect-error Email OTP Ed25519 signing requires a concrete budget allowance.
const loginForSigningWithoutRemainingUses: LoginForSigningArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
};
void loginForSigningWithoutRemainingUses;

const loginForSigningWithLooseRecord: LoginForSigningArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  remainingUses: 3,
  // @ts-expect-error Email OTP Ed25519 signing carries records through the committed lane.
  record,
};
void loginForSigningWithLooseRecord;

const loginForSigningWithLooseWalletRouteAuth: LoginForSigningArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  remainingUses: 3,
  // @ts-expect-error Email OTP Ed25519 signing carries wallet-session auth through the committed lane.
  routeAuth: { kind: 'wallet_session', jwt: 'wallet-session-jwt' },
};
void loginForSigningWithLooseWalletRouteAuth;

const loginForSigningWithLooseAuthLane: LoginForSigningArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  remainingUses: 3,
  // @ts-expect-error Email OTP Ed25519 signing carries auth lane through the committed lane.
  authLane: { kind: 'cookie' },
};
void loginForSigningWithLooseAuthLane;

export {};
