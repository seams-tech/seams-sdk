import type {
  ConsumableEmailOtpEcdsaLane,
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  EmailOtpEcdsaPostSignMaterial,
} from '../persistence/records';
import type {
  EcdsaPostSignPolicySession,
  SecondaryEcdsaPostSignPolicyMaterial,
} from './postSignPolicy';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountId } from '@/core/types/accountIds';

declare const consumableLane: ConsumableEmailOtpEcdsaLane;
declare const sessionLane: Extract<
  EmailOtpEcdsaPostSignMaterial,
  { kind: 'session_email_otp_ecdsa_lane' }
>;
declare const secondaryMaterial: SecondaryEcdsaPostSignPolicyMaterial;
declare const walletId: AccountId;
declare const chainTarget: ThresholdEcdsaChainTarget;

void ({
  kind: 'consume_single_use_email_otp_ecdsa_lane',
  lane: consumableLane,
  uses: 1,
} satisfies ConsumeSingleUseEmailOtpEcdsaLaneCommand);

void ({
  kind: 'consume_single_use_email_otp_ecdsa_lane',
  // @ts-expect-error session-retained Email OTP lanes are not consumable.
  lane: sessionLane,
  uses: 1,
} satisfies ConsumeSingleUseEmailOtpEcdsaLaneCommand);

void ({
  kind: 'consume_single_use_email_otp_ecdsa_lane',
  // @ts-expect-error secondary material cannot carry a consumable lane.
  lane: secondaryMaterial.emailOtpPostSignMaterial,
  uses: 1,
} satisfies ConsumeSingleUseEmailOtpEcdsaLaneCommand);

void ({
  kind: 'consume_single_use_email_otp_ecdsa_lane',
  lane: consumableLane,
  uses: 1,
  // @ts-expect-error broad subject/target lookup fields are rejected.
  subjectId: 'alice.testnet',
} satisfies ConsumeSingleUseEmailOtpEcdsaLaneCommand);

void ({
  walletId,
  chainTarget,
  source: 'email_otp',
  signingGrantId: 'signing-grant',
  thresholdSessionId: 'threshold-session',
  emailOtpRetention: 'session',
  emailOtpConsumedAtMs: null,
  // @ts-expect-error post-sign policy sessions derive subject from the shared key identity.
  subjectId: 'alice.testnet',
} satisfies EcdsaPostSignPolicySession);

export {};
