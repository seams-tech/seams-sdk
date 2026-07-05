import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { EmailOtpEcdsaSealedRecoveryRecord } from '../sealedRecovery/recoveryRecord';
import type { EmailOtpEcdsaRestoreSource } from './ecdsaRecovery';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';

declare const sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
declare const ecdsaRecord: ThresholdEcdsaSessionRecord & {
  source: 'email_otp';
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  thresholdSessionKind: 'jwt';
  signingRootVersion: string;
  participantIds: [number, ...number[]];
};
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId: toWalletId('wallet_email_otp_restore'),
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  chainTargetKey: 'evm:eip155:1',
});

const restoreSourceCommon = {
  emailOtpAuthContext,
  walletSessionJwt: 'wallet-session-jwt',
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
  relayerUrl: 'https://relay.example',
  chainTarget,
  keyHandle: 'key-handle',
  evmFamilySigningKeySlotId,
  relayerKeyId: 'relayer-key-id',
  participantIds: [1, 2],
  sessionKind: 'jwt',
  signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
  signingSessionSealShamirPrimeB64u: 'prime-b64u',
} as const;

void ({
  kind: 'sealed_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
} satisfies EmailOtpEcdsaRestoreSource);

void ({
  kind: 'current_record_restore',
  sealedRecord,
  ecdsaRecord,
  ...restoreSourceCommon,
} satisfies EmailOtpEcdsaRestoreSource);

const sealedSourceWithCurrentRecord = {
  kind: 'sealed_record_restore',
  sealedRecord,
  ecdsaRecord,
  ...restoreSourceCommon,
} as const;
// @ts-expect-error sealed-source restore cannot carry current-record fallback bags.
const invalidSealedSourceWithCurrentRecord: EmailOtpEcdsaRestoreSource =
  sealedSourceWithCurrentRecord;
void invalidSealedSourceWithCurrentRecord;

const currentSourceWithoutCurrentRecord = {
  kind: 'current_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
} as const;
// @ts-expect-error current-source restore requires the current ECDSA record.
const invalidCurrentSourceWithoutCurrentRecord: EmailOtpEcdsaRestoreSource =
  currentSourceWithoutCurrentRecord;
void invalidCurrentSourceWithoutCurrentRecord;

void ({
  kind: 'sealed_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
  // @ts-expect-error restore source branches require Wallet Session JWT.
  walletSessionJwt: undefined,
} satisfies EmailOtpEcdsaRestoreSource);

export {};
