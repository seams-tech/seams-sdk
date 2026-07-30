import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type { EmailOtpEcdsaSealedRecoveryRecord } from '../sealedRecovery/recoveryRecord';
import type { EmailOtpEcdsaRestoreSource } from './ecdsaRecovery';

declare const sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
const restoreSourceCommon = {
  emailOtpAuthContext,
  walletSessionJwt: 'wallet-session-jwt',
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
  relayerUrl: 'https://relay.example',
  chainTarget,
  keyHandle: 'key-handle',
  relayerKeyId: 'relayer-key-id',
  participantIds: [1, 2],
  sessionKind: 'jwt',
  signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
  signingSessionSealGroupId: 'prime-b64u',
} as const;

void ({
  kind: 'sealed_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
} satisfies EmailOtpEcdsaRestoreSource);

void ({
  kind: 'sealed_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
  // @ts-expect-error sealed restore cannot carry a composite current-record fallback.
  ecdsaRecord: {},
} satisfies EmailOtpEcdsaRestoreSource);

void ({
  kind: 'sealed_record_restore',
  sealedRecord,
  ...restoreSourceCommon,
  // @ts-expect-error restore source branches require Wallet Session JWT.
  walletSessionJwt: undefined,
} satisfies EmailOtpEcdsaRestoreSource);

export {};
