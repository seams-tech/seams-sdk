import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpSessionAuthContext } from '../identity/laneIdentity';
import type { EmailOtpEcdsaSealedRecoveryRecord } from '../sealedRecovery/recoveryRecord';
import type { EmailOtpEcdsaRestoreSource } from './ecdsaRecovery';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';

declare const sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const emailOtpAuthContext: ThresholdEcdsaEmailOtpSessionAuthContext;
declare const authorization: ExactEvmFamilyWalletSessionAuthorization;
const restoreSourceCommon = {
  emailOtpAuthContext,
  authorization,
  relayerUrl: 'https://relay.example',
  chainTarget,
  keyHandle: 'key-handle',
  relayerKeyId: 'relayer-key-id',
  participantIds: [1, 2],
  signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
  signingSessionSealGroupId: 'prime-b64u',
} as const;
const { authorization: _authorization, ...restoreSourceWithoutAuthorization } = restoreSourceCommon;
void _authorization;

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
  ...restoreSourceWithoutAuthorization,
  // @ts-expect-error restore source requires the exact identity-coupled authorization.
  authorization: undefined,
} satisfies EmailOtpEcdsaRestoreSource);

export {};
