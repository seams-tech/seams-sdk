import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildThresholdEd25519SessionRecordKey,
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  serializeThresholdEd25519SessionLaneKey,
  type EmailOtpEcdsaSessionRecord,
  type ThresholdEd25519SessionRecordKey,
} from './records';
import { SigningSessionIds } from '../operationState/types';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';

const walletId = toWalletId('frost-typecheck-k7p9m2');
const nearAccountId = toAccountId('c'.repeat(64));
const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId('ed25519ks_typecheck');
const signingGrantId = SigningSessionIds.signingGrant('grant-typecheck');
const thresholdSessionId = SigningSessionIds.thresholdEd25519Session('tsess-typecheck');
const signerSlot = parseSignerSlot(1);
if (!signerSlot) throw new Error('signerSlot fixture is invalid');

const exactLaneKey: ThresholdEd25519SessionRecordKey = {
  walletId,
  nearAccountId,
  nearEd25519SigningKeyId,
  authMethod: 'passkey',
  signingGrantId,
  thresholdSessionId,
  signerSlot,
};

clearStoredThresholdEd25519SessionRecordForLaneKey(exactLaneKey);
serializeThresholdEd25519SessionLaneKey(exactLaneKey);

// Boundary builders can normalize raw input into the exact lane-key type.
clearStoredThresholdEd25519SessionRecordForLaneKey(
  buildThresholdEd25519SessionRecordKey({
    walletId: 'frost-typecheck-k7p9m2',
    nearAccountId: 'c'.repeat(64),
    nearEd25519SigningKeyId: 'ed25519ks_typecheck',
    authMethod: 'passkey',
    signingGrantId: 'grant-typecheck',
    thresholdSessionId: 'tsess-typecheck',
    signerSlot: 1,
  }),
);

const rawLaneKeyBag = {
  walletId: 'frost-typecheck-k7p9m2',
  nearAccountId: 'c'.repeat(64),
  nearEd25519SigningKeyId: 'ed25519ks_typecheck',
  authMethod: 'passkey',
  signingGrantId: 'grant-typecheck',
  thresholdSessionId: 'tsess-typecheck',
  signerSlot: 1,
};

// @ts-expect-error exact lane clearing rejects raw string bags.
clearStoredThresholdEd25519SessionRecordForLaneKey(rawLaneKeyBag);

const wrongGrantLaneKey: ThresholdEd25519SessionRecordKey = {
  walletId,
  nearAccountId,
  nearEd25519SigningKeyId,
  authMethod: 'passkey',
  // @ts-expect-error signingGrantId cannot be a threshold Ed25519 session id.
  signingGrantId: thresholdSessionId,
  thresholdSessionId,
  signerSlot,
};
void wrongGrantLaneKey;

const wrongSessionLaneKey: ThresholdEd25519SessionRecordKey = {
  walletId,
  nearAccountId,
  nearEd25519SigningKeyId,
  authMethod: 'passkey',
  signingGrantId,
  // @ts-expect-error thresholdSessionId cannot be a signing grant id.
  thresholdSessionId: signingGrantId,
  signerSlot,
};
void wrongSessionLaneKey;

const wrongSlotLaneKey: ThresholdEd25519SessionRecordKey = {
  walletId,
  nearAccountId,
  nearEd25519SigningKeyId,
  authMethod: 'passkey',
  signingGrantId,
  thresholdSessionId,
  // @ts-expect-error signerSlot must come from the positive signer-slot parser.
  signerSlot: 1,
};
void wrongSlotLaneKey;

const weakAccountId: AccountId = 'c'.repeat(64);

serializeThresholdEd25519SessionLaneKey({
  ...exactLaneKey,
  // @ts-expect-error lane-key serialization requires the strict account id brand.
  nearAccountId: weakAccountId,
});

declare const emailOtpEcdsaSessionRecord: EmailOtpEcdsaSessionRecord;
emailOtpEcdsaSessionRecord.walletSessionJwt.toUpperCase();

const emailOtpEcdsaSessionRecordWithoutJwt: EmailOtpEcdsaSessionRecord = {
  ...emailOtpEcdsaSessionRecord,
  // @ts-expect-error Email OTP ECDSA session records require walletSessionJwt.
  walletSessionJwt: undefined,
};
void emailOtpEcdsaSessionRecordWithoutJwt;

const emailOtpEcdsaCookieSessionRecord: EmailOtpEcdsaSessionRecord = {
  ...emailOtpEcdsaSessionRecord,
  // @ts-expect-error Email OTP ECDSA session records are JWT-backed.
  thresholdSessionKind: 'cookie',
};
void emailOtpEcdsaCookieSessionRecord;

export {};
