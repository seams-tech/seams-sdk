import {
  buildRecoveryEmailBody,
  buildRecoveryEmailSubject,
  type RecoveryEmailPayload,
} from '../../packages/shared-ts/src/utils/recoveryEmail.ts';
import type {
  MultichainRecoveryPayloadFields,
  RecoverySubjectBinding,
  RecoveryTargetKeySet,
} from '../../packages/shared-ts/src/utils/recoveryDomain.ts';
import type { EmailRecoveryRequest } from '../../packages/sdk-server-ts/src/email-recovery/types.ts';
import type {
  DerivedRecoveryKeys,
  PendingEmailRecovery,
} from '../../packages/sdk-web/src/core/types/emailRecovery.ts';

const subject: RecoverySubjectBinding = {
  nearAccountId: 'alice.testnet',
  recoverySessionId: 'ABC123',
  deadlineEpochSeconds: 1_893_456_000,
  scope: 'full-account-recovery',
};

const targetKeys: RecoveryTargetKeySet = {
  newNearPublicKey: 'ed25519:recovery-key',
  newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
};

const fields: MultichainRecoveryPayloadFields = {
  ...subject,
  ...targetKeys,
};

const payload: RecoveryEmailPayload = {
  version: 'recovery_email_payload_v1',
  ...fields,
};

const request: EmailRecoveryRequest = {
  accountId: subject.nearAccountId,
  emailBlob: 'Subject: recover-v1 alice.testnet ABC123',
  recoveryPayload: payload,
};

const pending: PendingEmailRecovery = {
  accountId: subject.nearAccountId,
  signerSlot: 1,
  requestId: 'REQ123',
  recoverySessionId: subject.recoverySessionId,
  nearPublicKey: targetKeys.newNearPublicKey,
  newEvmOwnerAddress: targetKeys.newEvmOwnerAddress,
  deadlineEpochSeconds: subject.deadlineEpochSeconds,
  recoveryEmailPayloadHash: 'sha256:demo',
  recoveryEmailSubject: buildRecoveryEmailSubject(payload),
  recoveryEmailBody: buildRecoveryEmailBody(payload),
  credential: {
    id: 'credential-id',
    rawId: 'credential-raw-id',
    response: {
      clientDataJSON: 'client-data',
      attestationObject: 'attestation-object',
      transports: ['internal'],
    },
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: { prf: { results: { first: undefined, second: undefined } } },
  },
  createdAt: 1,
  status: 'awaiting-email',
};

const derived: DerivedRecoveryKeys = {
  nearPublicKey: targetKeys.newNearPublicKey,
  evmOwnerAddress: targetKeys.newEvmOwnerAddress,
};

console.log(
  'RESULT:' +
    JSON.stringify({
      payloadVersion: payload.version,
      accountId: request.accountId,
      recoverySessionId: pending.recoverySessionId,
      deadlineEpochSeconds: pending.deadlineEpochSeconds,
      derivedEvmOwnerAddress: derived.evmOwnerAddress,
      bodyPrefix: pending.recoveryEmailBody.split('\n')[1]?.split(':')[0] || '',
    }),
);
