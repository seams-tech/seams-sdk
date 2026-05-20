import type {
  ThresholdEcdsaHssRoleLocalBootstrapRequest,
  ThresholdEcdsaHssRoleLocalClientRootProof,
  ThresholdEcdsaHssRoleLocalPasskeyFirstBootstrapAuthorization,
} from './thresholdEcdsa';
import {
  toEcdsaHssThresholdKeyId,
  toEcdsaHssWalletSubjectId,
  toWalletSessionUserId,
} from '../../signingEngine/session/identity/emailOtpHssIdentity';

const bootstrapBase = {
  formatVersion: 'ecdsa-hss-role-local',
  walletSessionUserId: toWalletSessionUserId('wallet-user'),
  rpId: 'wallet.example.test',
  subjectId: toEcdsaHssWalletSubjectId('wallet-user'),
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ecdsa-key'),
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  keyScope: 'evm-family',
  relayerKeyId: 'relayer-key',
  clientPublicKey33B64u: 'client-public-key',
  clientShareRetryCounter: 0,
  contextBinding32B64u: 'context-binding',
  requestId: 'request-id',
  sessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  ttlMs: 60_000,
  remainingUses: 2,
  participantIds: [1, 2],
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;

const clientRootProof = {
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v1',
  digest32B64u: 'digest',
  signature65B64u: 'signature',
} satisfies ThresholdEcdsaHssRoleLocalClientRootProof;

declare const passkeyFirstBootstrapAuthorization: ThresholdEcdsaHssRoleLocalPasskeyFirstBootstrapAuthorization;

void ({
  ...bootstrapBase,
  clientRootProof,
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  passkeyFirstBootstrapAuthorization,
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  clientRootProof,
  passkeyFirstBootstrapAuthorization,
  // @ts-expect-error role-local bootstrap accepts exactly one first-bootstrap authorization branch
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects client root share material
  clientRootShare32B64u: 'client-root-share',
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects relayer export share material
  serverExportShare32B64u: 'server-export-share',
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects canonical private key material
  privateKeyHex: '0x01',
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);
