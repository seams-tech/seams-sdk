import type {
  ThresholdEcdsaHssRoleLocalBootstrapRequest,
  ThresholdEcdsaHssRoleLocalClientRootProof,
  ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization,
} from './thresholdEcdsa';
import {
  toEcdsaHssThresholdKeyId,
} from '../../signingEngine/session/identity/emailOtpHssIdentity';
import { toWalletId } from '../../signingEngine/interfaces/ecdsaChainTarget';

const bootstrapBase = {
  formatVersion: 'ecdsa-hss-role-local',
  walletId: toWalletId('wallet-user'),
  rpId: 'wallet.example.test',
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
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
  digest32B64u: 'digest',
  signature65B64u: 'signature',
} satisfies ThresholdEcdsaHssRoleLocalClientRootProof;

declare const passkeyBootstrapAuthorization: ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization;

void ({
  ...bootstrapBase,
  clientRootProof,
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  passkeyBootstrapAuthorization,
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  clientRootProof,
  passkeyBootstrapAuthorization,
  // @ts-expect-error role-local bootstrap accepts exactly one proof branch.
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects legacy wallet session aliases.
  walletSessionUserId: 'wallet-user',
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects legacy subject ids.
  subjectId: 'wallet-subject',
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
