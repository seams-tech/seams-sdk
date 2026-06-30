import type {
  ThresholdEcdsaHssRoleLocalBootstrapRequest,
  ThresholdEcdsaHssRoleLocalClientRootProof,
  ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization,
} from './thresholdEcdsa';
import {
  toEcdsaHssThresholdKeyId,
} from '../../signingEngine/session/identity/emailOtpHssIdentity';
import { toWalletId } from '../../signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaClientRootPublicKey33B64u,
  EcdsaHssClientSharePublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

const bootstrapBase = {
  formatVersion: 'ecdsa-hss-role-local',
  walletId: toWalletId('wallet-user'),
  evmFamilySigningKeySlotId: 'wallet-key-example-test',
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ecdsa-key'),
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  keyScope: 'evm-family',
  relayerKeyId: 'relayer-key',
  hssClientSharePublicKey33B64u:
    'client-public-key' as EcdsaHssClientSharePublicKey33B64u,
  clientShareRetryCounter: 0,
  contextBinding32B64u: 'context-binding',
  requestId: 'request-id',
  sessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  ttlMs: 60_000,
  remainingUses: 2,
  participantIds: [1, 2],
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;

const clientRootProof = {
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
  clientRootPublicKey33B64u: 'public-key' as EcdsaClientRootPublicKey33B64u,
  digest32B64u: 'digest',
  signature65B64u: 'signature',
} satisfies ThresholdEcdsaHssRoleLocalClientRootProof;

declare const hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
void ({
  ...clientRootProof,
  // @ts-expect-error HSS client-share keys cannot verify client-root proofs.
  clientRootPublicKey33B64u: hssClientSharePublicKey33B64u,
} satisfies ThresholdEcdsaHssRoleLocalClientRootProof);

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
