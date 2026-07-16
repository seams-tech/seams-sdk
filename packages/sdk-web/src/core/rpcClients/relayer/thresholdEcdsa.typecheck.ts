import type {
  ThresholdEcdsaDerivationRoleLocalBootstrapRequest,
  ThresholdEcdsaDerivationRoleLocalClientRootProof,
  ThresholdEcdsaDerivationRoleLocalPasskeyBootstrapAuthorization,
} from './thresholdEcdsa';
import {
  toEcdsaDerivationThresholdKeyId,
} from '../../signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import { toWalletId } from '../../signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaClientRootPublicKey33B64u,
  DerivationClientSharePublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

const bootstrapBase = {
  formatVersion: 'ecdsa-derivation-role-local',
  walletId: toWalletId('wallet-user'),
  evmFamilySigningKeySlotId: 'wallet-key-example-test',
  ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId('ecdsa-key'),
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  keyScope: 'evm-family',
  relayerKeyId: 'relayer-key',
  derivationClientSharePublicKey33B64u:
    'client-public-key' as DerivationClientSharePublicKey33B64u,
  clientShareRetryCounter: 0,
  contextBinding32B64u: 'context-binding',
  requestId: 'request-id',
  sessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  ttlMs: 60_000,
  remainingUses: 2,
  participantIds: [1, 2],
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest;

const clientRootProof = {
  version: 'ecdsa-derivation:role-local:first-bootstrap-root-proof:v2',
  clientRootPublicKey33B64u: 'public-key' as EcdsaClientRootPublicKey33B64u,
  digest32B64u: 'digest',
  signature65B64u: 'signature',
} satisfies ThresholdEcdsaDerivationRoleLocalClientRootProof;

declare const derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
void ({
  ...clientRootProof,
  // @ts-expect-error DERIVATION client-share keys cannot verify client-root proofs.
  clientRootPublicKey33B64u: derivationClientSharePublicKey33B64u,
} satisfies ThresholdEcdsaDerivationRoleLocalClientRootProof);

declare const passkeyBootstrapAuthorization: ThresholdEcdsaDerivationRoleLocalPasskeyBootstrapAuthorization;

void ({
  ...bootstrapBase,
  clientRootProof,
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  passkeyBootstrapAuthorization,
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  clientRootProof,
  passkeyBootstrapAuthorization,
  // @ts-expect-error role-local bootstrap accepts exactly one proof branch.
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects client root share material
  clientRootShare32B64u: 'client-root-share',
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects relayer export share material
  serverExportShare32B64u: 'server-export-share',
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);

void ({
  ...bootstrapBase,
  // @ts-expect-error role-local bootstrap request rejects canonical private key material
  privateKeyHex: '0x01',
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest);
