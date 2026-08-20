/**
 * Public boundary references.
 *
 * `WalletSessionRef`, `NearAccountRef` and `ThresholdEcdsaChainTarget` name the
 * exact subject and target a wallet operation authorizes. Every signing, export
 * and session call takes them, so they belong on the entrypoints an application
 * already imports — not behind `@seams/wallet/advanced`.
 *
 * This module only re-exports: the implementations stay in
 * `core/signingEngine/interfaces/ecdsaChainTarget.ts`, which is the path the
 * capability-binding source guards hold jurisdiction over.
 */
export {
  configuredThresholdEcdsaChainTargets,
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetFromConfiguredRequest,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  walletIdFromWalletProfile,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type {
  EcdsaCommandSubject,
  EvmEip155ChainTarget,
  NearAccountRef,
  NearCommandSubject,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
