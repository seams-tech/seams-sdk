import type { SecureConfirmWorkerManager } from '../../secureConfirm';
import type { AccountId } from '../../../types/accountIds';
import type { OrchestrationDependencyBundle } from '../bootstrap/orchestrationDependencyFactory';
import {
  createIndexedDbRegistrationSurface,
  type IndexedDbRegistrationSurface,
} from './indexedDbRegistrationSurface';
import {
  createSigningActionsSurface,
  type SigningActionsSurface,
} from './signingActionsSurface';
import {
  createCredentialRecoverySurface,
  type CredentialRecoverySurface,
} from './credentialRecoverySurface';
import {
  createThresholdSessionSurface,
  type ThresholdSessionSurface,
} from './thresholdSessionSurface';
import {
  createThresholdKeyLifecycleSurface,
  type ThresholdKeyLifecycleSurface,
} from './thresholdKeyLifecycleSurface';

export type WebAuthnManagerDomains = {
  indexedDbRegistration: IndexedDbRegistrationSurface;
  signingActions: SigningActionsSurface;
  credentialRecovery: CredentialRecoverySurface;
  thresholdSession: ThresholdSessionSurface;
  thresholdKeyLifecycle: ThresholdKeyLifecycleSurface;
};

export type CreateWebAuthnManagerDomainsArgs = {
  orchestrationDeps: OrchestrationDependencyBundle;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
  activeSigningSessionIds: Map<string, string>;
  thresholdEcdsaSignInFlightByAccount: Set<string>;
  withThresholdEcdsaBootstrapQueue: <T>(
    nearAccountId: AccountId,
    task: () => Promise<T>,
  ) => Promise<T>;
};

export function createWebAuthnManagerDomains(
  args: CreateWebAuthnManagerDomainsArgs,
): WebAuthnManagerDomains {
  return {
    indexedDbRegistration: createIndexedDbRegistrationSurface({
      indexedDbFacadeDeps: args.orchestrationDeps.indexedDbFacadeDeps,
      registrationAccountLifecycleDeps: args.orchestrationDeps.registrationAccountLifecycleDeps,
    }),
    signingActions: createSigningActionsSurface({
      nearSigningDeps: args.orchestrationDeps.nearSigningDeps,
      tempoSigningDeps: args.orchestrationDeps.tempoSigningDeps,
      getFacadeConvenienceDeps: args.orchestrationDeps.getFacadeConvenienceDeps,
      thresholdEcdsaSignInFlightByAccount: args.thresholdEcdsaSignInFlightByAccount,
    }),
    credentialRecovery: createCredentialRecoverySurface({
      registrationSessionDeps: args.orchestrationDeps.registrationSessionDeps,
      nearKeyDerivationDeps: args.orchestrationDeps.nearKeyDerivationDeps,
      privateKeyExportRecoveryDeps: args.orchestrationDeps.privateKeyExportRecoveryDeps,
      signerWorkerBridgeDeps: args.orchestrationDeps.signerWorkerBridgeDeps,
    }),
    thresholdSession: createThresholdSessionSurface({
      thresholdSessionActivationDeps: args.orchestrationDeps.thresholdSessionActivationDeps,
      getFacadeConvenienceDeps: args.orchestrationDeps.getFacadeConvenienceDeps,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      activeSigningSessionIds: args.activeSigningSessionIds,
      withThresholdEcdsaBootstrapQueue: args.withThresholdEcdsaBootstrapQueue,
    }),
    thresholdKeyLifecycle: createThresholdKeyLifecycleSurface({
      thresholdEd25519LifecycleDeps: args.orchestrationDeps.thresholdEd25519LifecycleDeps,
      thresholdSessionActivationDeps: args.orchestrationDeps.thresholdSessionActivationDeps,
    }),
  };
}
