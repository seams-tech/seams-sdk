import { toAccountId, type AccountId } from '../../../types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../../types';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../chainAdaptors/evm/ethSignerWasm';
import { getPrfResultsFromCredential } from '../../webauthn/credentials/credentialExtensions';
import {
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  enrollThresholdEd25519Key as enrollThresholdEd25519KeyValue,
  enrollThresholdEd25519KeyPostRegistration as enrollThresholdEd25519KeyPostRegistrationValue,
  rotateThresholdEd25519KeyPostRegistration as rotateThresholdEd25519KeyPostRegistrationValue,
  type ThresholdEd25519LifecycleDeps,
} from '../thresholdEd25519Lifecycle';
import type { ThresholdSessionActivationDeps } from '../thresholdSessionActivation';

type DeriveThresholdClientVerifyingShareResult =
  Awaited<ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>>;
type EnrollThresholdEd25519KeyResult = Awaited<ReturnType<typeof enrollThresholdEd25519KeyValue>>;
type RotateThresholdEd25519KeyPostRegistrationResult = Awaited<
  ReturnType<typeof rotateThresholdEd25519KeyPostRegistrationValue>
>;

export type ThresholdKeyLifecycleSurfaceDeps = {
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  thresholdSessionActivationDeps: Pick<ThresholdSessionActivationDeps, 'getSignerWorkerContext'>;
};

export type ThresholdKeyLifecycleSurface = {
  deriveThresholdEd25519ClientVerifyingShareFromCredential(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  }): Promise<DeriveThresholdClientVerifyingShareResult>;
  deriveThresholdEcdsaClientVerifyingShareFromCredential(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  }): Promise<DeriveThresholdClientVerifyingShareResult>;
  enrollThresholdEd25519KeyPostRegistration(args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  }): Promise<EnrollThresholdEd25519KeyResult>;
  rotateThresholdEd25519KeyPostRegistration(args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  }): Promise<RotateThresholdEd25519KeyPostRegistrationResult>;
  enrollThresholdEd25519Key(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
    deviceNumber?: number;
    keygenSessionId?: string;
  }): Promise<EnrollThresholdEd25519KeyResult>;
};

export function createThresholdKeyLifecycleSurface(
  deps: ThresholdKeyLifecycleSurfaceDeps,
): ThresholdKeyLifecycleSurface {
  return {
    async deriveThresholdEd25519ClientVerifyingShareFromCredential(args): Promise<DeriveThresholdClientVerifyingShareResult> {
      return await deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(
        deps.thresholdEd25519LifecycleDeps,
        args,
      );
    },
    async deriveThresholdEcdsaClientVerifyingShareFromCredential(args): Promise<DeriveThresholdClientVerifyingShareResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      try {
        const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
        if (!prfFirstB64u) {
          throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
        }
        const workerCtx = deps.thresholdSessionActivationDeps.getSignerWorkerContext();
        const derived = await deriveThresholdSecp256k1ClientShareWasm({
          prfFirstB64u,
          userId: nearAccountId,
          workerCtx,
        });
        return {
          success: true,
          nearAccountId,
          clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
        };
      } catch (error: unknown) {
        const message = String((error as { message?: unknown })?.message ?? error);
        return {
          success: false,
          nearAccountId,
          clientVerifyingShareB64u: '',
          error: message,
        };
      }
    },
    async enrollThresholdEd25519KeyPostRegistration(args): Promise<EnrollThresholdEd25519KeyResult> {
      return await enrollThresholdEd25519KeyPostRegistrationValue(
        deps.thresholdEd25519LifecycleDeps,
        args,
      );
    },
    async rotateThresholdEd25519KeyPostRegistration(args): Promise<RotateThresholdEd25519KeyPostRegistrationResult> {
      return await rotateThresholdEd25519KeyPostRegistrationValue(
        deps.thresholdEd25519LifecycleDeps,
        args,
      );
    },
    async enrollThresholdEd25519Key(args): Promise<EnrollThresholdEd25519KeyResult> {
      return await enrollThresholdEd25519KeyValue(deps.thresholdEd25519LifecycleDeps, args);
    },
  };
}
