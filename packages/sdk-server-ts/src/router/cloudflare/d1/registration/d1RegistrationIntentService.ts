import {
  addAuthMethodIntentGrantFromString,
  addSignerIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  normalizeAddAuthMethodInput,
  normalizeAddSignerSelection,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { ThresholdRuntimePolicyScope } from '../../../../core/types';
import type {
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
} from '../../../../core/registrationContracts';
import { thresholdEcdsaChainTargetFromValue } from '../../../../core/thresholdEcdsaChainTarget';
import { CloudflareD1RegistrationCeremonyIntentStore } from './d1RegistrationCeremonyStore';
import {
  buildAddAuthMethodIntent,
  buildAddSignerIntent,
  inferRuntimePolicyScopeFromSigningRoot,
  intentScopeMetadata,
  parseWalletIdForIntent,
} from './d1RegistrationCeremonyRecords';
import type {
  CreateAddAuthMethodIntentCommand,
  CreateAddSignerIntentCommand,
} from '../../../framework/authServicePort';

type CreateAddSignerIntentInput = {
  readonly command: CreateAddSignerIntentCommand;
  readonly orgId: string;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
};
type CreateAddAuthMethodIntentInput = {
  readonly command: CreateAddAuthMethodIntentCommand;
  readonly orgId: string;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
};

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1RegistrationIntentService {
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;

  constructor(input: {
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  }) {
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
  }

  async createAddSignerIntent(
    input: CreateAddSignerIntentInput,
  ): Promise<CreateAddSignerIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const walletId = parseWalletIdForIntent(input.command.subject.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }

      const signerSelection = normalizeAddSignerSelection(input.command.signerSelection, {
        normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
      });
      if (!signerSelection.ok) return signerSelection;

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildAddSignerIntent({
        walletId,
        signerSelection: signerSelection.value,
        runtimePolicyScope,
      });
      const digestB64u = await computeAddSignerIntentDigestB64u(intent);
      const grant = addSignerIntentGrantFromString(`wasig_${secureRandomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await store.putAddSignerIntent({
        kind: 'add_signer_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...intentScopeMetadata(input),
      });
      return {
        ok: true,
        intent,
        addSignerIntentDigestB64u: digestB64u,
        addSignerIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-signer intent',
      };
    }
  }

  async createAddAuthMethodIntent(
    input: CreateAddAuthMethodIntentInput,
  ): Promise<CreateAddAuthMethodIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const walletId = parseWalletIdForIntent(input.command.subject.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const authMethod = normalizeAddAuthMethodInput(input.command.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildAddAuthMethodIntent({
        walletId,
        authMethod,
        runtimePolicyScope,
      });
      const digestB64u = await computeAddAuthMethodIntentDigestB64u(intent);
      const grant = addAuthMethodIntentGrantFromString(`waig_${secureRandomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await store.putAddAuthMethodIntent({
        kind: 'add_auth_method_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...intentScopeMetadata(input),
      });
      return {
        ok: true,
        intent,
        addAuthMethodIntentDigestB64u: digestB64u,
        addAuthMethodIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-auth-method intent',
      };
    }
  }

}
