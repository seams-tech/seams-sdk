import {
  addAuthMethodIntentGrantFromString,
  addSignerIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanNearEd25519Branch,
  normalizeAddAuthMethodInput,
  normalizeAddSignerSelection,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerPlan,
  parseServerAllocatedWalletId,
  registrationIntentGrantFromString,
  registrationSignerSetSelectionFromPlan,
  type RegistrationSignerPlan,
  type RegisterWalletInput,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentResponse,
} from '../../core/types';
import { thresholdEcdsaChainTargetFromValue } from '../../core/thresholdEcdsaChainTarget';
import type { RouterApiAuthService } from '../authServicePort';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildAddAuthMethodIntent,
  buildAddSignerIntent,
  buildRegistrationIntent,
  createD1ServerAllocatedWalletId,
  inferRuntimePolicyScopeFromSigningRoot,
  intentScopeMetadata,
  parseWalletIdForIntent,
} from './d1RegistrationCeremonyRecords';

type CreateRegistrationIntentInput = Parameters<
  RouterApiAuthService['createRegistrationIntent']
>[0];
type CreateAddSignerIntentInput = Parameters<
  RouterApiAuthService['createAddSignerIntent']
>[0];
type CreateAddAuthMethodIntentInput = Parameters<
  RouterApiAuthService['createAddAuthMethodIntent']
>[0];

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type SignerWalletExistenceStore = {
  signerWalletExists(walletId: string): Promise<boolean>;
};

type RegistrationIntentWalletResolution =
  | {
      readonly ok: true;
      readonly walletId: WalletId;
      readonly code?: never;
      readonly message?: never;
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_body' | 'wallet_id_collision' | 'configuration';
      readonly message: string;
      readonly walletId?: never;
    };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

export class CloudflareD1RegistrationIntentService {
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly signerWallets: SignerWalletExistenceStore;

  constructor(input: {
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly signerWallets: SignerWalletExistenceStore;
  }) {
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.signerWallets = input.signerWallets;
  }

  async createRegistrationIntent(
    input: CreateRegistrationIntentInput,
  ): Promise<CreateRegistrationIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();

      const signerPlan = normalizeRegistrationSignerPlan(input.request?.signerSelection);
      if (!signerPlan.ok) return signerPlan;
      const signerSelection = registrationSignerSetSelectionFromPlan(signerPlan.value, {
        normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
      });
      if (!signerSelection.ok) return signerSelection;
      const authMethod = normalizeRegistrationAuthMethodInput(input.request?.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const expiresAtMs = Date.now() + 5 * 60_000;
      const wallet = await this.resolveRegistrationIntentWalletId({
        store,
        wallet: input.request?.wallet,
        signerPlan: signerPlan.value,
        expiresAtMs,
      });
      if (!wallet.ok) return wallet;

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent = buildRegistrationIntent({
        walletId: wallet.walletId,
        authMethod,
        signerSelection: signerSelection.value,
        runtimePolicyScope,
      });
      const digestB64u = await computeRegistrationIntentDigestB64u(intent);
      const grant = registrationIntentGrantFromString(`rig_${secureRandomBase64Url(32)}`);
      await store.putIntent({
        kind: 'intent_allocated',
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
        registrationIntentDigestB64u: digestB64u,
        registrationIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create registration intent',
      };
    }
  }

  async createAddSignerIntent(
    input: CreateAddSignerIntentInput,
  ): Promise<CreateAddSignerIntentResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(input.request?.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }

      const signerSelection = normalizeAddSignerSelection(input.request?.signerSelection, {
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
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(input.request?.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const authMethod = normalizeAddAuthMethodInput(input.request?.authMethod);
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

  private async createAvailableServerAllocatedWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const walletId = createD1ServerAllocatedWalletId();
      const existing = await this.signerWallets.signerWalletExists(walletId);
      if (existing) continue;
      const reserved = await input.store.reserveServerAllocatedWalletId({
        walletId,
        expiresAtMs: input.expiresAtMs,
      });
      if (reserved) return { ok: true, walletId };
    }
    return {
      ok: false,
      code: 'wallet_id_collision',
      message: 'Unable to allocate an unused server-allocated walletId',
    };
  }

  private async reserveProvidedImplicitWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly walletId: unknown;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    const parsed = parseServerAllocatedWalletId(input.walletId);
    if (!parsed.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'implicit account registration requires a generated readable walletId',
      };
    }
    const existing = await this.signerWallets.signerWalletExists(parsed.value);
    if (existing) {
      return {
        ok: false,
        code: 'wallet_id_collision',
        message: 'walletId is already registered',
      };
    }
    const reserved = await input.store.reserveServerAllocatedWalletId({
      walletId: parsed.value,
      expiresAtMs: input.expiresAtMs,
    });
    if (!reserved) {
      return {
        ok: false,
        code: 'wallet_id_collision',
        message: 'walletId is already reserved',
      };
    }
    return { ok: true, walletId: parsed.value };
  }

  private async resolveGenericRegistrationWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly wallet: RegisterWalletInput | undefined;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    if (!input.wallet || input.wallet.kind === 'server_allocated') {
      return await this.createAvailableServerAllocatedWalletId(input);
    }
    if (input.wallet.kind === 'provided') {
      const walletId = parseWalletIdForIntent(input.wallet.walletId);
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      return { ok: true, walletId };
    }
    return { ok: false, code: 'invalid_body', message: 'wallet.kind is unsupported' };
  }

  private async resolveRegistrationIntentWalletId(input: {
    readonly store: CloudflareD1RegistrationCeremonyIntentStore;
    readonly wallet: RegisterWalletInput | undefined;
    readonly signerPlan: RegistrationSignerPlan;
    readonly expiresAtMs: number;
  }): Promise<RegistrationIntentWalletResolution> {
    const nearEd25519 = findRegistrationSignerPlanNearEd25519Branch(input.signerPlan);
    if (!nearEd25519) {
      return await this.resolveGenericRegistrationWalletId(input);
    }
    const provisioning = nearEd25519.accountProvisioning;
    switch (provisioning.kind) {
      case 'implicit_account':
        if (input.wallet?.kind === 'provided') {
          return await this.reserveProvidedImplicitWalletId({
            store: input.store,
            walletId: input.wallet.walletId,
            expiresAtMs: input.expiresAtMs,
          });
        }
        return await this.createAvailableServerAllocatedWalletId(input);
      case 'sponsored_named_account': {
        if (input.wallet?.kind !== 'provided') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'sponsored named registration requires a provided walletId',
          };
        }
        const walletId = parseWalletIdForIntent(input.wallet.walletId);
        if (!walletId) {
          return { ok: false, code: 'invalid_body', message: 'walletId is required' };
        }
        return { ok: true, walletId };
      }
      default: {
        const exhaustive: never = provisioning;
        return {
          ok: false,
          code: 'invalid_body',
          message: `unsupported account provisioning: ${String(exhaustive)}`,
        };
      }
    }
  }
}
