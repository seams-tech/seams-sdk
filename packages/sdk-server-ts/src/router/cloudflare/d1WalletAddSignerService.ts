import {
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondRequest,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse
} from '../../core/registrationContracts';
import type { WalletStore } from '../../core/d1WalletStore';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildD1EcdsaAddSignerRespondedCeremony,
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  isMatchingD1EcdsaClientBootstrap,
  normalizeThresholdEcdsaChainTargets,
  parseD1RuntimePolicyScope,
  parseWalletIdForIntent,
  toD1EcdsaHssClientBootstrapRequest,
} from './d1RegistrationCeremonyRecords';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';

type StartWalletAddSignerInput = WalletAddSignerStartRequest;
type RespondWalletAddSignerHssInput = WalletAddSignerHssRespondRequest;
type FinalizeWalletAddSignerInput = WalletAddSignerFinalizeRequest;

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type ThresholdSigningServiceProvider = () => ThresholdSigningService | null;
type WalletStoreProvider = () => WalletStore;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function hasUnexpectedKeyHandle(expectedKeyHandles: readonly string[], keyHandle: string): boolean {
  return expectedKeyHandles.length > 0 && !expectedKeyHandles.includes(keyHandle);
}

export class CloudflareD1WalletAddSignerService {
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getThresholdSigningService: ThresholdSigningServiceProvider;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getThresholdSigningService: ThresholdSigningServiceProvider;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getThresholdSigningService = input.getThresholdSigningService;
    this.getWalletStore = input.getWalletStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async startWalletAddSigner(
    request: StartWalletAddSignerInput,
  ): Promise<WalletAddSignerStartResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(request.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addSignerIntentGrantFromString(
        toOptionalTrimmedString(request.addSignerIntentGrant) || '',
      );
      if (!grant) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant is required' };
      }
      const intentPreview = await store.getAddSignerIntent(grant);
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      if (request.intent.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-signer walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addSignerIntentDigestB64u);
      const requestDigest = await computeAddSignerIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'add-signer intent digest mismatch' };
      }
      if (intentPreview.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer start currently supports ECDSA signer selection',
        };
      }

      const storedAuth = await this.walletAuthMethods.resolveAddSignerExistingAuth({
        auth: request.auth,
        walletId,
        intent: intentPreview.intent,
        nowMs: Date.now(),
      });
      if (!storedAuth.ok) return storedAuth;

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }

      const storedIntent = await store.takeAddSignerIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      const selection = storedIntent.intent.signerSelection;
      if (selection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer start currently supports ECDSA signer selection',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(storedIntent.intent.runtimePolicyScope);
      if (!runtimePolicyScope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer requires a runtime policy scope',
        };
      }
      const signingRootId = storedIntent.signingRootId || deriveSigningRootId(runtimePolicyScope);
      const signingRootVersion =
        toOptionalTrimmedString(storedIntent.signingRootVersion) ||
        runtimePolicyScope.signingRootVersion;
      const chainTargets = normalizeThresholdEcdsaChainTargets(selection.ecdsa.chainTargets);
      if (!chainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer contains an invalid chain target',
        };
      }

      const addSignerCeremonyId = `wasc_${secureRandomBase64Url(24)}`;
      const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationCeremonyId: addSignerCeremonyId,
        walletId,
        signingRootId,
        signingRootVersion,
        chainTargets,
        participantIds: [...selection.ecdsa.participantIds],
        runtimePolicyScope,
      });
      if (!prepared.ok) return prepared;
      const ecdsa = prepared.ecdsa;
      await store.putAddSignerCeremony({
        addSignerCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: runtimePolicyScope.orgId,
        signingRootId,
        signingRootVersion,
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: storedAuth.auth,
        signerState: {
          kind: 'ecdsa_add_signer_prepared',
          hssKind: ecdsa.kind,
          chainTargets,
          prepare: ecdsa.prepare,
        },
      });
      return {
        ok: true,
        addSignerCeremonyId,
        intent: storedIntent.intent,
        ecdsa,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-signer ceremony',
      };
    }
  }

  async respondWalletAddSignerHss(
    request: RespondWalletAddSignerHssInput,
  ): Promise<WalletAddSignerHssRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer respond currently supports ECDSA signer selection',
        };
      }
      if (!request.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing ECDSA add-signer HSS response',
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response already recorded',
        };
      }
      const expected = ceremony.signerState.prepare;
      const actual = request.ecdsa.clientBootstrap;
      if (!isMatchingD1EcdsaClientBootstrap({ expected, actual })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer bootstrap identity mismatch',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(
        toD1EcdsaHssClientBootstrapRequest(actual),
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'ECDSA add-signer HSS bootstrap failed',
        };
      }
      await store.updateAddSignerCeremony(
        buildD1EcdsaAddSignerRespondedCeremony({
          ceremony,
          bootstrap: bootstrap.value,
        }),
      );
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          bootstrap: bootstrap.value,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet add-signer ceremony',
      };
    }
  }

  async finalizeWalletAddSigner(
    request: FinalizeWalletAddSignerInput,
  ): Promise<WalletAddSignerFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer finalize currently supports ECDSA signer selection',
        };
      }
      if (!request.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing ECDSA add-signer finalize input',
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response is required before finalize',
        };
      }
      const bootstrap = ceremony.signerState.responded.bootstrap;
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      if (hasUnexpectedKeyHandle(expectedKeyHandles, bootstrap.keyHandle)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA add-signer finalize expected key handle mismatch',
        };
      }
      const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
        bootstrap,
        chainTargets: ceremony.signerState.chainTargets,
        errorContext: 'ECDSA add-signer finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;

      const walletKeys = walletKeyResult.walletKeys;
      const signerWriteNow = Date.now();
      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        now: signerWriteNow,
      });
      const walletSigners = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys,
        now: signerWriteNow,
      });
      const walletStore = this.getWalletStore();
      await walletStore.putSubject(wallet);
      await walletStore.putSigners(walletSigners);

      const consumed = await store.takeAddSignerCeremony(ceremony.addSignerCeremonyId);
      if (!consumed) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (consumed.signerState.kind !== 'ecdsa_add_signer_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA add-signer HSS response is required before finalize',
        };
      }
      return {
        ok: true,
        walletId: ceremony.intent.walletId,
        ...(ceremony.auth.kind === 'webauthn_assertion' ? { rpId: ceremony.auth.rpId } : {}),
        ecdsa: {
          walletKeys,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-signer ceremony',
      };
    }
  }
}
