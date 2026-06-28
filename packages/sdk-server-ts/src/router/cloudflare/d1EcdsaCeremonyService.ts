import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  addSignerIntentGrantFromString,
  registrationIntentGrantFromString,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartResponse,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationStartResponse,
} from '../../core/types';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type { WalletStore } from '../../core/d1WalletStore';
import type { CloudflareRouterApiAuthService } from '../authServicePort';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildD1EcdsaAddSignerRespondedCeremony,
  buildD1EcdsaRegistrationRespondedCeremony,
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  derivePlannedEvmFamilyWalletKeyId,
  isMatchingD1EcdsaClientBootstrap,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RuntimePolicyScope,
  parseWalletIdForIntent,
  toD1EcdsaHssClientBootstrapRequest,
} from './d1RegistrationCeremonyRecords';
import { walletRegistrationFinalizeAuthMethodFromAuthority } from './d1WalletAuthMethodBoundary';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

type StartWalletRegistrationInput = Parameters<
  CloudflareRouterApiAuthService['startWalletRegistration']
>[0];
type RespondWalletRegistrationHssInput = Parameters<
  CloudflareRouterApiAuthService['respondWalletRegistrationHss']
>[0];
type FinalizeWalletRegistrationInput = Parameters<
  CloudflareRouterApiAuthService['finalizeWalletRegistration']
>[0];
type StartWalletAddSignerInput = Parameters<CloudflareRouterApiAuthService['startWalletAddSigner']>[0];
type RespondWalletAddSignerHssInput = Parameters<
  CloudflareRouterApiAuthService['respondWalletAddSignerHss']
>[0];
type FinalizeWalletAddSignerInput = Parameters<
  CloudflareRouterApiAuthService['finalizeWalletAddSigner']
>[0];

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type ThresholdSigningServiceProvider = () => ThresholdSigningService | null;
type WalletStoreProvider = () => WalletStore;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function hasUnexpectedKeyHandle(
  expectedKeyHandles: readonly string[],
  keyHandle: string,
): boolean {
  for (const expectedKeyHandle of expectedKeyHandles) {
    if (expectedKeyHandle !== keyHandle) return true;
  }
  return false;
}

export class CloudflareD1EcdsaCeremonyService {
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getThresholdSigningService: ThresholdSigningServiceProvider;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getThresholdSigningService: ThresholdSigningServiceProvider;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.emailOtpRegistrationEnrollmentFinalizer =
      input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getThresholdSigningService = input.getThresholdSigningService;
    this.getWalletStore = input.getWalletStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async startWalletRegistration(
    request: StartWalletRegistrationInput,
  ): Promise<WalletRegistrationStartResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const grant = registrationIntentGrantFromString(
        toOptionalTrimmedString(request.registrationIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'registration intent grant is required',
        };
      }
      const intentPreview = await store.getIntent(grant);
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent digest mismatch',
        };
      }
      const selection = intentPreview.intent.signerSelection;
      if (selection.mode !== 'ecdsa_only') {
        return {
          ok: false,
          code: 'unsupported',
          message:
            'Cloudflare D1 wallet registration start currently supports ECDSA-only signer selection',
        };
      }
      if (request.registrationPreparationId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is not used for ECDSA-only registration',
        };
      }
      const chainTargets = normalizeThresholdEcdsaChainTargets(selection.ecdsa.chainTargets);
      if (!chainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(intentPreview.intent.runtimePolicyScope);
      const signingRootId =
        intentPreview.signingRootId ||
        (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
      const signingRootVersion =
        toOptionalTrimmedString(intentPreview.signingRootVersion) ||
        runtimePolicyScope?.signingRootVersion ||
        'default';
      if (!signingRootId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration requires a signing root',
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

      const authority = request.authority;
      if (!authority || (authority.kind !== 'passkey' && authority.kind !== 'email_otp')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration authority is required',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(intentPreview.expectedOrigin);
      if (authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
        orgId: intentPreview.orgId,
        authority,
        expectedDigestB64u: intentPreview.digestB64u,
        expectedOrigin: storedExpectedOrigin || '',
        intent: intentPreview.intent,
      });
      if (!verifiedAuthority.ok) return verifiedAuthority;

      const storedIntent = await store.takeIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      if (
        storedIntent.digestB64u !== intentPreview.digestB64u ||
        storedIntent.intent.signerSelection.mode !== 'ecdsa_only'
      ) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'registration intent changed before consumption',
        };
      }
      const registrationCeremonyId = `wrc_${secureRandomBase64Url(24)}`;
      const walletKeyId = derivePlannedEvmFamilyWalletKeyId({
        walletId: storedIntent.intent.walletId,
        signingRootId,
        signingRootVersion,
      });
      const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
        walletId: storedIntent.intent.walletId,
        walletKeyId,
        signingRootId,
        signingRootVersion,
      });
      const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId: storedIntent.intent.walletId,
        walletKeyId,
      });
      const ecdsa = {
        kind: 'evm_family_ecdsa_keygen' as const,
        chainTargets,
        prepare: {
          formatVersion: 'ecdsa-hss-role-local' as const,
          walletId: storedIntent.intent.walletId,
          walletKeyId,
          ecdsaThresholdKeyId,
          signingRootId,
          signingRootVersion,
          keyScope: 'evm-family' as const,
          relayerKeyId,
          requestId: `${registrationCeremonyId}:ecdsa`,
          thresholdSessionId: `tehss_${secureRandomBase64Url(24)}`,
          signingGrantId: `wss_${secureRandomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: selection.ecdsa.participantIds,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        },
      };
      await store.putCeremony({
        registrationCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        ...(storedExpectedOrigin ? { expectedOrigin: storedExpectedOrigin } : {}),
        expiresAtMs: Date.now() + 10 * 60_000,
        authority: verifiedAuthority.authority,
        signerState: {
          kind: 'ecdsa_prepared',
          hssKind: ecdsa.kind,
          chainTargets,
          prepare: ecdsa.prepare,
        },
      });
      return {
        ok: true,
        registrationCeremonyId,
        intent: storedIntent.intent,
        ecdsa,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet registration ceremony',
      };
    }
  }

  async respondWalletRegistrationHss(
    request: RespondWalletRegistrationHssInput,
  ): Promise<WalletRegistrationHssRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa_only') {
        return {
          ok: false,
          code: 'unsupported',
          message:
            'Cloudflare D1 registration HSS respond currently supports ECDSA-only signer selection',
        };
      }
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA HSS response' };
      }
      if (request.ed25519) {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 registration HSS respond does not support Ed25519 input',
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response already recorded',
        };
      }
      const expected = ceremony.signerState.prepare;
      const actual = request.ecdsa.clientBootstrap;
      if (!isMatchingD1EcdsaClientBootstrap({ expected, actual })) {
        return { ok: false, code: 'invalid_body', message: 'ECDSA bootstrap identity mismatch' };
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
          message: bootstrap.message || 'ECDSA HSS bootstrap failed',
        };
      }
      await store.updateCeremony(
        buildD1EcdsaRegistrationRespondedCeremony({
          ceremony,
          bootstrap: bootstrap.value,
        }),
      );
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ecdsa: {
          bootstrap: bootstrap.value,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet registration ceremony',
      };
    }
  }

  async finalizeWalletRegistration(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (idempotencyKey) {
        const replay = await store.getFinalizeReplay({
          registrationCeremonyId: request.registrationCeremonyId,
          idempotencyKey,
        });
        if (replay) return replay.response;
      }
      if (request.ed25519) {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 registration finalize currently supports ECDSA-only registration',
        };
      }
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa_only') {
        return {
          ok: false,
          code: 'unsupported',
          message:
            'Cloudflare D1 registration finalize currently supports ECDSA-only signer selection',
        };
      }
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA finalize input' };
      }
      if (ceremony.signerState.kind !== 'ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const bootstrap = ceremony.signerState.responded.bootstrap;
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      if (hasUnexpectedKeyHandle(expectedKeyHandles, bootstrap.keyHandle)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA finalize expected key handle mismatch',
        };
      }
      const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
        bootstrap,
        chainTargets: ceremony.signerState.chainTargets,
        errorContext: 'ECDSA registration finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;

      const now = Date.now();
      const emailOtpEnrollment =
        await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
          authority: ceremony.authority,
          request,
          walletId: ceremony.intent.walletId,
          orgId: ceremony.orgId,
          nowMs: now,
        });
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;

      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        now,
      });
      const walletSigners = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys: walletKeyResult.walletKeys,
        now,
      });
      const walletStore = this.getWalletStore();
      await walletStore.putSubject(wallet);
      await walletStore.putSigners(walletSigners);
      await this.walletAuthMethods.persistAuthority({
        authority: ceremony.authority,
        now,
      });
      if (emailOtpEnrollment.persistence) {
        const persisted = await this.emailOtpRegistrationEnrollmentFinalizer.persistPrepared(
          emailOtpEnrollment.persistence,
        );
        if (!persisted.ok) return persisted;
      }

      const consumed = await store.takeCeremony(ceremony.registrationCeremonyId);
      if (!consumed) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (consumed.signerState.kind !== 'ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const response: Extract<WalletRegistrationFinalizeResponse, { ok: true }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        ...(ceremony.authority.kind === 'passkey' ? { rpId: ceremony.authority.rpId } : {}),
        authMethod: walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority),
        ecdsa: {
          walletKeys: walletKeyResult.walletKeys,
        },
      };
      if (idempotencyKey) {
        await store.putFinalizeReplay({
          kind: 'wallet_registration_finalize_replay_v1',
          registrationCeremonyId: ceremony.registrationCeremonyId,
          idempotencyKey,
          response,
          createdAtMs: now,
          expiresAtMs: ceremony.expiresAtMs,
        });
      }
      return response;
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet registration ceremony',
      };
    }
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
      const walletKeyId = derivePlannedEvmFamilyWalletKeyId({
        walletId,
        signingRootId,
        signingRootVersion,
      });
      const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
        walletId,
        walletKeyId,
        signingRootId,
        signingRootVersion,
      });
      const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId,
        walletKeyId,
      });
      const ecdsa = {
        kind: 'evm_family_ecdsa_keygen' as const,
        chainTargets,
        prepare: {
          formatVersion: 'ecdsa-hss-role-local' as const,
          walletId,
          walletKeyId,
          ecdsaThresholdKeyId,
          signingRootId,
          signingRootVersion,
          keyScope: 'evm-family' as const,
          relayerKeyId,
          requestId: `${addSignerCeremonyId}:ecdsa`,
          thresholdSessionId: `tehss_${secureRandomBase64Url(24)}`,
          signingGrantId: `wss_${secureRandomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: selection.ecdsa.participantIds,
          runtimePolicyScope,
        },
      };
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
