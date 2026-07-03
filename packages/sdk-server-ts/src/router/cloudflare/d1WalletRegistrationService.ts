import {
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  registrationIntentGrantFromString,
  registrationSignerPlanFromSelection,
  type RegistrationEvmFamilyEcdsaSignerPlan,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type RegistrationNearEd25519SignerPlan,
  type ResolvedRegistrationNearAccount,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  deriveSigningRootId,
  normalizeRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  AccountCreationResult,
  ThresholdEd25519BootstrapSession
} from '../../core/types';
import {
  registrationPreparationIdFromString,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationPrepareRequest,
  WalletRegistrationPrepareResponse,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse
} from '../../core/registrationContracts';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../core/ThresholdService';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type { WalletStore } from '../../core/d1WalletStore';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildStoredWalletRegistrationHssPreparationPrepared,
  buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  buildStoredWalletRegistrationNearEd25519PreparedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  findStoredWalletRegistrationNearEd25519Branch,
  getPreparedWalletRegistrationHssPreparation,
  replaceStoredWalletRegistrationSignerBranch,
  storedEd25519RegistrationPrepareScopesMatch,
} from '../../core/RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  isMatchingD1EcdsaClientBootstrap,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RuntimePolicyScope,
  toD1EcdsaHssClientBootstrapRequest,
} from './d1RegistrationCeremonyRecords';
import { walletRegistrationFinalizeAuthMethodFromAuthority } from './d1WalletAuthMethodBoundary';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import {
  buildD1ThresholdEd25519RegistrationSessionPolicy,
  buildD1WalletEd25519SignerRecord,
  d1RegistrationAuthorityNearEd25519SigningKeyId,
  d1RegistrationAuthorityThresholdEd25519AuthorityScope,
  d1WalletAuthAuthorityFromRegistrationAuthority,
  d1RegistrationIntentSigningRootId,
  d1RegistrationIntentSigningRootVersion,
  d1ThresholdEd25519RegistrationAccountScope,
  prepareD1NearEd25519RegistrationHss,
  resolveD1NearEd25519RegistrationPrepareScope,
  respondD1NearEd25519RegistrationHss,
  toD1ThresholdEd25519BootstrapSession,
} from './d1NearEd25519RegistrationBranch';

type StartWalletRegistrationInput = WalletRegistrationStartRequest;
type PrepareWalletRegistrationInput = WalletRegistrationPrepareRequest;
type RespondWalletRegistrationHssInput = WalletRegistrationHssRespondRequest;
type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;
type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type ThresholdSigningServiceProvider = () => ThresholdSigningService | null;
type WalletStoreProvider = () => WalletStore;
type SponsoredNamedNearAccountCreator = (input: {
  readonly accountId: string;
  readonly publicKey: string;
}) => Promise<AccountCreationResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function hasUnexpectedKeyHandle(expectedKeyHandles: readonly string[], keyHandle: string): boolean {
  return expectedKeyHandles.length > 0 && !expectedKeyHandles.includes(keyHandle);
}

function normalizeD1ThresholdRuntimePolicyScope(raw: unknown) {
  try {
    return normalizeRuntimePolicyScope(raw);
  } catch {
    return undefined;
  }
}

type RegistrationIntentSignerBranches = {
  readonly nearEd25519: RegistrationNearEd25519SignerPlan | null;
  readonly evmFamilyEcdsa: RegistrationEvmFamilyEcdsaSignerPlan | null;
};

type RegistrationIntentSignerBranchesResult =
  | { ok: true; value: RegistrationIntentSignerBranches }
  | { ok: false; code: string; message: string };

function registrationIntentSignerBranches(
  intent: RegistrationIntentV1,
): RegistrationIntentSignerBranchesResult {
  const plan = registrationSignerPlanFromSelection(intent.signerSelection);
  if (!plan.ok) return plan;
  return {
    ok: true,
    value: {
      nearEd25519: findRegistrationSignerPlanNearEd25519Branch(plan.value),
      evmFamilyEcdsa: findRegistrationSignerPlanEvmFamilyEcdsaBranch(plan.value),
    },
  };
}

function registrationIntentResponseRpId(intent: RegistrationIntentV1): string | undefined {
  return intent.authMethod.kind === 'passkey' ? intent.authMethod.rpId : undefined;
}

function registrationIntentWalletsMatch(input: {
  readonly requestIntent: RegistrationIntentV1;
  readonly storedIntent: RegistrationIntentV1;
}): boolean {
  return input.requestIntent.walletId === input.storedIntent.walletId;
}

function registrationPreparationWalletsMatch(input: {
  readonly expectedWalletId: string;
  readonly preparation: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
    readonly ed25519Scope: { readonly walletId: string };
  };
}): boolean {
  return (
    input.preparation.intent.walletId === input.expectedWalletId &&
    input.preparation.authority.walletId === input.expectedWalletId &&
    input.preparation.ed25519Scope.walletId === input.expectedWalletId
  );
}

function registrationCeremonyWalletsMatch(input: {
  readonly ceremony: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
  };
}): boolean {
  return input.ceremony.authority.walletId === input.ceremony.intent.walletId;
}

function resolvedRegistrationNearAccount(input: {
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly sponsoredTransactionHash?: string;
}):
  | { ok: true; value: ResolvedRegistrationNearAccount }
  | { ok: false; code: string; message: string } {
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(input.nearEd25519SigningKeyId);
  switch (input.accountProvisioning.kind) {
    case 'implicit_account': {
      const parsed = parseImplicitNearAccountId(input.nearAccountId);
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
      return {
        ok: true,
        value: {
          kind: 'implicit_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
        },
      };
    }
    case 'sponsored_named_account': {
      const parsed = parseNamedNearAccountId(input.nearAccountId);
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
      const transactionHash = toOptionalTrimmedString(input.sponsoredTransactionHash);
      if (!transactionHash) {
        return {
          ok: false,
          code: 'internal',
          message: 'Sponsored named registration missing account creation transaction hash',
        };
      }
      return {
        ok: true,
        value: {
          kind: 'sponsored_named_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
          transactionHash,
        },
      };
    }
  }
}

function sponsoredNamedRegistrationAccountId(
  provisioning: RegistrationNearAccountProvisioning,
): string | null {
  switch (provisioning.kind) {
    case 'implicit_account':
      return null;
    case 'sponsored_named_account':
      return String(provisioning.requestedAccountId);
  }
}

export class CloudflareD1WalletRegistrationService {
  private readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getThresholdSigningService: ThresholdSigningServiceProvider;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getThresholdSigningService: ThresholdSigningServiceProvider;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.createSponsoredNamedNearAccount = input.createSponsoredNamedNearAccount;
    this.emailOtpRegistrationEnrollmentFinalizer = input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getThresholdSigningService = input.getThresholdSigningService;
    this.getWalletStore = input.getWalletStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async prepareWalletRegistration(
    request: PrepareWalletRegistrationInput,
  ): Promise<WalletRegistrationPrepareResponse> {
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
      const storedIntent = await store.getIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const signerBranches = registrationIntentSignerBranches(storedIntent.intent);
      if (!signerBranches.ok) return signerBranches;
      const ed25519Selection = signerBranches.value.nearEd25519;
      if (!ed25519Selection) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 HSS preparation requires an Ed25519 registration branch',
        };
      }
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== storedIntent.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent mismatch' };
      }
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: storedIntent.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const signingRootId =
        storedIntent.signingRootId ||
        (storedIntent.intent.runtimePolicyScope
          ? deriveSigningRootId(storedIntent.intent.runtimePolicyScope)
          : '');
      const signingRootVersion =
        storedIntent.signingRootVersion ||
        storedIntent.intent.runtimePolicyScope?.signingRootVersion ||
        'default';
      const authority = request.authority;
      if (!authority || (authority.kind !== 'passkey' && authority.kind !== 'email_otp')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration authority is required',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin) || '';
      if (authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
        orgId: storedIntent.orgId,
        authority,
        expectedDigestB64u: storedIntent.digestB64u,
        expectedOrigin: storedExpectedOrigin,
        intent: storedIntent.intent,
      });
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const scope = await resolveD1NearEd25519RegistrationPrepareScope({
        intent: storedIntent.intent,
        authority: verifiedAuthority.authority,
        nearEd25519: ed25519Selection,
        registrationIntentDigestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        expectedOrigin: storedExpectedOrigin,
      });
      const prepared = await prepareD1NearEd25519RegistrationHss({
        threshold: this.getThresholdSigningService(),
        scope,
        accountProvisioning: ed25519Selection.accountProvisioning,
      });
      if (!prepared.ok) {
        return {
          ok: false,
          code: prepared.code || 'hss_prepare_failed',
          message: prepared.message || 'Ed25519 HSS prepare failed',
        };
      }
      const registrationPreparationId = registrationPreparationIdFromString(
        `wrp_${secureRandomBase64Url(24)}`,
      );
      const expiresAtMs = Math.min(storedIntent.expiresAtMs, Date.now() + 10 * 60_000);
      await store.putPreparation(
        buildStoredWalletRegistrationHssPreparationPrepared({
          registrationPreparationId,
          registrationIntentGrant: grant,
          registrationIntentDigestB64u: storedIntent.digestB64u,
          intent: storedIntent.intent,
          authority: verifiedAuthority.authority,
          orgId: storedIntent.orgId,
          expectedOrigin: storedExpectedOrigin,
          signingRootId,
          signingRootVersion,
          ed25519Scope: scope,
          prepared: {
            kind: 'ed25519_prepared',
            ceremonyHandle: prepared.ceremonyHandle,
            preparedSession: prepared.preparedSession,
            clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
            serverState: prepared.serverState,
          },
          createdAtMs: Date.now(),
          expiresAtMs,
        }),
      );
      return {
        ok: true,
        state: 'prepared',
        registrationPreparationId,
        expiresAtMs,
        ed25519: {
          ceremonyHandle: prepared.ceremonyHandle,
          preparedSession: prepared.preparedSession,
          clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to prepare wallet registration',
      };
    }
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
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: intentPreview.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const previewBranches = registrationIntentSignerBranches(intentPreview.intent);
      if (!previewBranches.ok) return previewBranches;
      const previewNearEd25519 = previewBranches.value.nearEd25519;
      const previewEvmFamilyEcdsa = previewBranches.value.evmFamilyEcdsa;
      const previewEcdsaChainTargets = previewEvmFamilyEcdsa
        ? normalizeThresholdEcdsaChainTargets(previewEvmFamilyEcdsa.chainTargets)
        : null;
      if (previewEvmFamilyEcdsa && !previewEcdsaChainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }
      if (!previewNearEd25519 && request.registrationPreparationId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is not used when no Ed25519 branch is requested',
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
      if (previewEvmFamilyEcdsa && !signingRootId) {
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

      const storedExpectedOrigin = toOptionalTrimmedString(intentPreview.expectedOrigin);
      const preparedRegistration = !previewNearEd25519
        ? null
        : request.registrationPreparationId
          ? await store.getPreparation(request.registrationPreparationId)
          : null;
      if (previewNearEd25519 && !preparedRegistration) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is required for Ed25519 registration',
        };
      }
      const preparedRegistrationState = preparedRegistration
        ? getPreparedWalletRegistrationHssPreparation(preparedRegistration)
        : null;
      if (preparedRegistrationState && !preparedRegistrationState.ok) {
        return {
          ok: false,
          code: preparedRegistrationState.code,
          message: preparedRegistrationState.message,
        };
      }
      if (
        preparedRegistrationState?.ok &&
        !registrationPreparationWalletsMatch({
          expectedWalletId: intentPreview.intent.walletId,
          preparation: preparedRegistrationState.preparation,
        })
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration preparation walletId mismatch',
        };
      }
      const verifiedAuthority = preparedRegistrationState?.ok
        ? { ok: true as const, authority: preparedRegistrationState.preparation.authority }
        : request.authority
          ? await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
              orgId: intentPreview.orgId,
              authority: request.authority,
              expectedDigestB64u: intentPreview.digestB64u,
              expectedOrigin: storedExpectedOrigin || '',
              intent: intentPreview.intent,
            })
          : {
              ok: false as const,
              code: 'invalid_body',
              message: 'registration authority is required',
            };
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const preparedScope = !previewNearEd25519
        ? null
        : await resolveD1NearEd25519RegistrationPrepareScope({
            intent: intentPreview.intent,
            authority: verifiedAuthority.authority,
            nearEd25519: previewNearEd25519,
            registrationIntentDigestB64u: intentPreview.digestB64u,
            orgId: intentPreview.orgId,
            signingRootId,
            signingRootVersion,
            expectedOrigin: storedExpectedOrigin || '',
          });
      if (
        preparedRegistration &&
        preparedRegistrationState?.ok &&
        preparedScope &&
        !(
          preparedRegistration.registrationIntentGrant === grant &&
          preparedRegistration.registrationIntentDigestB64u === intentPreview.digestB64u &&
          storedEd25519RegistrationPrepareScopesMatch(
            preparedRegistrationState.preparation.ed25519Scope,
            preparedScope,
          )
        )
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration preparation scope does not match verified intent',
        };
      }
      const storedIntentResult = !previewNearEd25519
        ? await store.takeIntent(grant).then((intent) =>
            intent
              ? { ok: true as const, intent }
              : {
                  ok: false as const,
                  code: 'invalid_grant' as const,
                  message: 'registration intent grant expired',
                },
          )
        : await store.consumeRegistrationIntentForPreparation({
            registrationIntentGrant: grant,
            registrationIntentDigestB64u: intentPreview.digestB64u,
            registrationPreparationId: request.registrationPreparationId!,
            authority: verifiedAuthority.authority,
            ed25519Scope: preparedScope!,
          });
      if (!storedIntentResult.ok) return storedIntentResult;
      const storedIntent = storedIntentResult.intent;
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: storedIntent.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const storedBranches = registrationIntentSignerBranches(storedIntent.intent);
      if (!storedBranches.ok) return storedBranches;
      const storedNearEd25519 = storedBranches.value.nearEd25519;
      const storedEvmFamilyEcdsa = storedBranches.value.evmFamilyEcdsa;
      const storedEcdsaChainTargets = storedEvmFamilyEcdsa
        ? normalizeThresholdEcdsaChainTargets(storedEvmFamilyEcdsa.chainTargets)
        : null;
      if (storedEvmFamilyEcdsa && !storedEcdsaChainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }
      const registrationCeremonyId = `wrc_${secureRandomBase64Url(24)}`;
      if (!storedNearEd25519) {
        if (!storedEvmFamilyEcdsa || !storedEcdsaChainTargets) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'registration signer set requires a signer branch',
          };
        }
        const ecdsaResult = await buildD1EvmFamilyEcdsaRegistrationPrepare({
          registrationCeremonyId,
          walletId: storedIntent.intent.walletId,
          signingRootId,
          signingRootVersion,
          chainTargets: storedEcdsaChainTargets,
          participantIds: [...storedEvmFamilyEcdsa.participantIds],
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        });
        if (!ecdsaResult.ok) return ecdsaResult;
        const ecdsa = ecdsaResult.ecdsa;
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
            kind: 'signer_set_registration',
            branches: [
              buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
                branchKey: storedEvmFamilyEcdsa.branchKey,
                ecdsa,
              }),
            ],
          },
        });
        return {
          ok: true,
          registrationCeremonyId,
          intent: storedIntent.intent,
          ecdsa,
        };
      }

      if (!preparedRegistrationState?.ok) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 registration preparation is required',
        };
      }
      if (!storedNearEd25519) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 registration branch is required',
        };
      }
      const ed25519 = {
        ceremonyHandle: preparedRegistrationState.preparation.prepared.ceremonyHandle,
        preparedSession: preparedRegistrationState.preparation.prepared.preparedSession,
        clientOtOfferMessageB64u:
          preparedRegistrationState.preparation.prepared.clientOtOfferMessageB64u,
      };
      const storedEd25519 = {
        ...ed25519,
        serverState: preparedRegistrationState.preparation.prepared.serverState,
      };
      if (!storedEvmFamilyEcdsa) {
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
            kind: 'signer_set_registration',
            branches: [
              buildStoredWalletRegistrationNearEd25519PreparedBranch({
                branchKey: storedNearEd25519.branchKey,
                prepared: storedEd25519,
              }),
            ],
          },
        });
        await store.takePreparation(request.registrationPreparationId!);
        return {
          ok: true,
          registrationCeremonyId,
          intent: storedIntent.intent,
          ed25519,
        };
      }
      if (!storedEcdsaChainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }

      const combinedEcdsaResult = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationCeremonyId,
        registrationPreparationId: request.registrationPreparationId,
        walletId: storedIntent.intent.walletId,
        signingRootId,
        signingRootVersion,
        chainTargets: storedEcdsaChainTargets,
        participantIds: [...storedEvmFamilyEcdsa.participantIds],
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      });
      if (!combinedEcdsaResult.ok) return combinedEcdsaResult;
      const ecdsa = combinedEcdsaResult.ecdsa;
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
          kind: 'signer_set_registration',
          branches: [
            buildStoredWalletRegistrationNearEd25519PreparedBranch({
              branchKey: storedNearEd25519.branchKey,
              prepared: storedEd25519,
            }),
            buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
              branchKey: storedEvmFamilyEcdsa.branchKey,
              ecdsa,
            }),
          ],
        },
      });
      await store.takePreparation(request.registrationPreparationId!);
      return {
        ok: true,
        registrationCeremonyId,
        intent: storedIntent.intent,
        ed25519,
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
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const signerBranches = registrationIntentSignerBranches(ceremony.intent);
      if (!signerBranches.ok) return signerBranches;
      const requestedNearEd25519 = signerBranches.value.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.value.evmFamilyEcdsa;
      let nextSignerState = ceremony.signerState;
      const response: Extract<WalletRegistrationHssRespondResponse, { ok: true }> = {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
      };
      if (request.ed25519) {
        if (!requestedNearEd25519) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept Ed25519 HSS input',
          };
        }
        const ed25519Branch = findStoredWalletRegistrationNearEd25519Branch(ceremony.signerState);
        if (!ed25519Branch) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration requires an Ed25519 branch',
          };
        }
        if (ed25519Branch.kind !== 'near_ed25519_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS response already recorded',
          };
        }
        const ed25519Response = await respondD1NearEd25519RegistrationHss({
          threshold: this.getThresholdSigningService(),
          ceremony,
          nearEd25519: requestedNearEd25519,
          preparedEd25519: {
            kind: 'ed25519_prepared',
            ceremonyHandle: ed25519Branch.ceremonyHandle,
            preparedSession: ed25519Branch.preparedSession,
            clientOtOfferMessageB64u: ed25519Branch.clientOtOfferMessageB64u,
            serverState: ed25519Branch.serverState,
          },
          requestEd25519: request.ed25519,
        });
        if (!ed25519Response.ok) return ed25519Response;
        nextSignerState = replaceStoredWalletRegistrationSignerBranch({
          state: nextSignerState,
          replacement: {
            kind: 'near_ed25519_responded',
            branchKey: ed25519Branch.branchKey,
            ceremonyHandle: ed25519Branch.ceremonyHandle,
            preparedSession: ed25519Branch.preparedSession,
            clientOtOfferMessageB64u: ed25519Branch.clientOtOfferMessageB64u,
            serverState: ed25519Response.serverState,
            responded: ed25519Response.responded,
          },
        });
        response.ed25519 = ed25519Response.responded;
      } else if (requestedNearEd25519) {
        return { ok: false, code: 'invalid_body', message: 'missing Ed25519 HSS response' };
      }
      if (request.ecdsa) {
        if (!requestedEvmFamilyEcdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept ECDSA HSS input',
          };
        }
        const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (!ecdsaBranch) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration requires an ECDSA branch',
          };
        }
        if (ecdsaBranch.kind !== 'evm_family_ecdsa_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA HSS response already recorded',
          };
        }
        const expected = ecdsaBranch.prepare;
        const actual = request.ecdsa.clientBootstrap;
        if (!isMatchingD1EcdsaClientBootstrap({ expected, actual })) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA bootstrap identity mismatch',
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
            message: bootstrap.message || 'ECDSA HSS bootstrap failed',
          };
        }
        nextSignerState = replaceStoredWalletRegistrationSignerBranch({
          state: nextSignerState,
          replacement: {
            kind: 'evm_family_ecdsa_responded',
            branchKey: ecdsaBranch.branchKey,
            hssKind: ecdsaBranch.hssKind,
            chainTargets: ecdsaBranch.chainTargets,
            prepare: ecdsaBranch.prepare,
            responded: {
              bootstrap: bootstrap.value,
            },
          },
        });
        response.ecdsa = { bootstrap: bootstrap.value };
      } else if (requestedEvmFamilyEcdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA HSS response' };
      }
      if (!response.ed25519 && !response.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration HSS response is required',
        };
      }
      await store.updateCeremony({
        ...ceremony,
        signerState: nextSignerState,
      });
      return response;
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
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      const signerBranches = registrationIntentSignerBranches(ceremony.intent);
      if (!signerBranches.ok) return signerBranches;
      const requestedNearEd25519 = signerBranches.value.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.value.evmFamilyEcdsa;
      if (requestedNearEd25519) {
        if (!request.ed25519) {
          return { ok: false, code: 'invalid_body', message: 'missing Ed25519 finalize input' };
        }
        if (request.ecdsa && !requestedEvmFamilyEcdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept ECDSA finalize input',
          };
        }
        if (ceremony.signerState.kind !== 'signer_set_registration') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration state is required',
          };
        }
        const ed25519State = findStoredWalletRegistrationNearEd25519Branch(ceremony.signerState);
        if (!ed25519State || ed25519State.kind !== 'near_ed25519_responded') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS response is required before finalize',
          };
        }
        const ecdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (requestedEvmFamilyEcdsa) {
          if (!request.ecdsa) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'registration signer set requires ECDSA finalize input',
            };
          }
          if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_responded') {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'registration signer set requires ECDSA HSS response before finalize',
            };
          }
          const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
          if (
            hasUnexpectedKeyHandle(expectedKeyHandles, ecdsaState.responded.bootstrap.keyHandle)
          ) {
            return {
              ok: false,
              code: 'key_handle_mismatch',
              message: 'ECDSA finalize expected key handle mismatch',
            };
          }
        }
        const threshold = this.getThresholdSigningService();
        if (!threshold) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'threshold signing is not configured on this server',
          };
        }
        const ed25519 = requestedNearEd25519;
        const nearEd25519SigningKeyId = await d1RegistrationAuthorityNearEd25519SigningKeyId({
          intent: ceremony.intent,
          authority: ceremony.authority,
          nearEd25519: requestedNearEd25519,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
        });
        const ed25519AuthorityScope = d1RegistrationAuthorityThresholdEd25519AuthorityScope(
          ceremony.authority,
        );
        const finalized = await threshold.ed25519Hss.finalizeForRegistration({
          orgId: ceremony.orgId,
          request: {
            registrationAccountScope: d1ThresholdEd25519RegistrationAccountScope({
              walletId: ceremony.intent.walletId,
              intentDigestB64u: ceremony.digestB64u,
              signingRootId: d1RegistrationIntentSigningRootId({
                signingRootId: ceremony.signingRootId,
                intent: ceremony.intent,
              }),
              signingRootVersion: d1RegistrationIntentSigningRootVersion({
                signingRootVersion: ceremony.signingRootVersion,
                intent: ceremony.intent,
              }),
              nearEd25519SigningKeyId,
              signerSlot: ed25519.signerSlot,
              keyPurpose: ed25519.keyPurpose,
              keyVersion: ed25519.keyVersion,
              derivationVersion: ed25519.derivationVersion,
              participantIds: [...ed25519.participantIds],
              accountProvisioning: ed25519.accountProvisioning,
            }),
            wallet_key_id: nearEd25519SigningKeyId,
            authorityScope: ed25519AuthorityScope,
            ceremonyHandle: ed25519State.ceremonyHandle,
            preparedSession: ed25519State.preparedSession,
            serverState: ed25519State.serverState,
            evaluationResult: request.ed25519.evaluationResult,
            accountResolution: {
              kind: 'registration_provisioning',
              accountProvisioning: ed25519.accountProvisioning,
            },
          },
        });
        if (!finalized.ok) {
          return {
            ok: false,
            code: finalized.code || 'hss_finalize_failed',
            message: finalized.message || 'Ed25519 HSS finalize failed',
          };
        }
        const sponsoredNamedAccountId = sponsoredNamedRegistrationAccountId(
          ed25519.accountProvisioning,
        );
        let sponsoredTransactionHash: string | undefined;
        if (sponsoredNamedAccountId) {
          const created = await this.createSponsoredNamedNearAccount({
            accountId: sponsoredNamedAccountId,
            publicKey: finalized.publicKey,
          });
          if (!created.success) {
            return {
              ok: false,
              code: 'account_creation_failed',
              message: created.error || created.message || 'Failed to create NEAR account',
            };
          }
          sponsoredTransactionHash = created.transactionHash;
        }
        const resolvedAccount = resolvedRegistrationNearAccount({
          accountProvisioning: ed25519.accountProvisioning,
          nearAccountId: finalized.nearAccountId,
          nearEd25519SigningKeyId,
          sponsoredTransactionHash,
        });
        if (!resolvedAccount.ok) return resolvedAccount;
        const scheme = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
        if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
          return {
            ok: false,
            code: 'not_configured',
            message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
          };
        }
        const keygen = await scheme.registration.keygenFromRegistrationMaterial({
          walletId: ceremony.intent.walletId,
          nearAccountId: finalized.nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope: ed25519AuthorityScope,
          keyVersion: ed25519.keyVersion,
          recoveryExportCapable: true,
          publicKey: finalized.publicKey,
          relayerKeyId: finalized.relayerKeyId,
        });
        if (!keygen.ok) {
          return {
            ok: false,
            code: keygen.code || 'keygen_failed',
            message: keygen.message || 'Ed25519 registration keygen failed',
          };
        }
        const now = Date.now();
        const runtimePolicyScope = normalizeD1ThresholdRuntimePolicyScope(
          ceremony.intent.runtimePolicyScope,
        );
        const emailOtpEnrollment =
          await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
            authority: ceremony.authority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
        });
        if (!emailOtpEnrollment.ok) return emailOtpEnrollment;
        const walletAuthAuthority = d1WalletAuthAuthorityFromRegistrationAuthority(
          ceremony.authority,
        );
        let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
        if (request.ed25519.sessionPolicy) {
          const sessionKind = String(request.ed25519.sessionKind || 'jwt')
            .trim()
            .toLowerCase();
          if (sessionKind !== 'jwt') {
            return { ok: false, code: 'invalid_body', message: 'ed25519.sessionKind must be jwt' };
          }
          const requestedPolicy = request.ed25519.sessionPolicy as Record<string, unknown>;
          const sessionPolicy = buildD1ThresholdEd25519RegistrationSessionPolicy({
            requestedSessionPolicy: requestedPolicy,
            walletId: String(ceremony.intent.walletId),
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            relayerKeyId: keygen.relayerKeyId,
            authority: walletAuthAuthority,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          });
          if (!sessionPolicy.ok) return sessionPolicy;
          const session = await threshold.mintEd25519SessionFromRegistration({
            walletId: String(ceremony.intent.walletId),
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            authorityScope: ed25519AuthorityScope,
            relayerKeyId: keygen.relayerKeyId,
            sessionPolicy: sessionPolicy.value,
          });
          if (
            !session.ok ||
            !session.thresholdSessionId ||
            !Number.isFinite(Number(session.expiresAtMs))
          ) {
            return {
              ok: false,
              code: session.code || 'internal',
              message: session.message || 'threshold-ed25519 session bootstrap failed',
            };
          }
          const normalizedSession = toD1ThresholdEd25519BootstrapSession({
            walletId: session.walletId,
            nearAccountId: session.nearAccountId,
            nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
            authorityScope: ed25519AuthorityScope,
            thresholdSessionId: session.thresholdSessionId,
            signingGrantId: session.signingGrantId,
            expiresAtMs: session.expiresAtMs,
            expiresAt: session.expiresAt,
            participantIds: session.participantIds,
            remainingUses: session.remainingUses,
            runtimePolicyScope: session.runtimePolicyScope,
            routerAbNormalSigning: session.routerAbNormalSigning,
            jwt: session.jwt,
          });
          if (!normalizedSession) {
            return {
              ok: false,
              code: 'internal',
              message: 'threshold-ed25519 session bootstrap failed',
            };
          }
          thresholdEd25519Session = normalizedSession;
        }
        const walletKeyResult =
          ecdsaState && ecdsaState.kind === 'evm_family_ecdsa_responded'
            ? buildD1EcdsaWalletKeysFromBootstrap({
                bootstrap: ecdsaState.responded.bootstrap,
                chainTargets: ecdsaState.chainTargets,
                errorContext: 'combined ECDSA registration finalize',
              })
            : null;
        if (walletKeyResult && !walletKeyResult.ok) return walletKeyResult;
        const wallet = buildD1WalletRecord({
          walletId: ceremony.intent.walletId,
          now,
        });
        const walletSigners = [
          buildD1WalletEd25519SignerRecord({
            walletId: ceremony.intent.walletId,
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            signerSlot: ed25519.signerSlot,
            keygen,
            now,
          }),
          ...(walletKeyResult?.ok
            ? buildD1WalletEcdsaSignerRecords({
                walletId: ceremony.intent.walletId,
                walletKeys: walletKeyResult.walletKeys,
                now,
              })
            : []),
        ];
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
        const rpId = registrationIntentResponseRpId(ceremony.intent);
        const ed25519Response: NonNullable<
          Extract<WalletRegistrationFinalizeResponse, { ed25519: object }>['ed25519']
        > = {
          nearAccountId: finalized.nearAccountId,
          nearEd25519SigningKeyId,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
        };
        if (thresholdEd25519Session) ed25519Response.session = thresholdEd25519Session;
        const response: Extract<WalletRegistrationFinalizeResponse, { ed25519: object }> = {
          ok: true,
          walletId: ceremony.intent.walletId,
          authority: walletAuthAuthority,
          authorityScope: ed25519AuthorityScope,
          authMethod: walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority),
          accountProvisioning: ed25519.accountProvisioning,
          resolvedAccount: resolvedAccount.value,
          ed25519: ed25519Response,
        };
        if (rpId) response.rpId = rpId;
        if (walletKeyResult?.ok) response.ecdsa = { walletKeys: walletKeyResult.walletKeys };
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
      }
      if (!requestedEvmFamilyEcdsa) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'registration signer set requires a signer branch',
        };
      }
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA finalize input' };
      }
      if (request.ed25519) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration signer set does not accept Ed25519 finalize input',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const ecdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const bootstrap = ecdsaState.responded.bootstrap;
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
        chainTargets: ecdsaState.chainTargets,
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
      const walletAuthAuthority = d1WalletAuthAuthorityFromRegistrationAuthority(
        ceremony.authority,
      );
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
      if (consumed.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const consumedEcdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
        consumed.signerState,
      );
      if (!consumedEcdsaState || consumedEcdsaState.kind !== 'evm_family_ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const response: Extract<WalletRegistrationFinalizeResponse, { ecdsa: object }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        authority: walletAuthAuthority,
        authMethod: walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority),
        ecdsa: {
          walletKeys: walletKeyResult.walletKeys,
        },
      };
      if (ceremony.authority.kind === 'passkey') response.rpId = ceremony.authority.rpId;
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
}
