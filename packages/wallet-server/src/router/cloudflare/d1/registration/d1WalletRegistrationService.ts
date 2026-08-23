import type {
  WalletRegistrationAuthorityInput,
  WalletRegistrationFinalizeAuthMethod,
} from '../../../../core/registrationContracts';
import {
  parseAuthFactorId,
  parseDeviceId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseEcdsaAuthorizationSessionId,
  type DeviceId,
  type PrincipalId,
  type MpcWalletSigningQuotaId,
  type ReusableWalletSessionMintId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import {
  buildExactAdministeredSignerManifestV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredEd25519SignerV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import { parseVerifiedOwnerProofId, parseSessionOrigin } from '../../../../authorization/domain';
import {
  buildVerifiedOwnerProof,
  buildVerifiedWalletSessionEmailOtpFactorResult,
  buildVerifiedWalletSessionPasskeyFactorResult,
  type VerifiedOwnerProof,
} from '../../../../authorization/factorEvidence';
import type {
  AuthorizationService,
  IssuedReusableWalletSession,
  OpaqueOwnerWalletSessionBinding,
} from '../../../../authorization/service';
import {
  issueRouterAbEd25519OpaqueWalletSessionToken,
  issueRouterAbEcdsaDerivationOpaqueWalletSessionToken,
} from '../../../auth/commonRouterUtils';
import { mintRouterAbEd25519YaoWalletSessionV1 } from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import type { SessionAdapter } from '../../../framework/routerApi';
import {
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  registrationIntentGrantFromString,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  walletIdFromString,
  type RegistrationEvmFamilyEcdsaSignerPlan,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type RegistrationNearEd25519SignerPlan,
  type RegistrationSignerPlan,
  type ResolvedRegistrationNearAccount,
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
  type WalletId,
  registrationEd25519AuthorityScopeFromAuthority,
  type RegistrationAuthMethodInput,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import {
  routerAbMpcMaterialActivationRefFromWire,
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  ecdsaClientRootPublicKey33B64uFromString,
  type EcdsaClientRootPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseEmailOtpChallengeId,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletKeyId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletKeyId,
} from '@shared/utils/domainIds';
import type {
  RegistrationEstablishedEcdsaSession,
  RegistrationEstablishedEd25519Session,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import {
  deriveSigningRootId,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import { type EcdsaDerivationServerBootstrapResponse } from '../../../../core/types';
import {
  buildRouterAbEcdsaDerivationActiveStateIdV1,
  buildRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../../../core/thresholdEcdsaChainTarget';
import {
  registrationPreparationIdFromString,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaDerivationRespondRequest,
  WalletRegistrationEcdsaDerivationRespondResponse,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEd25519YaoStart,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEd25519YaoPublicResult,
  type WalletRegistrationFinalizeSuccess,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '../../../../core/registrationContracts';
import { parseEcdsaDerivationPublicIdentity } from '../../../../core/ThresholdService/validation';
import {
  routerAbEcdsaStrictRegistrationFactsBindingJson,
  routerAbEcdsaStrictRegistrationRequestBindingJson,
  routerAbEcdsaStrictRegistrationRequestMatchesFacts,
  type RouterAbEcdsaStrictRegistrationPort,
} from '../../../domains/ecdsa/routerAbEcdsaStrictRegistration';
import { CloudflareD1RegistrationCeremonyIntentStore } from './d1RegistrationCeremonyStore';
import {
  listThresholdEcdsaKeyIdentityTargetsForUser,
  type ThresholdEcdsaKeyInventoryDiagnostics,
  type ThresholdEcdsaKeyInventoryRecord,
} from '../../../../core/authService/thresholdEcdsaKeyInventory';
import {
  buildStoredWalletRegistrationPreparedContext,
  buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  findStoredWalletRegistrationNearEd25519YaoBranch,
  replaceStoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch,
  type StoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationPreparedContext,
  type StoredRegistrationAuthority,
  type StoredWalletRegistrationCeremony,
  type StoredWalletRegistrationCeremonyAuthorityState,
  storedRegistrationAuthoritiesMatch,
  verifiedRegistrationCeremonyAuthority,
} from '../../../../core/RegistrationCeremonyStore';
import type {
  WalletRegistrationNearProvisioningResponseV2,
  RespondEd25519DeferredWorkV2,
  WalletRegistrationActivateResponseV2,
  WalletRegistrationRespondResponseV2,
  WalletRegistrationSetupResponseV2,
} from '../../../../core/threeRouteRegistrationContracts';
import {
  buildWalletRegistrationSetupSignature,
  normalizeWalletRegistrationSetupRequest,
  resolveWalletRegistrationSetupWalletId,
  walletRegistrationSetupError,
  walletRegistrationSetupExpiresAtMs,
  walletRegistrationSetupIds,
  walletRegistrationSetupIntentDigest,
  walletRegistrationRespondResult,
  storedRespondEd25519DeferredWork,
} from './d1WalletRegistrationSetup';
import type {
  WalletRegistrationSetupInput,
  WalletRegistrationRespondInput,
  WalletRegistrationActivateInput,
  WalletRegistrationNearProvisioningInput,
} from '../../../domains/walletRegistration/walletRegistrationInputs';
import { walletCustodyCeremonyCommitPayloadFromWire } from '@shared/passkey-custody';
import { commitRegistrationCustody } from '../../../domains/passkeyCustody/registrationCustodyOutcome';
import type { CloudflareD1WalletCustodyCommitStore } from '../passkeyCustody/d1WalletCustodyCommitStore';
import {
  computeWalletRegistrationSetupDigestB64u,
  verifySignedWalletRegistrationSetup,
  verifyWalletRegistrationSetupClaims,
} from '../../../domains/walletRegistration/walletRegistrationSetupPayload';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RegistrationAuthority,
  parseD1RuntimePolicyScope,
  parseD1StoredWalletRegistrationCeremony,
  buildRegistrationIntent,
  createD1ServerAllocatedWalletId,
  inferRuntimePolicyScopeFromSigningRoot,
  parseWalletIdForIntent,
} from './d1RegistrationCeremonyRecords';
import {
  walletAuthAuthorityFromRegistrationAuthority,
  walletRegistrationFinalizeAuthMethodFromAuthority,
} from '../wallet/d1WalletAuthMethodBoundary';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from '../emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1WalletAuthMethodService } from '../wallet/d1WalletAuthMethodService';
import type { D1WalletRegistrationCommitStore } from './d1WalletRegistrationCommitStore';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import { sha256BytesPortable } from '../auth/d1RouterApiAuthBoundary';
import { alphabetizeStringify, bytesToUnprefixedHex, sha256BytesUtf8 } from '@shared/utils/digests';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  type WalletEcdsaSignerKey,
  type WalletEcdsaSignerRecord,
  type WalletEcdsaPendingSessionActivationRecord,
  type WalletEd25519SignerRecord,
  type WalletSignerRecord,
} from '../../../../core/WalletStore';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../../core/ThresholdService/validation';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  buildRouterAbEd25519YaoProductAdmissionRequestV1,
  createRouterAbEd25519YaoMaterialActivationRefV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
  type RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  buildRouterAbEd25519YaoRegistrationCapabilityRecordV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
} from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoBudgetRefreshRequestV1,
  RouterAbEd25519YaoBudgetRefreshResponseV1,
  RouterAbEd25519YaoVerifiedWalletUnlockRequestV1,
  RouterAbEd25519YaoVerifiedWalletUnlockResponseV1,
} from '../../../domains/ed25519Yao/session/routerAbEd25519YaoWalletSession';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
  implicitNearAccountIdFromEd25519PublicKeyBytes,
} from '../ed25519Yao/d1Ed25519YaoWalletSigner';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  parseRouterAbEd25519YaoRegistrationSideEffectRecordV1,
  throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../../../domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary';

type RespondWalletRegistrationDerivationInput = WalletRegistrationEcdsaDerivationRespondRequest;
type ActivateWalletRegistrationEcdsaInput = {
  readonly registrationCeremonyId: string;
  readonly ecdsa: {
    readonly kind: 'router_ab_ecdsa_registration_activation_v1';
    readonly activationCorrelationId: NonNullable<
      WalletRegistrationActivateInput['ecdsa']
    >['activationCorrelationId'];
    readonly activationRequestDigestB64u: NonNullable<
      WalletRegistrationActivateInput['ecdsa']
    >['activationRequestDigestB64u'];
    readonly publicFacts: NonNullable<WalletRegistrationActivateInput['ecdsa']>['clientActivation'];
  };
};
type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

async function walletRegistrationFinalizeRequestFingerprint(
  request: FinalizeWalletRegistrationInput,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(request)));
}

export type D1WalletRegistrationOperationPreparedV1 = {
  readonly kind: 'd1_wallet_registration_operation_prepared_v1';
  readonly walletAuthorityId: WalletAuthorityId;
  readonly deviceId: DeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
};

function requirePreparedRegistrationId<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label} is invalid: ${result.error.message}`);
  return result.value;
}

function allocateWalletRegistrationOperationPrepared(): D1WalletRegistrationOperationPreparedV1 {
  return {
    kind: 'd1_wallet_registration_operation_prepared_v1',
    walletAuthorityId: requirePreparedRegistrationId(
      parseWalletAuthorityId(`wallet-authority:${secureRandomBase64Url(32)}`),
      'walletAuthorityId',
    ),
    deviceId: requirePreparedRegistrationId(
      parseDeviceId(`device:${secureRandomBase64Url(32)}`),
      'deviceId',
    ),
    walletAuthMethodId: requirePreparedRegistrationId(
      parseWalletAuthMethodId(`wallet-auth-method:${secureRandomBase64Url(32)}`),
      'walletAuthMethodId',
    ),
  };
}

type FoundingEd25519Facts = {
  readonly signer: WalletEd25519SignerRecord;
  readonly registeredPublicKeyB64u: string;
  readonly materialActivation: MpcMaterialActivationRef;
};

type FoundingEcdsaFacts = {
  readonly walletKey: WalletRegistrationEcdsaWalletKey;
  readonly materialActivation: MpcMaterialActivationRef;
};

type FoundingSignerFacts =
  | {
      readonly kind: 'ed25519';
      readonly keyFamilies: readonly ['ed25519'];
      readonly ed25519: FoundingEd25519Facts;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'ecdsa_secp256k1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly ed25519?: never;
      readonly ecdsa: FoundingEcdsaFacts;
    }
  | {
      readonly kind: 'both';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly ed25519: FoundingEd25519Facts;
      readonly ecdsa: FoundingEcdsaFacts;
    };

type FoundingAuthorityRecords = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
};

function requireFoundingWalletKeyId(raw: string, label: string): WalletKeyId {
  const parsed = parseWalletKeyId(raw);
  if (!parsed.ok) throw new Error(`${label} is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function requireFoundingEvmAddress(raw: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(raw)) {
    throw new Error('ECDSA registration returned an invalid owner address');
  }
  return raw;
}

function requireSingleFoundingEcdsaWalletKey(
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[],
): WalletRegistrationEcdsaWalletKey {
  const first = walletKeys[0];
  if (!first) throw new Error('ECDSA founding authority is missing wallet-key facts');
  for (const candidate of walletKeys.slice(1)) {
    if (
      candidate.walletId !== first.walletId ||
      candidate.evmFamilySigningKeySlotId !== first.evmFamilySigningKeySlotId ||
      candidate.thresholdEcdsaPublicKeyB64u !== first.thresholdEcdsaPublicKeyB64u ||
      candidate.thresholdOwnerAddress !== first.thresholdOwnerAddress
    ) {
      throw new Error('ECDSA founding authority received conflicting wallet-key facts');
    }
  }
  return first;
}

function foundingEd25519SignerIdentity(
  walletId: WalletId,
  facts: FoundingEd25519Facts,
): ExactAdministeredEd25519SignerV1 {
  return {
    kind: 'exact_administered_ed25519_signer_v1',
    keyFamily: 'ed25519',
    walletId,
    walletKeyId: requireFoundingWalletKeyId(
      `wallet-key:ed25519:${walletId}:${facts.signer.nearEd25519SigningKeyId}`,
      'Ed25519 walletKeyId',
    ),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(facts.registeredPublicKeyB64u),
  };
}

function foundingEcdsaSignerIdentity(
  walletId: WalletId,
  facts: FoundingEcdsaFacts,
): ExactAdministeredEcdsaSignerV1 {
  return {
    kind: 'exact_administered_ecdsa_signer_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletId,
    walletKeyId: requireFoundingWalletKeyId(
      `wallet-key:ecdsa:${walletId}:${facts.walletKey.evmFamilySigningKeySlotId}`,
      'ECDSA walletKeyId',
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      facts.walletKey.thresholdEcdsaPublicKeyB64u,
    ),
    evmAddress: requireFoundingEvmAddress(facts.walletKey.thresholdOwnerAddress),
  };
}

function foundingSignerManifest(
  walletId: WalletId,
  facts: FoundingSignerFacts,
): ExactAdministeredSignerManifestV1 {
  switch (facts.kind) {
    case 'ed25519':
      return buildExactAdministeredSignerManifestV1([
        foundingEd25519SignerIdentity(walletId, facts.ed25519),
      ]);
    case 'ecdsa_secp256k1':
      return buildExactAdministeredSignerManifestV1([
        foundingEcdsaSignerIdentity(walletId, facts.ecdsa),
      ]);
    case 'both':
      return buildExactAdministeredSignerManifestV1([
        foundingEd25519SignerIdentity(walletId, facts.ed25519),
        foundingEcdsaSignerIdentity(walletId, facts.ecdsa),
      ]);
    default:
      return assertNeverFoundingSignerFacts(facts);
  }
}

function foundingSignerActivations(
  walletId: WalletId,
  facts: FoundingSignerFacts,
): WalletSignerActivationSetV1 {
  const manifest = foundingSignerManifest(walletId, facts);
  switch (facts.kind) {
    case 'ed25519':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: facts.ed25519.materialActivation,
        },
      });
    case 'ecdsa_secp256k1':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: facts.ecdsa.materialActivation,
        },
      });
    case 'both':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: facts.ed25519.materialActivation,
          ecdsa: facts.ecdsa.materialActivation,
        },
      });
    default:
      return assertNeverFoundingSignerFacts(facts);
  }
}

async function buildActiveFoundingAuthority(input: {
  readonly walletId: WalletId;
  readonly prepared: D1WalletRegistrationOperationPreparedV1;
  readonly signerFacts: FoundingSignerFacts;
  readonly now: number;
}): Promise<ActiveWalletAuthorityV1> {
  const signerActivations = foundingSignerActivations(input.walletId, input.signerFacts);
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const permissions = buildFullOwnerPermissionsV1();
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: input.prepared.walletAuthorityId,
    walletId: input.walletId,
    principal: { kind: 'owner_device', deviceId: input.prepared.deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: signerActivationSetDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.now,
    updatedAtMs: input.now,
    state: 'active',
    activatedAtMs: input.now,
  };
  const authorityDigestB64u = await computeWalletAuthorityDigestB64u(draft);
  return buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u,
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function buildActiveFoundingAuthMethod(input: {
  readonly authority: StoredRegistrationAuthority;
  readonly prepared: D1WalletRegistrationOperationPreparedV1;
  readonly now: number;
}): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  switch (input.authority.kind) {
    case 'passkey':
      return requireActiveFoundingAuthMethod(
        buildWalletAuthMethodRecordV2({
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: input.prepared.walletAuthMethodId,
          walletId: input.authority.walletId,
          walletAuthorityId: input.prepared.walletAuthorityId,
          kind: 'passkey',
          status: 'active',
          rpId: input.authority.rpId,
          credentialIdB64u: requirePreparedRegistrationId(
            parseWebAuthnCredentialIdB64u(input.authority.credentialIdB64u),
            'registration credentialIdB64u',
          ),
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
          activatedAtMs: input.now,
        }),
      );
    case 'email_otp':
      return requireActiveFoundingAuthMethod(
        buildWalletAuthMethodRecordV2({
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: input.prepared.walletAuthMethodId,
          walletId: input.authority.walletId,
          walletAuthorityId: input.prepared.walletAuthorityId,
          kind: 'email_otp',
          status: 'active',
          emailHashHex: input.authority.emailHashHex,
          registrationAuthorityId: input.authority.registrationAuthorityId,
          createdAtMs: input.now,
          updatedAtMs: input.now,
          activatedAtMs: input.now,
        }),
      );
  }
}

function requireActiveFoundingAuthMethod(
  record: WalletAuthMethodRecordV2,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  if (record.status !== 'active') {
    throw new Error('Founding wallet auth method must be active');
  }
  return record;
}

async function buildFoundingAuthorityRecords(input: {
  readonly authority: StoredRegistrationAuthority;
  readonly walletId: WalletId;
  readonly prepared: D1WalletRegistrationOperationPreparedV1;
  readonly signerFacts: FoundingSignerFacts;
  readonly now: number;
}): Promise<FoundingAuthorityRecords> {
  const authority = await buildActiveFoundingAuthority({
    walletId: input.walletId,
    prepared: input.prepared,
    signerFacts: input.signerFacts,
    now: input.now,
  });
  return {
    authority,
    authMethod: buildActiveFoundingAuthMethod({
      authority: input.authority,
      prepared: input.prepared,
      now: input.now,
    }),
  };
}

function assertNeverFoundingSignerFacts(value: never): never {
  throw new Error(`Unsupported founding signer facts: ${String(value)}`);
}

/** The activate operation row stores activate's own merged terminal bytes. */
export type D1WalletRegistrationActivateSideEffectStore =
  RouterAbEd25519YaoRegistrationSideEffectStoreV1<
    WalletRegistrationActivateResponseV2,
    D1WalletRegistrationOperationPreparedV1
  >;

export type D1WalletRegistrationActivateSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    WalletRegistrationActivateResponseV2,
    D1WalletRegistrationOperationPreparedV1
  >;

type WalletRegistrationNearProvisioningFinalizeResponse =
  | WalletRegistrationFinalizeResponse
  | (Extract<WalletRegistrationFinalizeSuccess, { kind: 'near_ed25519' }> & {
      registrationEstablishedSession: RegistrationEstablishedSession;
    });

type RegistrationOwnerProofContext = {
  readonly expectedOrigin: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly expiresAtMs: number;
};

function isEmailOtpWalletRegistrationFinalizeSuccess(
  value: WalletRegistrationFinalizeResponse,
): value is Extract<
  WalletRegistrationFinalizeSuccess,
  { kind: 'near_ed25519'; authMethod: { kind: 'email_otp' } }
> {
  return value.ok && value.kind === 'near_ed25519' && value.authMethod.kind === 'email_otp';
}

function isWalletRegistrationNearProvisioningSuccess(
  value: WalletRegistrationNearProvisioningFinalizeResponse,
): value is Extract<WalletRegistrationFinalizeSuccess, { kind: 'near_ed25519' }> & {
  registrationEstablishedSession: RegistrationEstablishedSession;
} {
  return value.ok && value.kind === 'near_ed25519' && 'registrationEstablishedSession' in value;
}

function isPasskeyWalletRegistrationFinalizeSuccess(
  value: WalletRegistrationNearProvisioningFinalizeResponse,
): value is Extract<
  WalletRegistrationFinalizeSuccess,
  { kind: 'near_ed25519'; authMethod: { kind: 'passkey' } }
> {
  return value.ok && value.kind === 'near_ed25519' && value.authMethod.kind === 'passkey';
}

export type D1WalletRegistrationNearProvisioningSideEffectStore =
  RouterAbEd25519YaoRegistrationSideEffectStoreV1<
    WalletRegistrationNearProvisioningFinalizeResponse,
    D1WalletRegistrationOperationPreparedV1
  >;

export type D1WalletRegistrationNearProvisioningSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    WalletRegistrationNearProvisioningFinalizeResponse,
    D1WalletRegistrationOperationPreparedV1
  >;

function recordValue(value: unknown): Record<string, unknown> | null {
  return isPlainObject(value) ? value : null;
}

const D1_WALLET_REGISTRATION_OPERATION_RESUME_AFTER_MS = 30_000;
const WALLET_REGISTRATION_ROUTER_POLICY_VERSION = 'wallet-registration-v1';

function requireReusableWalletSessionPrincipalId(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok)
    throw new Error(`Reusable Wallet Session principal is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function requireReusableWalletSessionMintId(value: string): ReusableWalletSessionMintId {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok)
    throw new Error(`Reusable Wallet Session mint identity is invalid: ${parsed.error.message}`);
  return parsed.value;
}

async function walletSessionPolicyMintId(
  policy: RouterAbEd25519YaoBudgetRefreshRequestV1['sessionPolicy'],
): Promise<ReusableWalletSessionMintId> {
  const digest = base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(policy)));
  return requireReusableWalletSessionMintId(`wallet-session-policy:${digest}`);
}

async function registrationWalletAuthAuthorityRef(input: {
  readonly authority: WalletAuthAuthority;
}): Promise<WalletAuthAuthorityRef> {
  return await walletAuthAuthorityRef({ authority: input.authority });
}

function registrationWalletAuthAuthority(input: {
  readonly authority: StoredRegistrationAuthority;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): WalletAuthAuthority {
  const authority = walletAuthAuthorityFromRegistrationAuthority(input.authority);
  if (isPasskeyWalletAuthAuthority(authority)) {
    return {
      walletId: authority.walletId,
      factor: authority.factor,
      verifier: authority.verifier,
      bindingId: input.walletAuthMethodId,
    };
  }
  if (isEmailOtpWalletAuthAuthority(authority)) {
    return {
      walletId: authority.walletId,
      factor: authority.factor,
      verifier: authority.verifier,
      bindingId: input.walletAuthMethodId,
    };
  }
  authority satisfies never;
  throw new Error('Registration wallet authority kind is invalid');
}

function reusableWalletSessionPrincipalId(authority: WalletAuthAuthority): PrincipalId {
  return requireReusableWalletSessionPrincipalId(
    isEmailOtpWalletAuthAuthority(authority)
      ? String(authority.factor.providerUserId)
      : String(authority.walletId),
  );
}

async function buildRegistrationOwnerProof(input: {
  readonly registrationCeremonyId: string;
  readonly authMethod: WalletRegistrationFinalizeAuthMethod;
  readonly authority: WalletAuthAuthority;
  readonly tenantId: TenantId;
  readonly expectedOrigin: string;
  readonly expiresAtMs: number;
}): Promise<Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>> {
  const factorId = parseAuthFactorId(`registration:${input.registrationCeremonyId}`);
  if (!factorId.ok) throw new Error(factorId.error.message);
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const principalId = reusableWalletSessionPrincipalId(input.authority);
  const origin = parseSessionOrigin(input.expectedOrigin);
  const verifiedAtMs = Date.now();
  const evidenceDigest = parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({
          kind: 'wallet_registration_owner_proof_v1',
          registrationCeremonyId: input.registrationCeremonyId,
          authMethod: input.authMethod,
          authority: authorityRef,
        }),
      ),
    ),
  );
  const common = {
    tenantId: input.tenantId,
    principalId,
    walletId: input.authority.walletId,
    authorityRef,
    requestOrigin: origin,
    audience: origin,
    factorId: factorId.value,
    verifiedAtMs,
    expiresAtMs: input.expiresAtMs,
  } as const;
  if (input.authMethod.kind === 'passkey') {
    const credentialId = parseWebAuthnCredentialIdB64u(input.authMethod.credentialIdB64u);
    if (!credentialId.ok) throw new Error(credentialId.error.message);
    return await buildVerifiedOwnerProof({
      purpose: 'wallet_session',
      proofId: parseVerifiedOwnerProofId(`registration:${input.registrationCeremonyId}`),
      factor: buildVerifiedWalletSessionPasskeyFactorResult({
        ...common,
        credentialIdB64u: credentialId.value,
        assertionDigest: evidenceDigest,
      }),
    });
  }
  return await buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId(`registration:${input.registrationCeremonyId}`),
    factor: buildVerifiedWalletSessionEmailOtpFactorResult({
      ...common,
      challengeId: requireEmailOtpChallengeId(input.authMethod.registrationAuthorityId),
      verificationReceiptDigest: evidenceDigest,
    }),
  });
}

function requireEmailOtpChallengeId(value: string) {
  const parsed = parseEmailOtpChallengeId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function walletSessionAuthSourceFromAuthority(
  authority: WalletAuthAuthority,
): Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'] {
  if (authority.factor.kind === 'passkey') {
    return {
      kind: 'passkey',
      credentialIdB64u: authority.factor.credentialIdB64u,
    };
  }
  const providerSubject = parseProviderSubject(authority.factor.providerUserId);
  if (!providerSubject.ok) throw new Error(providerSubject.error.message);
  return {
    kind: 'oidc_provider',
    providerId: authority.factor.provider === 'google' ? 'google_oidc' : 'oidc',
    providerSubject: providerSubject.value,
  };
}

function registrationEstablishedMintId(
  registrationCeremonyId: string,
): ReusableWalletSessionMintId {
  return requireReusableWalletSessionMintId(`registration-established:${registrationCeremonyId}`);
}

function registrationEstablishedEcdsaAuthorizationSessionId(
  authorizationId: WalletSessionAuthorizationId,
) {
  const parsed = parseEcdsaAuthorizationSessionId(authorizationId);
  if (!parsed.ok)
    throw new Error(
      `Registration-established ECDSA authorization session id is invalid: ${parsed.error.message}`,
    );
  return parsed.value;
}

type D1RegistrationEcdsaFinalizeState =
  | { readonly kind: 'ecdsa_registration_disabled' }
  | {
      readonly kind: 'ecdsa_registration_responded';
      readonly state: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
    };

type D1RegistrationEd25519WalletSessionIdentity = {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly thresholdSessionId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
};

function assertNeverD1RegistrationEcdsaFinalizeState(value: never): never {
  throw new Error(`Unexpected registration ECDSA finalize state: ${String(value)}`);
}

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore;
type WalletStoreProvider = () => D1WalletStore;
type Ed25519YaoProductRegistrationProvider =
  () => RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;
export type SponsoredNamedNearAccountCreationResult =
  | {
      readonly kind: 'created';
      readonly accountId: string;
      readonly transactionHash: string;
    }
  | {
      readonly kind: 'rejected';
      readonly message: string;
    }
  | {
      readonly kind: 'retryable';
      readonly message: string;
      readonly retryAfterMs: number;
    };
type SponsoredNamedNearAccountCreator = (input: {
  readonly accountId: string;
  readonly publicKey: string;
  /**
   * Registration-scoped key. The provisioning boundary persists the signed
   * transaction under this key before broadcasting, so a retry replays those
   * exact bytes instead of building a second transaction.
   */
  readonly idempotencyKey: string;
}) => Promise<SponsoredNamedNearAccountCreationResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function assertNeverSponsoredNamedNearAccountCreationResult(value: never): never {
  throw new Error(`Unexpected sponsored NEAR account creation result: ${String(value)}`);
}

async function cleanupFinalizedRegistrationCeremony(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly registrationCeremonyId: string;
}): Promise<void> {
  try {
    await input.store.deleteCeremony(input.registrationCeremonyId);
  } catch {
    // The replay record remains authoritative until the ceremony TTL expires.
  }
}

type D1RegistrationRouteTimingMark = {
  readonly name: WalletRegistrationRouteTimingName;
  readonly startedAtMs: number;
};

type D1RegistrationRouteTimingRecorder = {
  readonly route: WalletRegistrationRouteDiagnostics['route'];
  readonly entries: WalletRegistrationRouteDiagnostics['entries'];
};

function createD1RegistrationRouteTimingRecorder(
  route: WalletRegistrationRouteDiagnostics['route'],
): D1RegistrationRouteTimingRecorder {
  return {
    route,
    entries: [],
  };
}

function startD1RegistrationRouteTiming(
  name: WalletRegistrationRouteTimingName,
): D1RegistrationRouteTimingMark {
  return {
    name,
    startedAtMs: Date.now(),
  };
}

function finishD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  mark: D1RegistrationRouteTimingMark,
): void {
  recorder.entries.push({
    name: mark.name,
    durationMs: Math.max(0, Date.now() - mark.startedAtMs),
  });
}

function appendD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  name: WalletRegistrationRouteTimingName,
  durationMs: number,
): void {
  recorder.entries.push({
    name,
    durationMs: Math.max(0, Math.round(durationMs)),
  });
}

function d1RegistrationRouteDiagnostics(
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationRouteDiagnostics {
  const diagnostics: WalletRegistrationRouteDiagnostics = {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: recorder.route,
    entries: recorder.entries.map((entry) => ({
      name: entry.name,
      durationMs: entry.durationMs,
    })),
  };
  return diagnostics;
}

function withD1RegistrationRouteDiagnostics(
  response: WalletRegistrationFinalizeResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationFinalizeResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function normalizedKeyHandleSet(keyHandles: readonly string[]): Set<string> {
  const normalized = new Set<string>();
  for (const keyHandle of keyHandles) {
    const value = String(keyHandle || '').trim();
    if (value) normalized.add(value);
  }
  return normalized;
}

export function hasEcdsaKeyHandleSetMismatch(
  expectedKeyHandles: readonly string[],
  actualKeyHandles: readonly string[],
): boolean {
  if (expectedKeyHandles.length === 0) return false;
  const expected = normalizedKeyHandleSet(expectedKeyHandles);
  const actual = normalizedKeyHandleSet(actualKeyHandles);
  if (expected.size !== actual.size) return true;
  for (const keyHandle of expected) {
    if (!actual.has(keyHandle)) return true;
  }
  return false;
}

type RegistrationIntentSignerBranches = {
  readonly plan: RegistrationSignerPlan;
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
  return { ok: true, value: registrationSignerBranchesFromPlan(plan.value) };
}

function registrationSignerBranchesFromPlan(
  plan: RegistrationSignerPlan,
): RegistrationIntentSignerBranches {
  return {
    plan,
    nearEd25519: findRegistrationSignerPlanNearEd25519Branch(plan),
    evmFamilyEcdsa: findRegistrationSignerPlanEvmFamilyEcdsaBranch(plan),
  };
}

type RegistrationPreparedContextResolution =
  | {
      ok: true;
      preparedContext: StoredWalletRegistrationPreparedContext;
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[] | null;
    }
  | {
      ok: false;
      code: 'invalid_body';
      message: string;
    };

function resolveRegistrationPreparedContextFromPlan(input: {
  readonly signerPlan: RegistrationSignerPlan;
  readonly runtimePolicyScope: RuntimePolicyScope | undefined;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): RegistrationPreparedContextResolution {
  const branches = registrationSignerBranchesFromPlan(input.signerPlan);
  const ecdsaChainTargets = branches.evmFamilyEcdsa
    ? normalizeThresholdEcdsaChainTargets(branches.evmFamilyEcdsa.chainTargets)
    : null;
  if (branches.evmFamilyEcdsa && !ecdsaChainTargets) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration contains an invalid chain target',
    };
  }
  try {
    return {
      ok: true,
      preparedContext: buildStoredWalletRegistrationPreparedContext({
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        runtimePolicyScope: input.runtimePolicyScope || null,
        ecdsaChainTargets,
      }),
      ecdsaChainTargets,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'registration prepared context is invalid',
    };
  }
}

function registrationPreparedContextRuntimePolicyScope(
  preparedContext: StoredWalletRegistrationPreparedContext,
): RuntimePolicyScope | undefined {
  return preparedContext.runtimePolicy.kind === 'runtime_policy_scope'
    ? preparedContext.runtimePolicy.scope
    : undefined;
}

function registrationPreparedContextEcdsaChainTargets(
  preparedContext: StoredWalletRegistrationPreparedContext,
): readonly ThresholdEcdsaChainTarget[] | null {
  return preparedContext.ecdsa.kind === 'evm_family_ecdsa_requested'
    ? preparedContext.ecdsa.chainTargets
    : null;
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

/**
 * A verified authority must name the same wallet the intent does. A ceremony
 * still awaiting its proof has no authority to disagree with, so it matches
 * vacuously — respond performs this check again once the proof binds.
 */
function registrationCeremonyWalletsMatch(input: {
  readonly ceremony: {
    readonly intent: RegistrationIntentV1;
    readonly authorityState: StoredWalletRegistrationCeremonyAuthorityState;
  };
}): boolean {
  const authority = verifiedRegistrationCeremonyAuthority(input.ceremony);
  if (!authority) return true;
  return authority.walletId === input.ceremony.intent.walletId;
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

/**
 * A mixed plan finalizes in two calls: `evm_family_ecdsa` first, which returns
 * the wallet ECDSA-ready and leaves the ceremony open, then `near_ed25519`
 * once the Yao ceremony settles (Refactor 94 Phase 4+5). Single-signer plans
 * still finalize in one call.
 *
 * The requested kind must name only branches the plan admitted, and must be
 * legal for the progress those branches have made — a `near_ed25519` call on a
 * mixed plan before the ECDSA commit is durable would return a NEAR-ready
 * wallet whose ECDSA signer does not exist.
 */
function finalizeSignerWorkSequenceFailure(input: {
  readonly request: FinalizeWalletRegistrationInput;
  readonly hasNearEd25519: boolean;
  readonly hasEvmFamilyEcdsa: boolean;
  readonly ecdsaFinalized: boolean;
}): { readonly code: 'invalid_body' | 'invalid_state'; readonly message: string } | null {
  switch (input.request.kind) {
    case 'near_ed25519':
      if (!input.hasNearEd25519) {
        return {
          code: 'invalid_body',
          message: 'registration plan has no Ed25519 signer to finalize',
        };
      }
      if (input.hasEvmFamilyEcdsa && !input.ecdsaFinalized) {
        return {
          code: 'invalid_state',
          message: 'ECDSA finalize must complete before the Ed25519 finalize',
        };
      }
      return null;
    case 'evm_family_ecdsa':
      if (!input.hasEvmFamilyEcdsa) {
        return {
          code: 'invalid_body',
          message: 'registration plan has no ECDSA signer to finalize',
        };
      }
      if (input.ecdsaFinalized) {
        return {
          code: 'invalid_state',
          message: 'ECDSA finalize has already completed for this ceremony',
        };
      }
      return null;
  }
}

function finalizePasskeyRpId(authority: StoredRegistrationAuthority): string {
  if (authority.kind !== 'passkey') {
    throw new Error('passkey finalize auth method requires a passkey registration authority');
  }
  return authority.rpId;
}

export function ecdsaStrictRegistrationAuthority(facts: RouterAbEcdsaRegistrationRequestFactsV1): {
  readonly subjectId: string;
  readonly sessionId: string;
  readonly accountId: string;
  readonly expiresAtMs: number;
} {
  return {
    subjectId: facts.client_id,
    sessionId: facts.lifecycle.session_id,
    accountId: facts.lifecycle.account_id,
    expiresAtMs: facts.expires_at_ms,
  };
}

export function exactEcdsaParticipantPair(participantIds: readonly number[]): readonly [1, 2] {
  if (participantIds.length !== 2 || participantIds[0] !== 1 || participantIds[1] !== 2) {
    throw new Error('ECDSA registration requires participant pair [1, 2]');
  }
  return [1, 2];
}

function ethereumAddressHexFromBase64Url(value: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) {
    throw new Error('ECDSA activation Ethereum address must contain 20 bytes');
  }
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

type D1PendingEcdsaFamilyActivation = {
  readonly prepare: StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch['prepare'];
  readonly strictRegistration: StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch['strictRegistration'];
};

function requireActivatedEcdsaIdentity(input: {
  readonly branch: D1PendingEcdsaFamilyActivation;
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
}): void {
  const registration = input.branch.strictRegistration;
  const receipt = input.activation.ecdsa_activation;
  const identity = receipt.public_identity;
  if (
    receipt.context.application_binding_digest_b64u !==
      registration.context.application_binding_digest_b64u ||
    identity.context_binding_b64u !== input.publicFacts.contextBinding32B64u ||
    identity.derivation_client_share_public_key33_b64u !==
      input.publicFacts.derivationClientSharePublicKey33B64u ||
    identity.client_share_retry_counter !== input.publicFacts.clientShareRetryCounter ||
    input.activation.lifecycle_id !== registration.lifecycle.lifecycle_id ||
    base64UrlEncode(Uint8Array.from(input.activation.transcript_digest.bytes)) !==
      input.publicFacts.proofTranscriptDigestB64u ||
    receipt.signing_worker.server_id !== registration.lifecycle.selected_server_id
  ) {
    throw new Error('ECDSA activation receipt does not match the admitted registration identity');
  }
}

export async function buildActivatedEcdsaFamilyBootstrap(input: {
  readonly branch: D1PendingEcdsaFamilyActivation;
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
}): Promise<EcdsaDerivationServerBootstrapResponse> {
  requireActivatedEcdsaIdentity(input);
  const prepare = input.branch.prepare;
  const identity = input.activation.ecdsa_activation.public_identity;
  const expiresAtMs = input.branch.strictRegistration.expires_at_ms;
  const ethereumAddress = ethereumAddressHexFromBase64Url(identity.ethereum_address20_b64u);
  const publicIdentity = parseEcdsaDerivationPublicIdentity({
    derivationClientSharePublicKey33B64u: input.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: identity.server_public_key33_b64u,
    groupPublicKey33B64u: identity.threshold_public_key33_b64u,
    ethereumAddress,
  });
  if (!publicIdentity) {
    throw new Error('ECDSA activation receipt contains an invalid public identity');
  }
  const keyHandle = await deriveThresholdEcdsaKeyHandle({
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
  });
  const routerAbEcdsaDerivationNormalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: String(prepare.walletId),
      ecdsa_threshold_key_id: prepare.ecdsaThresholdKeyId,
      signing_root_id: prepare.signingRootId,
      signing_root_version: prepare.signingRootVersion,
      context: {
        application_binding_digest_b64u:
          input.branch.strictRegistration.context.application_binding_digest_b64u,
      },
      public_identity: {
        context_binding_b64u: input.publicFacts.contextBinding32B64u,
        derivation_client_share_public_key33_b64u:
          input.publicFacts.derivationClientSharePublicKey33B64u,
        server_public_key33_b64u: identity.server_public_key33_b64u,
        threshold_public_key33_b64u: identity.threshold_public_key33_b64u,
        ethereum_address20_b64u: base64UrlEncode(
          Uint8Array.from(
            ethereumAddress
              .slice(2)
              .match(/.{2}/g)
              ?.map((byte) => Number.parseInt(byte, 16)) ?? [],
          ),
        ),
        client_share_retry_counter: input.publicFacts.clientShareRetryCounter,
        server_share_retry_counter: identity.server_share_retry_counter,
      },
      signing_worker: input.activation.ecdsa_activation.signing_worker,
      material_activation: input.activation.ecdsa_activation.material_activation,
      activation_epoch: input.activation.ecdsa_activation.activation_epoch,
    },
  });
  if (!routerAbEcdsaDerivationNormalSigning) {
    throw new Error('ECDSA activation produced invalid normal-signing state');
  }
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: String(prepare.walletId),
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    relayerKeyId: prepare.relayerKeyId,
    applicationBindingDigestB64u:
      input.branch.strictRegistration.context.application_binding_digest_b64u,
    contextBinding32B64u: input.publicFacts.contextBinding32B64u,
    publicIdentity,
    clientShareRetryCounter: input.publicFacts.clientShareRetryCounter,
    relayerShareRetryCounter: identity.server_share_retry_counter,
    publicTranscriptDigest32B64u: input.publicFacts.proofTranscriptDigestB64u,
    keyHandle,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: identity.threshold_public_key33_b64u,
    ethereumAddress,
    relayerVerifyingShareB64u: identity.server_public_key33_b64u,
    participantIds: [...exactEcdsaParticipantPair(prepare.participantIds)],
    thresholdSessionId: buildRouterAbEcdsaDerivationActiveStateIdV1({
      ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
      signingRootId: prepare.signingRootId,
      signingRootVersion: prepare.signingRootVersion,
      activationEpoch: input.activation.ecdsa_activation.activation_epoch,
    }),
    activationEpoch: input.activation.ecdsa_activation.activation_epoch,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: prepare.remainingUses,
    routerAbEcdsaDerivationNormalSigning,
  };
}

type EcdsaPostRegistrationProofInput = {
  readonly operation: 'refresh';
  readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
  readonly response: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
};

function postRegistrationProofResponse(
  input: EcdsaPostRegistrationProofInput,
): RouterAbEcdsaStrictForwardedRegistrationResponseV1['response'] {
  return input.response.response;
}

function postRegistrationProofMatchesRequest(input: EcdsaPostRegistrationProofInput): boolean {
  const response = postRegistrationProofResponse(input);
  return (
    response.bundles.signerA.transcriptDigestB64u === response.bundles.signerB.transcriptDigestB64u
  );
}

function postRegistrationRequestId(input: EcdsaPostRegistrationProofInput): string {
  return input.request.refresh_nonce;
}

function pendingEcdsaSessionActivationRecord(input: {
  readonly proof: EcdsaPostRegistrationProofInput;
  readonly walletId: WalletId;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly nowMs: number;
}): WalletEcdsaPendingSessionActivationRecord {
  const response = postRegistrationProofResponse(input.proof);
  const base = {
    version: 'wallet_ecdsa_pending_session_activation_v1',
    walletId: input.walletId,
    lifecycleId: input.proof.request.lifecycle.lifecycle_id,
    requestId: postRegistrationRequestId(input.proof),
    publicCapability: input.publicCapability,
    createdAtMs: input.nowMs,
    expiresAtMs: input.proof.request.expires_at_ms,
  } as const;
  return {
    ...base,
    operation: 'refresh',
    request: input.proof.request,
    response: input.proof.response,
  };
}

function buildPostRegistrationEcdsaNormalSigningState(input: {
  readonly walletKey: WalletEcdsaSignerKey;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const capability = input.publicCapability;
  const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: input.walletKey.walletId,
      ecdsa_threshold_key_id: input.walletKey.ecdsaThresholdKeyId,
      signing_root_id: input.walletKey.signingRootId,
      signing_root_version: input.walletKey.signingRootVersion,
      context: capability.context,
      public_identity: capability.public_identity,
      material_activation: capability.material_activation,
      signing_worker: capability.signer_set.selected_server,
      activation_epoch: capability.activation_epoch,
    },
  });
  if (!state) {
    throw new Error('registered ECDSA normal-signing state is invalid');
  }
  return state;
}

/**
 * Upper bound on Router metrics folded into one Gateway header. The Router is
 * ours, but a merged header grows at every hop, so the fold is bounded rather
 * than trusting the peer to stay terse.
 */
const ROUTER_SERVER_TIMING_MERGE_LIMIT = 32;

/** Metric names the Gateway is willing to re-emit in its own header. */
const ROUTER_SERVER_TIMING_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Folds the Router's own `Server-Timing` header into the Gateway's span list
 * (Refactor 94B Phase 0), so the Router and role-worker breakdown reaches the
 * browser on the same header as the Gateway's own boundaries.
 *
 * Entries without a finite non-negative `dur` are dropped, which also discards
 * Cloudflare's descriptive metrics, and names are restricted to a token
 * charset so a metric name can never forge extra entries downstream.
 */
export function mergeRouterServerTiming(
  target: Array<readonly [string, number]>,
  header: string,
): void {
  let merged = 0;
  for (const entry of header.split(',')) {
    if (merged >= ROUTER_SERVER_TIMING_MERGE_LIMIT) return;
    const parts = entry.split(';');
    const name = String(parts[0] || '').trim();
    if (!ROUTER_SERVER_TIMING_NAME_PATTERN.test(name)) continue;
    for (const part of parts.slice(1)) {
      const [key, rawValue] = part.split('=');
      if (String(key || '').trim() !== 'dur') continue;
      const duration = Number(String(rawValue || '').trim());
      if (!Number.isFinite(duration) || duration < 0) break;
      target.push([name, duration]);
      merged += 1;
      break;
    }
  }
}

export class CloudflareD1WalletRegistrationService {
  private readonly authorizationService: AuthorizationService;
  private readonly authorizationTenantId: TenantId;
  private readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
  private readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  private readonly getWalletStore: WalletStoreProvider;
  /** The single Gateway operation row for activate-with-finalize (94C). */
  private readonly activateSideEffects: D1WalletRegistrationActivateSideEffectStore;
  /** Deferred NEAR provisioning's own operation row (94C). */
  private readonly nearProvisioningSideEffects: D1WalletRegistrationNearProvisioningSideEffectStore;
  private readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
  /** Where a ceremony's sealed custody seed and its recovery set land. */
  private readonly walletCustodyCommitStore: CloudflareD1WalletCustodyCommitStore;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly authorizationService: AuthorizationService;
    readonly authorizationTenantId: TenantId;
    readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
    readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
    readonly getWalletStore: WalletStoreProvider;
    readonly activateSideEffects: D1WalletRegistrationActivateSideEffectStore;
    readonly nearProvisioningSideEffects: D1WalletRegistrationNearProvisioningSideEffectStore;
    readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
    readonly walletCustodyCommitStore: CloudflareD1WalletCustodyCommitStore;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.authorizationService = input.authorizationService;
    this.authorizationTenantId = input.authorizationTenantId;
    this.createSponsoredNamedNearAccount = input.createSponsoredNamedNearAccount;
    this.emailOtpRegistrationEnrollmentFinalizer = input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getEd25519YaoProductRegistration = input.getEd25519YaoProductRegistration;
    this.ecdsaStrictRegistration = input.ecdsaStrictRegistration;
    this.getWalletStore = input.getWalletStore;
    this.activateSideEffects = input.activateSideEffects;
    this.nearProvisioningSideEffects = input.nearProvisioningSideEffects;
    this.walletRegistrationCommitStore = input.walletRegistrationCommitStore;
    this.walletCustodyCommitStore = input.walletCustodyCommitStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async getWalletRegistrationRuntimePolicyScope(
    registrationCeremonyId: string,
  ): Promise<RuntimePolicyScope | undefined> {
    const store = this.getRegistrationCeremonyIntentStore();
    const ceremony = await store.getCeremony(registrationCeremonyId);
    if (!ceremony) return undefined;
    return registrationPreparedContextRuntimePolicyScope(ceremony.preparedContext);
  }

  private async issueRegistrationEstablishedGrant(input: {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
  }): Promise<IssuedReusableWalletSession> {
    const issuedAtMs = Date.now();
    if (!Number.isSafeInteger(input.remainingUses) || input.remainingUses <= 0) {
      throw new Error('Registration-established session remaining uses is invalid');
    }
    if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= issuedAtMs) {
      throw new Error('Registration-established session expiry is invalid');
    }
    const expiresAtMs = Math.min(input.expiresAtMs, issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS);
    const remainingUses = Math.min(DEFAULT_WALLET_SESSION_REMAINING_USES, input.remainingUses);
    const activeRegistration =
      await this.walletAuthMethods.readActiveRegistrationAuthority(input.registrationAuthority);
    if (
      !activeRegistration ||
      activeRegistration.authority.walletId !== input.authority.walletId ||
      activeRegistration.walletAuthMethodId !== input.walletAuthMethodId
    ) {
      throw new Error('Registration founding authority is unavailable after commit');
    }
    const authorityRef = await registrationWalletAuthAuthorityRef({
      authority: input.authority,
    });
    const reusableWalletSession = await this.authorizationService.issueReusableWalletSession({
      tenantId: this.authorizationTenantId,
      principalId: reusableWalletSessionPrincipalId(input.authority),
      walletId: walletIdFromString(String(input.authority.walletId)),
      authority: authorityRef,
      mintId: registrationEstablishedMintId(input.registrationCeremonyId),
      remainingUses,
      issuedAtMs,
      expiresAtMs,
    });
    await this.authorizationService.issueWalletSessionAuthorizationV2FromReusableSession({
      reusableWalletSession,
      authority: activeRegistration.authority,
      walletAuthMethodId: activeRegistration.walletAuthMethodId,
    });
    return reusableWalletSession;
  }

  private async readRegistrationEstablishedGrant(input: {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<IssuedReusableWalletSession | null> {
    const authorityRef = await registrationWalletAuthAuthorityRef({
      authority: input.authority,
    });
    return await this.authorizationService.readWalletSessionAuthorizationByMint({
      tenantId: this.authorizationTenantId,
      principalId: reusableWalletSessionPrincipalId(input.authority),
      walletId: walletIdFromString(String(input.authority.walletId)),
      authority: authorityRef,
      mintId: registrationEstablishedMintId(input.registrationCeremonyId),
      nowMs: Date.now(),
    });
  }

  private registrationEstablishedSessionBase(
    authority: WalletAuthAuthority,
    reusableWalletSession: IssuedReusableWalletSession,
  ) {
    return {
      walletId: walletIdFromString(String(authority.walletId)),
      authorizationId: reusableWalletSession.session.authorizationId,
      walletSessionId: reusableWalletSession.quota.walletSessionId,
      quotaId: reusableWalletSession.quota.quotaId,
      expiresAtMs: reusableWalletSession.quota.expiresAtMs,
      remainingUses: reusableWalletSession.quota.remainingUses,
    } as const;
  }

  private async issueRegistrationEstablishedEcdsaSession(input: {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly keyManifestDigestB64u: DigestB64u;
  }): Promise<RegistrationEstablishedSession> {
    const reusableWalletSession = await this.issueRegistrationEstablishedGrant(input);
    const base = this.registrationEstablishedSessionBase(input.authority, reusableWalletSession);
    const bootstrap = input.bootstrap;
    const thresholdSessionId = parseThresholdEcdsaSessionId(bootstrap.thresholdSessionId);
    if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
    const keyHandle = await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
      signingRootId: bootstrap.signingRootId,
      signingRootVersion: bootstrap.signingRootVersion,
    });
    if (keyHandle !== bootstrap.keyHandle) {
      throw new Error('Registration ECDSA bootstrap key handle is inconsistent');
    }
    const signed = await issueRouterAbEcdsaDerivationOpaqueWalletSessionToken({
      opaqueWalletSessions: this.authorizationService,
      tenantId: this.authorizationTenantId,
      proof: input.proof,
      walletAuthAuthorityRef: await registrationWalletAuthAuthorityRef({
        authority: input.authority,
      }),
      authSource: walletSessionAuthSourceFromAuthority(input.authority),
      userId: bootstrap.walletId,
      relayerKeyId: bootstrap.relayerKeyId,
      fallbackParticipantIds: bootstrap.participantIds,
      invalidPayloadErrorMessage: 'Registration-established ECDSA Wallet Session is invalid',
      sessionInfo: {
        sessionKind: 'opaque',
        authorizationKind: 'owner_wallet_session',
        thresholdSessionId: thresholdSessionId.value,
        authorizationId: base.authorizationId,
        walletSessionId: base.walletSessionId,
        quotaId: base.quotaId,
        expiresAtMs: base.expiresAtMs,
        participantIds: bootstrap.participantIds,
        runtimePolicyScope: input.runtimePolicyScope,
        keyManifestDigestB64u: input.keyManifestDigestB64u,
        authorizationSessionId: registrationEstablishedEcdsaAuthorizationSessionId(
          base.authorizationId,
        ),
        keyHandle,
        stableKeyContext: {
          walletId: bootstrap.walletId,
          keyScope: 'evm-family',
          ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
          signingRootId: bootstrap.signingRootId,
          signingRootVersion: bootstrap.signingRootVersion,
          applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
          contextBinding32B64u: bootstrap.contextBinding32B64u,
        },
        publicIdentity: bootstrap.publicIdentity,
        activationEpoch: bootstrap.activationEpoch,
        signingWorkerId:
          bootstrap.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id,
        routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
      },
    });
    if (!signed.ok) throw new Error(signed.message);
    if (signed.authorizationKind !== 'owner_wallet_session') {
      throw new Error('Registration ECDSA owner Wallet Session issuance failed');
    }
    return {
      kind: 'registration_established_wallet_session_v1',
      ...base,
      tokens: {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          sessionKind: 'opaque',
          walletSessionToken: signed.token,
          thresholdSessionId: thresholdSessionId.value,
          keyHandle,
          runtimePolicyScope: input.runtimePolicyScope,
          routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
        },
      },
    };
  }

  private async issueOrReuseRegistrationEstablishedEd25519Session(input: {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly publicResult: WalletRegistrationEd25519YaoPublicResult;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly keyManifestDigestB64u: DigestB64u;
  }): Promise<RegistrationEstablishedSession> {
    const reusableWalletSession =
      (await this.readRegistrationEstablishedGrant(input)) ??
      (await this.issueRegistrationEstablishedGrant(input));
    const base = this.registrationEstablishedSessionBase(input.authority, reusableWalletSession);
    const publicResult = input.publicResult;
    const thresholdSessionId = parseThresholdEd25519SessionId(publicResult.thresholdSessionId);
    if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
    const signed = await issueRouterAbEd25519OpaqueWalletSessionToken({
      opaqueWalletSessions: this.authorizationService,
      tenantId: this.authorizationTenantId,
      proof: input.proof,
      userId: input.authority.walletId,
      relayerKeyId: publicResult.relayerKeyId,
      authority: input.authority,
      fallbackParticipantIds: publicResult.participantIds,
      invalidPayloadErrorMessage: 'Registration-established Ed25519 Wallet Session is invalid',
      sessionInfo: {
        sessionKind: 'opaque',
        authorizationKind: 'owner_wallet_session',
        walletId: input.authority.walletId,
        nearAccountId: publicResult.nearAccountId,
        nearEd25519SigningKeyId: publicResult.nearEd25519SigningKeyId,
        authorizationId: base.authorizationId,
        thresholdSessionId: thresholdSessionId.value,
        walletSessionId: base.walletSessionId,
        quotaId: base.quotaId,
        expiresAtMs: base.expiresAtMs,
        participantIds: publicResult.participantIds,
        runtimePolicyScope: publicResult.runtimePolicyScope,
        routerAbNormalSigning: publicResult.routerAbNormalSigning,
        keyManifestDigestB64u: input.keyManifestDigestB64u,
      },
    });
    if (!signed.ok) throw new Error(signed.message);
    if (signed.authorizationKind !== 'owner_wallet_session') {
      throw new Error('Registration Ed25519 owner Wallet Session issuance failed');
    }
    const nearAccount = parseImplicitNearAccountId(publicResult.nearAccountId);
    const namedNearAccount = parseNamedNearAccountId(publicResult.nearAccountId);
    const nearAccountId = nearAccount.ok
      ? nearAccount.value
      : namedNearAccount.ok
        ? namedNearAccount.value
        : null;
    if (!nearAccountId) throw new Error('Registration Ed25519 near account identity is invalid');
    return {
      kind: 'registration_established_wallet_session_v1',
      ...base,
      tokens: {
        kind: 'near_ed25519',
        ed25519: {
          sessionKind: 'opaque',
          walletSessionToken: signed.token,
          thresholdSessionId: thresholdSessionId.value,
          nearAccountId,
          nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
            publicResult.nearEd25519SigningKeyId,
          ),
          runtimePolicyScope: publicResult.runtimePolicyScope,
          routerAbNormalSigning: publicResult.routerAbNormalSigning,
        },
      },
    };
  }

  async resolveEd25519MaterialActivation(input: {
    readonly walletId: string;
    readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  }): Promise<
    | {
        readonly ok: true;
        readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
        readonly nearAccountId: string;
        readonly signerSlot: number;
        readonly signingWorkerId: string;
        readonly participantIds: readonly [number, number];
        readonly runtimePolicyScope: RuntimePolicyScope;
      }
    | { readonly ok: false; readonly code: 'not_found' | 'internal'; readonly message: string }
  > {
    try {
      const walletId = walletIdFromString(input.walletId);
      const signer = await this.getWalletStore().getEd25519SignerByMaterialActivation({
        walletId,
        materialActivation: input.materialActivation,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Ed25519 material activation is not active for this wallet',
        };
      }
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      if (!yaoRuntime) {
        return {
          ok: false,
          code: 'internal',
          message: 'Ed25519 Yao capability resolver is not configured',
        };
      }
      const active = await yaoRuntime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId: input.walletId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        signerSlot: signer.signerSlot,
        signingWorkerId: signer.signingWorkerId,
        participantIds: signer.participantIds,
      });
      if (!active.ok) {
        return {
          ok: false,
          code: active.code === 'unknown_capability' ? 'not_found' : 'internal',
          message: active.message,
        };
      }
      if (
        !sameRouterAbMpcMaterialActivationRef(
          active.capability.materialActivation,
          input.materialActivation,
        )
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Ed25519 material activation does not match the active capability',
        };
      }
      return {
        ok: true,
        materialActivation: active.capability.materialActivation,
        nearAccountId: active.capability.nearAccountId,
        signerSlot: signer.signerSlot,
        signingWorkerId: signer.signingWorkerId,
        participantIds: signer.participantIds,
        runtimePolicyScope: active.capability.runtimePolicyScope,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : 'Ed25519 material lookup failed',
      };
    }
  }

  async resolveEcdsaMaterialActivation(input: {
    readonly walletId: string;
    readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  }): Promise<
    | {
        readonly ok: true;
        readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
        readonly keyHandle: string;
        readonly relayerKeyId: string;
        readonly participantIds: readonly [number, number];
        readonly runtimePolicyScope: RuntimePolicyScope;
      }
    | { readonly ok: false; readonly code: 'not_found' | 'internal'; readonly message: string }
  > {
    try {
      const signer = await this.getWalletStore().getEcdsaSignerByMaterialActivation({
        walletId: walletIdFromString(input.walletId),
        materialActivation: input.materialActivation,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA material activation is not active for this wallet',
        };
      }
      return {
        ok: true,
        materialActivation: signer.walletKey.publicCapability.material_activation,
        keyHandle: signer.walletKey.keyHandle,
        relayerKeyId: signer.walletKey.relayerKeyId,
        participantIds: signer.walletKey.participantIds,
        runtimePolicyScope: signer.runtimePolicyScope,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : 'ECDSA material lookup failed',
      };
    }
  }

  async listWalletEcdsaKeyFactsInventory(input: {
    readonly walletId: string;
    readonly rpId: string;
    readonly keyTargets: readonly unknown[];
  }): Promise<{
    readonly records: ThresholdEcdsaKeyInventoryRecord[];
    readonly diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    const store = this.getWalletStore();
    return await listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
      getEcdsaSignerByKeyHandle: store.getEcdsaSignerByKeyHandle.bind(store),
    });
  }

  async listWalletEcdsaCustodyContinuity(input: {
    readonly walletId: string;
  }): Promise<readonly WalletEcdsaSignerRecord[]> {
    return await this.getWalletStore().listEcdsaSignersForWallet({
      walletId: walletIdFromString(input.walletId),
    });
  }

  async recordEcdsaPostRegistrationProof(
    input: EcdsaPostRegistrationProofInput,
  ): Promise<
    { readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    try {
      const nowMs = Date.now();
      if (input.request.expires_at_ms <= nowMs || !postRegistrationProofMatchesRequest(input)) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA post-registration proof does not match its admitted request',
        };
      }
      const walletId = walletIdFromString(input.request.lifecycle.account_id);
      if (input.request.client_id !== walletId || input.request.lifecycle.root_share_epoch === '') {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA post-registration proof has an invalid wallet identity',
        };
      }
      const store = this.getWalletStore();
      const signer = await store.getEcdsaSignerByPostRegistrationRequest({
        walletId,
        request: input.request,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA post-registration public capability is not registered',
        };
      }
      if (
        input.request.previous_activation_epoch !==
        signer.walletKey.publicCapability.activation_epoch
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA post-registration request uses a stale activation epoch',
        };
      }
      await store.putEcdsaPendingSessionActivation(
        pendingEcdsaSessionActivationRecord({
          proof: input,
          walletId,
          publicCapability: signer.walletKey.publicCapability,
          nowMs,
        }),
      );
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to persist ECDSA post-registration proof',
      };
    }
  }

  async activateEcdsaPostRegistrationSession(
    input: RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  ): Promise<
    | {
        readonly ok: true;
        readonly walletKey: WalletEcdsaSignerKey;
        readonly session: {
          readonly thresholdSessionId: string;
          readonly expiresAtMs: number;
          readonly remainingUses: number;
        };
        readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
        /** Recorded on the signer record when registration verified this key set. */
        readonly keyManifestDigestB64u: DigestB64u;
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    try {
      const nowMs = Date.now();
      const walletId = walletIdFromString(input.public_capability.client_id);
      const store = this.getWalletStore();
      const signer = await store.getEcdsaSignerByPublicCapability({
        walletId,
        publicCapability: input.public_capability,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA public capability is not registered for this wallet',
        };
      }
      const walletKey = signer.walletKey;
      const signingRootScope = signingRootScopeFromRuntimePolicyScope(
        input.session_policy.runtime_policy_scope,
      );
      if (
        signingRootScope.signingRootId !== walletKey.signingRootId ||
        signingRootScope.signingRootVersion !== walletKey.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA session policy is outside the registered signing-root scope',
        };
      }
      const normalSigning = buildPostRegistrationEcdsaNormalSigningState({
        walletKey,
        publicCapability: input.public_capability,
      });
      const activeThresholdSessionId = input.session_policy.threshold_session_id;
      const expiresAtMs = nowMs + input.session_policy.ttl_ms;
      return {
        ok: true,
        walletKey,
        session: {
          thresholdSessionId: activeThresholdSessionId,
          expiresAtMs,
          remainingUses: input.session_policy.remaining_uses,
        },
        normalSigning,
        keyManifestDigestB64u: parseDigestB64u(signer.custodyKeyManifestDigestB64u),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate ECDSA post-registration session',
      };
    }
  }

  async refreshEd25519YaoWalletSession(
    request: RouterAbEd25519YaoBudgetRefreshRequestV1,
  ): Promise<RouterAbEd25519YaoBudgetRefreshResponseV1> {
    try {
      const policy = request.sessionPolicy;
      const authorization = request.authorization;
      const authority = policy.authority;
      const runtimePolicyScope = policy.runtimePolicyScope;
      const routerAbNormalSigning = policy.routerAbNormalSigning;
      const participantIds = normalizeThresholdEd25519ParticipantIds(policy.participantIds);
      if (
        !runtimePolicyScope ||
        !routerAbNormalSigning ||
        !participantIds ||
        participantIds.length !== 2 ||
        !walletAuthAuthoritiesMatch(authority, authorization.authority)
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh policy is invalid',
        };
      }
      if (!isPasskeyWalletAuthAuthority(authority)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao passkey budget refresh requires passkey authority',
        };
      }
      const firstParticipantId = participantIds[0];
      const secondParticipantId = participantIds[1];
      if (firstParticipantId === undefined || secondParticipantId === undefined) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh requires exactly two participants',
        };
      }
      const exactParticipantIds: readonly [number, number] = [
        firstParticipantId,
        secondParticipantId,
      ];
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      if (!yaoRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Ed25519 Yao Wallet Session refresh is not configured',
        };
      }
      if (
        policy.relayerKeyId !== yaoRuntime.signingWorkerId ||
        routerAbNormalSigning.signingWorkerId !== yaoRuntime.signingWorkerId
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'Ed25519 Yao budget refresh does not match the active Wallet Session',
        };
      }
      const activeAuthority = await this.walletAuthMethods.verifyActivePasskeyAuthority(
        authorization.authority,
      );
      if (!activeAuthority.ok) return activeAuthority;
      const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
      const signingRootVersion = toOptionalTrimmedString(signingRoot.signingRootVersion);
      if (!signingRootVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh requires a signing-root version',
        };
      }
      const signer = await this.getWalletStore().getEd25519Signer({
        walletId: authority.walletId,
        nearAccountId: policy.nearAccountId,
        nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
      });
      if (
        !signer ||
        signer.signingWorkerId !== yaoRuntime.signingWorkerId ||
        alphabetizeStringify(signer.participantIds) !== alphabetizeStringify(exactParticipantIds) ||
        signer.signingRootId !== signingRoot.signingRootId ||
        signer.signingRootVersion !== signingRootVersion ||
        alphabetizeStringify(signer.runtimePolicyScope) !== alphabetizeStringify(runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Registered Ed25519 Yao signer does not match the refresh policy',
        };
      }
      const issuedAtMs = Date.now();
      let sessionIdentity:
        | {
            readonly kind: 'same_identity_budget_refresh_v1';
            readonly authorizationId: WalletSessionAuthorizationId;
            readonly walletSessionId: WalletSessionId;
            readonly quotaId: MpcWalletSigningQuotaId;
            readonly remainingUses: number;
          }
        | {
            readonly kind: 'same_wallet_session_curve_mint_v1';
            readonly authorizationId: WalletSessionAuthorizationId;
            readonly walletSessionId: WalletSessionId;
            readonly quotaId: MpcWalletSigningQuotaId;
            readonly expiresAtMs: number;
            readonly remainingUses: number;
          };
      switch (request.kind) {
        case 'router_ab_ed25519_yao_budget_refresh_v1': {
          const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
          const remainingUses = Math.min(
            DEFAULT_WALLET_SESSION_REMAINING_USES,
            policy.remainingUses,
          );
          const mintId = requireReusableWalletSessionMintId(authorization.verifiedChallengeId);
          const reusableWalletSession = await this.authorizationService.issueReusableWalletSession({
            tenantId: this.authorizationTenantId,
            principalId: reusableWalletSessionPrincipalId(authority),
            walletId: authority.walletId,
            authority: await walletAuthAuthorityRef({ authority }),
            mintId,
            remainingUses,
            issuedAtMs,
            expiresAtMs,
          });
          sessionIdentity = {
            kind: 'same_identity_budget_refresh_v1' as const,
            authorizationId: reusableWalletSession.session.authorizationId,
            walletSessionId: reusableWalletSession.quota.walletSessionId,
            quotaId: reusableWalletSession.quota.quotaId,
            remainingUses,
          };
          break;
        }
        case 'router_ab_ed25519_yao_same_wallet_session_curve_mint_v1':
          sessionIdentity = {
            kind: 'same_wallet_session_curve_mint_v1' as const,
            ...request.existingWalletSession,
          };
          break;
      }
      let sessionInput: RouterAbEd25519YaoWalletSessionMintInputV1;
      switch (sessionIdentity.kind) {
        case 'same_identity_budget_refresh_v1':
          sessionInput = {
            kind: 'same_identity_budget_refresh_v1',
            walletId: authority.walletId,
            nearAccountId: policy.nearAccountId,
            nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
            authority,
            thresholdSessionId: policy.thresholdSessionId,
            authorizationId: sessionIdentity.authorizationId,
            walletSessionId: sessionIdentity.walletSessionId,
            quotaId: sessionIdentity.quotaId,
            remainingUses: sessionIdentity.remainingUses,
            participantIds: exactParticipantIds,
            runtimePolicyScope,
            keyManifestDigestB64u: parseDigestB64u(signer.custodyKeyManifestDigestB64u),
            proof: authorization.proof,
          };
          break;
        case 'same_wallet_session_curve_mint_v1':
          sessionInput = {
            kind: 'same_wallet_session_curve_mint_v1',
            walletId: authority.walletId,
            nearAccountId: policy.nearAccountId,
            nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
            authority,
            thresholdSessionId: policy.thresholdSessionId,
            authorizationId: sessionIdentity.authorizationId,
            walletSessionId: sessionIdentity.walletSessionId,
            quotaId: sessionIdentity.quotaId,
            expiresAtMs: sessionIdentity.expiresAtMs,
            remainingUses: sessionIdentity.remainingUses,
            participantIds: exactParticipantIds,
            runtimePolicyScope,
            keyManifestDigestB64u: parseDigestB64u(signer.custodyKeyManifestDigestB64u),
            proof: authorization.proof,
          };
          break;
      }
      const minted = await mintRouterAbEd25519YaoWalletSessionV1({
        opaqueWalletSessions: this.authorizationService,
        tenantId: this.authorizationTenantId,
        signingWorkerId: yaoRuntime.signingWorkerId,
        sessionInput,
      });
      if (!minted.ok) return minted;
      const session = minted.session;
      return {
        ok: true,
        walletId: session.walletId,
        nearAccountId: session.nearAccountId,
        nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
        authorityScope: session.authorityScope,
        thresholdSessionId: session.thresholdSessionId,
        authorizationId: sessionIdentity.authorizationId,
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
        expiresAtMs: session.expiresAtMs,
        expiresAt: new Date(session.expiresAtMs).toISOString(),
        participantIds: exactParticipantIds,
        remainingUses: session.remainingUses,
        runtimePolicyScope,
        routerAbNormalSigning,
        walletSessionToken: session.walletSessionToken,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Ed25519 Yao Wallet Session refresh failed',
      };
    }
  }

  async provisionEd25519YaoWalletSession(
    request: RouterAbEd25519YaoVerifiedWalletUnlockRequestV1,
  ): Promise<RouterAbEd25519YaoVerifiedWalletUnlockResponseV1> {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const verifiedChallengeId = toOptionalTrimmedString(request.verifiedChallengeId);
      const signerSlot = Math.floor(Number(request.signerSlot));
      const remainingUses = Math.floor(Number(request.remainingUses));
      if (
        !walletId ||
        !verifiedChallengeId ||
        !Number.isSafeInteger(signerSlot) ||
        signerSlot < 1 ||
        !Number.isSafeInteger(remainingUses) ||
        remainingUses < 1
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Verified Ed25519 Wallet Session request is invalid',
        };
      }
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      if (!yaoRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Verified Ed25519 Wallet Session provisioning is not configured',
        };
      }
      const authority = request.authority;
      if (String(authority.walletId) !== walletId) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'Verified owner proof does not match the wallet authority',
        };
      }
      const signer = await this.getWalletStore().getEd25519SignerBySlot({
        walletId: walletIdFromString(walletId),
        signerSlot,
      });
      const firstParticipantId = signer?.participantIds[0];
      const secondParticipantId = signer?.participantIds[1];
      if (
        !signer ||
        signer.walletId !== walletId ||
        signer.signerSlot !== signerSlot ||
        signer.signingWorkerId !== yaoRuntime.signingWorkerId ||
        firstParticipantId === undefined ||
        secondParticipantId === undefined
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Registered Ed25519 Yao signer is unavailable for wallet unlock',
        };
      }
      const participantIds: readonly [number, number] = [firstParticipantId, secondParticipantId];
      const signingRoot = signingRootScopeFromRuntimePolicyScope(signer.runtimePolicyScope);
      if (
        signingRoot.signingRootId !== signer.signingRootId ||
        signingRoot.signingRootVersion !== signer.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Registered Ed25519 Yao signer has inconsistent signing-root scope',
        };
      }
      const capability = await yaoRuntime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        signerSlot,
        signingWorkerId: signer.signingWorkerId,
        participantIds,
      });
      if (!capability.ok) return capability;
      const descriptor = capability.capability;
      if (
        descriptor.applicationBinding.wallet_id !== walletId ||
        descriptor.applicationBinding.near_ed25519_signing_key_id !==
          signer.nearEd25519SigningKeyId ||
        descriptor.applicationBinding.key_creation_signer_slot !== signerSlot ||
        descriptor.applicationBinding.signing_root_id !== signer.signingRootId ||
        descriptor.nearAccountId !== signer.nearAccountId ||
        descriptor.lifecycle.accountId !== walletId ||
        descriptor.lifecycle.signerSetId !== String(registrationNearEd25519BranchKey(signerSlot)) ||
        descriptor.lifecycle.signingWorkerId !== signer.signingWorkerId ||
        descriptor.lifecycle.rootShareEpoch !== signer.signingRootVersion ||
        ed25519NearPublicKeyFromBytes(descriptor.registeredPublicKey) !== signer.publicKey ||
        alphabetizeStringify(descriptor.participantIds) !== alphabetizeStringify(participantIds) ||
        alphabetizeStringify(descriptor.runtimePolicyScope) !==
          alphabetizeStringify(signer.runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'capability_conflict',
          message: 'Active Ed25519 Yao capability does not match the registered signer',
        };
      }
      const issuedAtMs = Date.now();
      const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
      const reusableRemainingUses = Math.min(DEFAULT_WALLET_SESSION_REMAINING_USES, remainingUses);
      const reusableWalletSession = await this.authorizationService.issueReusableWalletSession({
        tenantId: this.authorizationTenantId,
        principalId: reusableWalletSessionPrincipalId(authority),
        walletId: walletIdFromString(walletId),
        authority: await walletAuthAuthorityRef({ authority }),
        mintId: requireReusableWalletSessionMintId(verifiedChallengeId),
        remainingUses: reusableRemainingUses,
        issuedAtMs,
        expiresAtMs,
      });
      const minted = await mintRouterAbEd25519YaoWalletSessionV1({
        opaqueWalletSessions: this.authorizationService,
        tenantId: this.authorizationTenantId,
        signingWorkerId: yaoRuntime.signingWorkerId,
        sessionInput: {
          kind: 'verified_wallet_unlock_v1',
          walletId: walletIdFromString(walletId),
          nearAccountId: signer.nearAccountId,
          nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
          authority,
          thresholdSessionId: descriptor.lifecycle.thresholdSessionId,
          authorizationId: reusableWalletSession.session.authorizationId,
          walletSessionId: reusableWalletSession.quota.walletSessionId,
          quotaId: reusableWalletSession.quota.quotaId,
          participantIds,
          runtimePolicyScope: signer.runtimePolicyScope,
          keyManifestDigestB64u: parseDigestB64u(signer.custodyKeyManifestDigestB64u),
          expiresAtMs,
          remainingUses: reusableRemainingUses,
          proof: request.proof,
        },
      });
      if (!minted.ok) return minted;
      const session = minted.session;
      return { ok: true, session, capability: descriptor };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Verified Ed25519 Wallet Session provisioning failed',
      };
    }
  }

  /**
   * Refactor 94C. `/wallets/register/setup` — grant, intent, and start in one
   * request, with one D1 write.
   *
   * Setup runs before the client's WebAuthn create, because it issues the
   * challenge that create signs. So the ECDSA prepare and the Ed25519
   * admission — the two Router calls that dominated the measured cold path —
   * overlap the authenticator prompt instead of being serialized after it.
   * They are started before either is awaited: they share no state and neither
   * can invalidate the other.
   */
  async setupWalletRegistration(
    input: WalletRegistrationSetupInput,
  ): Promise<WalletRegistrationSetupResponseV2> {
    const timing = createD1RegistrationRouteTimingRecorder('wallets_register_setup');
    const total = startD1RegistrationRouteTiming('registerSetupTotalMs');
    try {
      const normalized = normalizeWalletRegistrationSetupRequest(input.request);
      if (!normalized.ok) return walletRegistrationSetupError(normalized.code, normalized.message);

      const wallet = resolveWalletRegistrationSetupWalletId({
        wallet: input.request?.wallet,
        parseProvided: parseWalletIdForIntent,
        createServerAllocated: createD1ServerAllocatedWalletId,
      });
      if (!wallet.ok) return walletRegistrationSetupError(wallet.code, wallet.message);

      const runtimePolicyScope =
        input.runtimePolicyScope ||
        inferRuntimePolicyScopeFromSigningRoot({
          orgId: input.orgId,
          signingRootId: input.signingRootId,
          signingRootVersion: input.signingRootVersion,
        });
      const signingRootId =
        toOptionalTrimmedString(input.signingRootId) ||
        (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
      const signingRootVersion =
        toOptionalTrimmedString(input.signingRootVersion) ||
        runtimePolicyScope?.signingRootVersion ||
        'default';
      if (!signingRootId) {
        return walletRegistrationSetupError('invalid_body', 'registration requires a signing root');
      }

      const intent = buildRegistrationIntent({
        walletId: wallet.walletId,
        authMethod: normalized.authMethod,
        signerSelection: normalized.signerSelection,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      });
      const digestB64u = await walletRegistrationSetupIntentDigest(intent);
      const branches = registrationIntentSignerBranches(intent);
      if (!branches.ok) return walletRegistrationSetupError(branches.code, branches.message);
      const ecdsaBranch = branches.value.evmFamilyEcdsa;
      const nearEd25519Branch = branches.value.nearEd25519;
      if (!ecdsaBranch && !nearEd25519Branch) {
        return walletRegistrationSetupError(
          'invalid_body',
          'registration signer branch is required',
        );
      }
      /* A mixed plan is stored whole — the plan is what the ceremony agreed
         to — but only its ECDSA branch is prepared here. Respond adds the
         Ed25519 branch once the verified authority determines its scope. */
      const preparedContext = resolveRegistrationPreparedContextFromPlan({
        signerPlan: branches.value.plan,
        runtimePolicyScope,
        signingRootId,
        signingRootVersion,
      });
      if (!preparedContext.ok) {
        return walletRegistrationSetupError(preparedContext.code, preparedContext.message);
      }
      if (ecdsaBranch && !runtimePolicyScope) {
        return walletRegistrationSetupError(
          'invalid_body',
          'ECDSA registration requires an exact runtime policy scope',
        );
      }
      const chainTargets = ecdsaBranch
        ? registrationPreparedContextEcdsaChainTargets(preparedContext.preparedContext)
        : null;
      if (ecdsaBranch && !chainTargets) {
        return walletRegistrationSetupError('invalid_body', 'ECDSA chain targets are required');
      }

      const nowMs = Date.now();
      const expiresAtMs = walletRegistrationSetupExpiresAtMs(nowMs);
      const { registrationCeremonyId, registrationPreparationId } = walletRegistrationSetupIds();

      /* ECDSA preparation only, and only when the plan has an ECDSA branch.
         An Ed25519-only plan has nothing to prepare before the proof: its Yao
         admission binds the authority scope, so respond derives it. */
      const ecdsaPrepared =
        ecdsaBranch && chainTargets && runtimePolicyScope
          ? await buildD1EvmFamilyEcdsaRegistrationPrepare({
              registrationPurpose: 'wallet_registration',
              registrationCeremonyId,
              registrationPreparationId:
                registrationPreparationIdFromString(registrationPreparationId),
              walletId: wallet.walletId,
              signingRootId,
              signingRootVersion,
              chainTargets,
              participantIds: [...ecdsaBranch.participantIds],
              strictRegistration: this.ecdsaStrictRegistration,
              runtimePolicyScope,
            })
          : null;
      if (ecdsaPrepared && !ecdsaPrepared.ok) {
        return walletRegistrationSetupError(ecdsaPrepared.code, ecdsaPrepared.message);
      }

      const storedBranches: StoredWalletRegistrationSignerBranch[] = [];
      if (ecdsaPrepared?.ok && ecdsaBranch)
        storedBranches.push(
          buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
            branchKey: ecdsaBranch.branchKey,
            ecdsa: {
              kind: ecdsaPrepared.ecdsa.kind,
              chainTargets: ecdsaPrepared.ecdsa.chainTargets,
              prepare: ecdsaPrepared.ecdsa.prepare,
              strictRegistration: ecdsaPrepared.ecdsa.strictRegistration,
              strictRegistrationBindingJson: routerAbEcdsaStrictRegistrationFactsBindingJson(
                ecdsaPrepared.ecdsa.strictRegistration,
              ),
            },
          }),
        );

      const ceremony: StoredWalletRegistrationCeremony = {
        registrationCeremonyId,
        intent,
        digestB64u,
        signerPlan: branches.value.plan,
        preparedContext: preparedContext.preparedContext,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        signingRootId,
        signingRootVersion,
        ...(input.expectedOrigin ? { expectedOrigin: input.expectedOrigin } : {}),
        expiresAtMs,
        /* The proof does not exist yet; respond binds it. */
        authorityState: { kind: 'awaiting_proof', authMethod: normalized.authMethod },
        signerState: { kind: 'signer_set_registration', branches: storedBranches },
      };
      /* The one canonical D1 write. */
      const ceremonyWriteTiming = startD1RegistrationRouteTiming('registrationCeremonyInsertMs');
      try {
        await this.getRegistrationCeremonyIntentStore().putCeremony(ceremony);
      } finally {
        finishD1RegistrationRouteTiming(timing, ceremonyWriteTiming);
      }

      const { signedSetup } = await buildWalletRegistrationSetupSignature({
        signer: input.signer,
        ceremony,
        expectedOrigin: input.expectedOrigin,
      });
      finishD1RegistrationRouteTiming(timing, total);
      const success = {
        ok: true as const,
        registrationCeremonyId,
        walletId: String(wallet.walletId),
        registrationIntentDigestB64u: digestB64u,
        intent,
        signedSetup,
      };
      /* The plan decides the shape. An Ed25519-only setup carries no `ecdsa`
         member at all, so a client cannot read one that was never prepared. */
      if (!ecdsaPrepared?.ok || !ecdsaBranch) {
        return { ...success, kind: 'near_ed25519' };
      }
      return {
        ...success,
        kind: nearEd25519Branch ? 'near_ed25519_and_evm_family_ecdsa' : 'evm_family_ecdsa',
        ecdsa: {
          kind: ecdsaPrepared.ecdsa.kind,
          chainTargets: ecdsaPrepared.ecdsa.chainTargets,
          prepare: ecdsaPrepared.ecdsa.prepare,
          strictRegistration: ecdsaPrepared.ecdsa.strictRegistration,
        },
      };
    } catch (error: unknown) {
      return walletRegistrationSetupError(
        'internal',
        errorMessage(error) || 'Failed to set up wallet registration',
      );
    }
  }

  async respondWalletRegistration(
    input: WalletRegistrationRespondInput,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationRespondResponseV2> {
    const serverTiming: Array<readonly [string, number]> = [];
    const totalStartedAtMs = Date.now();
    const mark = (name: string, startedAtMs: number): void => {
      serverTiming.push([name, Math.max(0, Date.now() - startedAtMs)]);
    };
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const loadStartedAtMs = Date.now();
      const snapshot = await store.getCeremonySnapshot(input.registrationCeremonyId);
      mark('respond_d1_load', loadStartedAtMs);
      if (!snapshot) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      const ceremony = snapshot.ceremony;
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const expectedOrigin = toOptionalTrimmedString(ceremony.expectedOrigin) || '';
      const setupDigestB64u = await computeWalletRegistrationSetupDigestB64u({
        registrationCeremonyId: ceremony.registrationCeremonyId,
        intent: ceremony.intent,
        intentDigestB64u: ceremony.digestB64u,
        orgId: ceremony.orgId,
        signingRootId: toOptionalTrimmedString(ceremony.signingRootId) || '',
        signingRootVersion: toOptionalTrimmedString(ceremony.signingRootVersion) || '',
        expectedOrigin,
      });
      const verifiedSetup = await verifySignedWalletRegistrationSetup(
        input.verifier,
        input.signedSetup,
        {
          registrationCeremonyId: ceremony.registrationCeremonyId,
          setupDigestB64u,
          nowMs: Date.now(),
        },
      );
      if (!verifiedSetup.ok) {
        return { ok: false, code: verifiedSetup.code, message: verifiedSetup.message };
      }
      const registrationBearerToken = toOptionalTrimmedString(input.signedSetup);
      if (!registrationBearerToken) {
        return { ok: false, code: 'invalid_body', message: 'signedSetup is required' };
      }

      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      const planNearEd25519 = registrationSignerBranchesFromPlan(ceremony.signerPlan).nearEd25519;
      if (!ecdsaBranch && !planNearEd25519) {
        return { ok: false, code: 'invalid_state', message: 'a signer branch is required' };
      }
      /* The client's declared plan must match what the ceremony recorded. */
      const ceremonyIsEd25519Only = !ecdsaBranch && Boolean(planNearEd25519);
      if ((input.planKind === 'near_ed25519') !== ceremonyIsEd25519Only) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'respond signer plan does not match the registration ceremony',
        };
      }
      if (!ecdsaBranch && planNearEd25519) {
        /* Ed25519-only: no ECDSA leg to run. Verify the proof, establish the
           authority, and hand back the authority-bound Yao admission as
           deferred work — the client starts the computation and calls activate
           without awaiting it. */
        return await this.respondEd25519OnlyRegistration({
          snapshot,
          ceremony,
          branch: planNearEd25519,
          authorityInput: input.authority,
          registrationBearerToken,
          expectedOrigin,
          ...(input.userAgent ? { userAgent: input.userAgent } : {}),
        });
      }
      if (!ecdsaBranch) {
        return { ok: false, code: 'invalid_state', message: 'ECDSA branch is required' };
      }
      if (!input.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'strict Router A/B ECDSA registration request is required',
        };
      }
      const strictRegistration = input.ecdsa.strictRegistration;
      const strictRegistrationBindingJson =
        routerAbEcdsaStrictRegistrationRequestBindingJson(strictRegistration);
      /* Exact replay: the terminal branch already holds this request's result,
         so return the stored bundles rather than calling the Router again. */
      if (ecdsaBranch.kind === 'evm_family_ecdsa_pending_activation') {
        if (
          alphabetizeStringify(ecdsaBranch.registrationRequest) !==
          alphabetizeStringify(strictRegistration)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA registration replay changed the exact request',
          };
        }
        const replayAuthority = await this.verifyRespondReplayAuthority({
          ceremony,
          authorityInput: input.authority,
          expectedOrigin,
          ...(input.userAgent ? { userAgent: input.userAgent } : {}),
        });
        if (!replayAuthority.ok) {
          return { ok: false, code: replayAuthority.code, message: replayAuthority.message };
        }
        return walletRegistrationRespondResult({
          ceremony,
          strictResult: ecdsaBranch.publicResponse,
          ed25519: storedRespondEd25519DeferredWork(ceremony.signerState),
        });
      }
      if (ecdsaBranch.kind !== 'evm_family_ecdsa_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA registration branch is not respondable',
        };
      }
      if (ecdsaBranch.strictRegistrationBindingJson !== strictRegistrationBindingJson) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA registration request does not match the admitted ceremony facts',
        };
      }

      /* The proof. Everything below this line is authority-bound. */
      const authorityStartedAtMs = Date.now();
      const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
        orgId: ceremony.orgId,
        authority: input.authority,
        expectedDigestB64u: ceremony.digestB64u,
        expectedOrigin,
        intent: ceremony.intent,
        verificationOperationId: ceremony.registrationCeremonyId,
        verificationReceiptExpiresAtMs: ceremony.expiresAtMs,
        ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      });
      mark('respond_authority_verify', authorityStartedAtMs);
      if (!verifiedAuthority.ok) {
        return { ok: false, code: verifiedAuthority.code, message: verifiedAuthority.message };
      }
      const authority = verifiedAuthority.authority;
      if (authority.walletId !== ceremony.intent.walletId) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration authority walletId does not match the ceremony',
        };
      }

      /* Both Router calls are authority-bound and independent of each other. */
      const routerStartedAtMs = Date.now();
      const nearEd25519Branch = registrationSignerBranchesFromPlan(ceremony.signerPlan).nearEd25519;
      const [strictResult, ed25519Admission] = await Promise.all([
        this.ecdsaStrictRegistration.register({
          request: strictRegistration,
          requestPolicy: {
            policyVersion: WALLET_REGISTRATION_ROUTER_POLICY_VERSION,
            requestDigestB64u: input.ecdsa.requestDigestB64u,
          },
          authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
          traceContext,
          onServerTiming: (header) => mergeRouterServerTiming(serverTiming, header),
          onHeaderPresence: (presence) =>
            serverTiming.push([`ecdsa_role_timing_${presence.serverTiming}`, 1]),
        }),
        this.admitRespondEd25519Branch({
          ceremony,
          branch: nearEd25519Branch,
          authority,
          registrationBearerToken,
        }),
      ]);
      mark('respond_router', routerStartedAtMs);
      if (!strictResult.ok) {
        if (!strictResult.retryable) {
          await store.cancelTerminalCeremony({
            registrationCeremonyId: ceremony.registrationCeremonyId,
            walletId: ceremony.intent.walletId,
          });
        }
        return { ok: false, code: strictResult.code, message: strictResult.message };
      }
      if (!ed25519Admission.ok) {
        return { ok: false, code: ed25519Admission.code, message: ed25519Admission.message };
      }

      let nextSignerState = replaceStoredWalletRegistrationSignerBranch({
        state: ceremony.signerState,
        replacement: {
          kind: 'evm_family_ecdsa_pending_activation',
          branchKey: ecdsaBranch.branchKey,
          derivationKind: ecdsaBranch.derivationKind,
          chainTargets: ecdsaBranch.chainTargets,
          prepare: ecdsaBranch.prepare,
          strictRegistration: ecdsaBranch.strictRegistration,
          strictRegistrationBindingJson: ecdsaBranch.strictRegistrationBindingJson,
          registrationRequest: strictRegistration,
          pendingActivation: strictResult.value.pendingActivation,
          publicResponse: strictResult.value.publicResponse,
        },
      });
      if (ed25519Admission.branch) {
        nextSignerState = {
          kind: 'signer_set_registration',
          branches: [ed25519Admission.branch, ...nextSignerState.branches],
        };
      }
      /* One write: the authority transition and the branch result commit
         together, so a ceremony can never be verified without its result or
         hold a result without a verified authority. */
      const next: StoredWalletRegistrationCeremony = {
        ...ceremony,
        authorityState: { kind: 'verified', authority },
        signerState: nextSignerState,
      };
      const commitStartedAtMs = Date.now();
      try {
        await store.commitEcdsaClaim({ expected: snapshot, next });
      } catch (error: unknown) {
        /* Lost the CAS to a concurrent duplicate. Converge on the stored
           terminal state when it is the same request, otherwise surface. */
        const reconciled = await store.getCeremony(input.registrationCeremonyId);
        const reconciledBranch =
          reconciled?.signerState.kind === 'signer_set_registration'
            ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciled.signerState)
            : null;
        if (
          !reconciled ||
          reconciledBranch?.kind !== 'evm_family_ecdsa_pending_activation' ||
          alphabetizeStringify(reconciledBranch.registrationRequest) !==
            alphabetizeStringify(strictRegistration)
        ) {
          throw error;
        }
        mark('respond_d1_commit', commitStartedAtMs);
        mark('respond_total', totalStartedAtMs);
        return walletRegistrationRespondResult({
          ceremony: reconciled,
          strictResult: reconciledBranch.publicResponse,
          ed25519: storedRespondEd25519DeferredWork(reconciled.signerState),
        });
      }
      mark('respond_d1_commit', commitStartedAtMs);
      mark('respond_total', totalStartedAtMs);
      return walletRegistrationRespondResult({
        ceremony: next,
        strictResult: strictResult.value.publicResponse,
        ed25519: ed25519Admission.deferred,
      });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet registration ceremony',
      };
    }
  }

  /**
   * The Ed25519 commit core, extracted so deferred provisioning reaches it
   * without going through the standalone finalize wrapper. The operation row
   * owns idempotency here, so the commit keeps no replay cache of its own.
   */
  private async readRegistrationOwnerProofContext(
    registrationCeremonyId: string,
  ): Promise<RegistrationOwnerProofContext | null> {
    const ceremony =
      await this.getRegistrationCeremonyIntentStore().getCeremony(registrationCeremonyId);
    if (!ceremony) return null;
    const expectedOrigin = toOptionalTrimmedString(ceremony.expectedOrigin);
    const runtimePolicyScope = registrationPreparedContextRuntimePolicyScope(
      ceremony.preparedContext,
    );
    if (!expectedOrigin || !runtimePolicyScope) {
      throw new Error('Registration is missing its session origin or runtime policy scope');
    }
    return {
      expectedOrigin,
      runtimePolicyScope,
      expiresAtMs: ceremony.expiresAtMs,
    };
  }

  private async registrationOwnerProof(input: {
    readonly registrationCeremonyId: string;
    readonly authMethod: WalletRegistrationFinalizeAuthMethod;
    readonly authority: WalletAuthAuthority;
  }): Promise<Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>> {
    const context = await this.readRegistrationOwnerProofContext(input.registrationCeremonyId);
    if (!context) throw new Error('Registration owner proof context is unavailable');
    return await buildRegistrationOwnerProof({
      ...input,
      tenantId: this.authorizationTenantId,
      expectedOrigin: context.expectedOrigin,
      expiresAtMs: Math.min(context.expiresAtMs, Date.now() + DEFAULT_WALLET_SESSION_TTL_MS),
    });
  }

  private async prepareNearProvisioningOperation(
    registrationCeremonyId: string,
    allocated: D1WalletRegistrationOperationPreparedV1 = allocateWalletRegistrationOperationPrepared(),
  ): Promise<D1WalletRegistrationOperationPreparedV1> {
    const ceremony =
      await this.getRegistrationCeremonyIntentStore().getCeremony(registrationCeremonyId);
    if (!ceremony) return allocated;
    const authority = verifiedRegistrationCeremonyAuthority(ceremony);
    if (!authority) return allocated;
    const persisted = await this.walletAuthMethods.readActiveRegistrationIdentity(authority);
    if (!persisted) return allocated;
    return {
      ...allocated,
      walletAuthorityId: persisted.walletAuthorityId,
      walletAuthMethodId: persisted.walletAuthMethodId,
    };
  }

  private async commitDeferredEd25519Signer(
    args: {
      readonly input: WalletRegistrationNearProvisioningInput;
    },
    prepared: D1WalletRegistrationOperationPreparedV1,
  ): Promise<WalletRegistrationNearProvisioningFinalizeResponse> {
    /* The ceremony is still present for a fresh side-effect execution. Keep
       this read inside the operation callback so an exact replay can return
       its stored response after finalize has tombstoned the ceremony. */
    const ownerProofContext = await this.readRegistrationOwnerProofContext(
      args.input.registrationCeremonyId,
    );
    if (!ownerProofContext) {
      throw new Error('Registration owner proof context is unavailable');
    }
    const ceremony = await this.getRegistrationCeremonyIntentStore().getCeremony(
      args.input.registrationCeremonyId,
    );
    const registrationAuthority = ceremony
      ? verifiedRegistrationCeremonyAuthority(ceremony)
      : null;
    if (!registrationAuthority) {
      throw new Error('Registration authority is unavailable before finalize');
    }
    const effectivePrepared = await this.prepareNearProvisioningOperation(
      args.input.registrationCeremonyId,
      prepared,
    );
    const committed = await this.executeWalletRegistrationFinalize(
      {
        kind: 'near_ed25519',
        registrationCeremonyId: args.input.registrationCeremonyId,
        idempotencyKey: args.input.idempotencyKey,
        ed25519: args.input.ed25519,
        emailOtpEnrollment: args.input.emailOtpEnrollment,
        walletCustodyCommit: args.input.walletCustodyCommit,
      } as FinalizeWalletRegistrationInput,
      effectivePrepared,
    );
    const finalized = committed.ok
      ? committed
      : throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(committed);
    if (!finalized.ok || finalized.kind !== 'near_ed25519') return finalized;
    const proof = await buildRegistrationOwnerProof({
      registrationCeremonyId: args.input.registrationCeremonyId,
      authMethod: finalized.authMethod,
      authority: finalized.authority,
      tenantId: this.authorizationTenantId,
      expectedOrigin: ownerProofContext.expectedOrigin,
      expiresAtMs: ownerProofContext.expiresAtMs,
    });
    const registrationEstablishedSession =
      await this.issueOrReuseRegistrationEstablishedEd25519Session({
        registrationCeremonyId: args.input.registrationCeremonyId,
        authority: finalized.authority,
        registrationAuthority,
        walletAuthMethodId: effectivePrepared.walletAuthMethodId,
        expiresAtMs: Date.now() + DEFAULT_WALLET_SESSION_TTL_MS,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        publicResult: finalized.ed25519,
        keyManifestDigestB64u: finalized.custodyKeyManifestDigestB64u,
        proof,
      });
    return { ...finalized, registrationEstablishedSession };
  }

  /**
   * Deferred NEAR provisioning. Verifies the signed setup, then reuses the
   * existing deferred Ed25519 commit — the same path lazy-Yao 4+5 built — so
   * signer installation and the implicit-account projection keep one
   * implementation across both plans.
   *
   * A retryable failure leaves the pending wallet intact: the wallet must not
   * be destroyed because its signer ceremony needs another attempt.
   */
  async completeWalletRegistrationNearProvisioning(
    input: WalletRegistrationNearProvisioningInput,
  ): Promise<WalletRegistrationNearProvisioningResponseV2> {
    try {
      const verified = await verifyWalletRegistrationSetupClaims(
        input.verifier,
        input.signedSetup,
        {
          registrationCeremonyId: input.registrationCeremonyId,
          nowMs: Date.now(),
        },
      );
      if (!verified.ok) {
        return { ok: false, code: verified.code, message: verified.message };
      }
      /* Its own operation row. This is a separate effect from activate with
         its own idempotency key, so it claims, records uncertainty, and
         replays through one record of its own rather than borrowing the
         legacy finalize journal and replay cache. */
      const requestFingerprint = base64UrlEncode(
        await sha256BytesUtf8(
          alphabetizeStringify({
            version: 'wallet_registration_near_provisioning_digest_v1',
            registrationCeremonyId: input.registrationCeremonyId,
            setupDigestB64u: verified.claims.setupDigestB64u,
            idempotencyKey: input.idempotencyKey,
            ed25519: input.ed25519,
            emailOtpEnrollment: input.emailOtpEnrollment,
          }),
        ),
      );
      const run = await runRouterAbEd25519YaoRegistrationSideEffectV1(
        this.nearProvisioningSideEffects,
        {
          kind: 'prepared_resumable',
          operation: 'near_provisioning',
          key: `near-provisioning:${input.registrationCeremonyId}:${input.idempotencyKey}`,
          requestFingerprint,
          resumeAfterMs: D1_WALLET_REGISTRATION_OPERATION_RESUME_AFTER_MS,
          nowMs: Date.now,
          prepare: async () =>
            await this.prepareNearProvisioningOperation(input.registrationCeremonyId),
          derivePreparedArtifactFingerprint: async (prepared) =>
            base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared))),
          execute: this.commitDeferredEd25519Signer.bind(this, { input }),
        },
      );
      switch (run.kind) {
        case 'executed':
        case 'exact_replay':
          break;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'NEAR provisioning idempotency key was reused for a different request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'NEAR provisioning is already in progress; retry later',
          };
        case 'uncertain':
          return {
            ok: false,
            code: 'internal',
            message: run.message || 'Failed to reconcile NEAR provisioning',
            nearProvisioning: { status: 'near_failed_retryable' },
          };
        default:
          return { ok: false, code: 'internal', message: 'unsupported provisioning outcome' };
      }
      const committed = run.value;
      if (!committed.ok) {
        return {
          ok: false,
          code: committed.code,
          message: committed.message,
          nearProvisioning: { status: 'near_failed_retryable' },
        };
      }
      if (committed.kind !== 'near_ed25519') {
        return {
          ok: false,
          code: 'internal',
          message: 'NEAR provisioning committed a different signer branch',
        };
      }
      if (!isWalletRegistrationNearProvisioningSuccess(committed)) {
        return {
          ok: false,
          code: 'internal',
          message: 'NEAR provisioning did not establish a Wallet Session',
          nearProvisioning: { status: 'near_failed_retryable' },
        };
      }
      return {
        ...committed,
        nearProvisioning: { status: 'near_ready' },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to complete NEAR provisioning',
        nearProvisioning: { status: 'near_failed_retryable' },
      };
    }
  }

  /**
   * Persists the Ed25519-only wallet in `near_pending`: wallet, profile, and
   * authentication state, and no signer record — the signer does not exist
   * until deferred Yao produces it.
   *
   * The terminal response carries no signer, resolved account, or key
   * identity, because none of those are known yet. Reporting them would be
   * fabricating readiness.
   */
  private async commitEd25519PendingWallet(input: {
    readonly ceremony: StoredWalletRegistrationCeremony;
    readonly authority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly enrollment: Pick<FinalizeWalletRegistrationInput, 'emailOtpEnrollment'>;
  }): Promise<WalletRegistrationActivateResponseV2> {
    const now = Date.now();
    const ceremony = input.ceremony;
    const authority = input.authority;
    const wallet = buildD1WalletRecord({ walletId: ceremony.intent.walletId, now });
    const walletAuthAuthority = registrationWalletAuthAuthority({
      authority,
      walletAuthMethodId: input.walletAuthMethodId,
    });
    switch (authority.kind) {
      case 'passkey':
        await this.walletRegistrationCommitStore.commit({
          kind: 'passkey_wallet_registration_commit_v1',
          wallet,
          /* Deliberately empty: the sole signer arrives with Yao. */
          walletSigners: [],
          authority,
          now,
        });
        break;
      case 'email_otp': {
        /* Email OTP enrollment is recovery-critical and belongs to the same
           transaction as the wallet — it is an authentication concern, not an
           ECDSA one, so a pending Ed25519-only wallet enrolls exactly as a
           signable one does. */
        const enrollment =
          await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
            authority,
            request: input.enrollment,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          });
        if (!enrollment.ok) return enrollment;
        if (!enrollment.persistence) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Email OTP registration is missing enrollment persistence state',
          };
        }
        await this.walletRegistrationCommitStore.commit({
          kind: 'email_otp_wallet_registration_commit_v1',
          wallet,
          walletSigners: [],
          authority,
          emailOtp: this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationCommitPlan(
            enrollment.persistence,
          ),
          now,
        });
        break;
      }
    }
    const authMethod = walletRegistrationFinalizeAuthMethodFromAuthority(authority);
    const base = {
      ok: true as const,
      kind: 'near_ed25519' as const,
      walletId: ceremony.intent.walletId,
      authority: walletAuthAuthority,
      authMethod,
      nearProvisioning: { status: 'near_pending' as const },
    };
    if (authMethod.kind === 'passkey') {
      if (!isPasskeyWalletAuthAuthority(walletAuthAuthority)) {
        return {
          ok: false,
          code: 'internal',
          message: 'Passkey registration returned a different authority',
        };
      }
      return {
        ...base,
        rpId: finalizePasskeyRpId(authority),
      } as WalletRegistrationActivateResponseV2;
    }
    if (!isEmailOtpWalletAuthAuthority(walletAuthAuthority)) {
      return {
        ok: false,
        code: 'internal',
        message: 'Email OTP registration returned a different authority',
      };
    }
    return base as WalletRegistrationActivateResponseV2;
  }

  /**
   * Ed25519-only respond. The wallet's sole signer is Yao, and that is
   * deliberately not a reason to block: the admission is returned as deferred
   * work exactly as on a mixed plan, and the wallet lives in `near_pending`
   * until the computation completes.
   */
  /**
   * Respond replay stays authority-bound.
   *
   * `signedSetup` is client-carried, so possession of it must never recover a
   * stored respond result. Re-verifying the proof is necessary but not
   * sufficient: registration *mints* the credential, so a fresh passkey over
   * the same challenge would verify. The replayed proof must therefore resolve
   * to the same authority that admitted the stored result.
   */
  private async verifyRespondReplayAuthority(input: {
    readonly ceremony: StoredWalletRegistrationCeremony;
    readonly authorityInput: WalletRegistrationAuthorityInput;
    readonly expectedOrigin: string;
    readonly userAgent?: string;
  }): Promise<
    { readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    const ceremony = input.ceremony;
    const storedAuthority = verifiedRegistrationCeremonyAuthority(ceremony);
    if (!storedAuthority) {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'registration ceremony has no verified authority to replay',
      };
    }
    const verified = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
      orgId: ceremony.orgId,
      authority: input.authorityInput,
      expectedDigestB64u: ceremony.digestB64u,
      expectedOrigin: input.expectedOrigin,
      intent: ceremony.intent,
      verificationOperationId: ceremony.registrationCeremonyId,
      verificationReceiptExpiresAtMs: ceremony.expiresAtMs,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    });
    if (!verified.ok) return { ok: false, code: verified.code, message: verified.message };
    if (!storedRegistrationAuthoritiesMatch(storedAuthority, verified.authority)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'registration respond replay presented a different authority',
      };
    }
    return { ok: true };
  }

  private async respondEd25519OnlyRegistration(input: {
    readonly snapshot: {
      readonly ceremony: StoredWalletRegistrationCeremony;
      readonly version: number;
    };
    readonly ceremony: StoredWalletRegistrationCeremony;
    readonly branch: RegistrationNearEd25519SignerPlan;
    readonly authorityInput: WalletRegistrationAuthorityInput;
    readonly registrationBearerToken: string;
    readonly expectedOrigin: string;
    readonly userAgent?: string;
  }): Promise<WalletRegistrationRespondResponseV2> {
    const ceremony = input.ceremony;
    /* Exact replay: the admission already exists, so return it rather than
       admitting a second time. */
    const stored = storedRespondEd25519DeferredWork(ceremony.signerState);
    if (stored) {
      const replayAuthority = await this.verifyRespondReplayAuthority({
        ceremony,
        authorityInput: input.authorityInput,
        expectedOrigin: input.expectedOrigin,
        ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      });
      if (!replayAuthority.ok) {
        return { ok: false, code: replayAuthority.code, message: replayAuthority.message };
      }
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        kind: 'near_ed25519',
        ed25519: stored,
      };
    }
    const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
      orgId: ceremony.orgId,
      authority: input.authorityInput,
      expectedDigestB64u: ceremony.digestB64u,
      expectedOrigin: input.expectedOrigin,
      intent: ceremony.intent,
      verificationOperationId: ceremony.registrationCeremonyId,
      verificationReceiptExpiresAtMs: ceremony.expiresAtMs,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    });
    if (!verifiedAuthority.ok) {
      return { ok: false, code: verifiedAuthority.code, message: verifiedAuthority.message };
    }
    const authority = verifiedAuthority.authority;
    if (authority.walletId !== ceremony.intent.walletId) {
      return {
        ok: false,
        code: 'scope_mismatch',
        message: 'registration authority walletId does not match the ceremony',
      };
    }
    const admitted = await this.admitRespondEd25519Branch({
      ceremony,
      branch: input.branch,
      authority,
      registrationBearerToken: input.registrationBearerToken,
    });
    if (!admitted.ok) return { ok: false, code: admitted.code, message: admitted.message };
    if (!admitted.branch || !admitted.deferred) {
      return { ok: false, code: 'internal', message: 'Ed25519 admission produced no branch' };
    }
    /* One write, as on the ECDSA path: the verified authority and the admitted
       branch commit together. */
    await this.getRegistrationCeremonyIntentStore().commitEcdsaClaim({
      expected: input.snapshot,
      next: {
        ...ceremony,
        authorityState: { kind: 'verified', authority },
        signerState: { kind: 'signer_set_registration', branches: [admitted.branch] },
      },
    });
    return {
      ok: true,
      registrationCeremonyId: ceremony.registrationCeremonyId,
      kind: 'near_ed25519',
      ed25519: admitted.deferred,
    };
  }

  /**
   * Derives the authority-bound Yao admission now that the proof is verified.
   * Both auth methods take this path — the scope comes from the verified
   * authority, so Email OTP's `providerUserId` is established rather than
   * assumed.
   */
  private async admitRespondEd25519Branch(input: {
    readonly ceremony: StoredWalletRegistrationCeremony;
    readonly branch: RegistrationNearEd25519SignerPlan | null;
    readonly authority: StoredRegistrationAuthority;
    readonly registrationBearerToken: string;
  }): Promise<
    | {
        readonly ok: true;
        readonly branch: StoredWalletRegistrationSignerBranch | null;
        readonly deferred: RespondEd25519DeferredWorkV2 | null;
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    if (!input.branch) return { ok: true, branch: null, deferred: null };
    const yaoRuntime = this.getEd25519YaoProductRegistration();
    if (!yaoRuntime) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'Ed25519 Yao product registration is not configured',
      };
    }
    const admissionRequest = await buildRouterAbEd25519YaoProductAdmissionRequestV1({
      registrationCeremonyId: input.ceremony.registrationCeremonyId,
      walletId: input.ceremony.intent.walletId,
      signingRootId: toOptionalTrimmedString(input.ceremony.signingRootId) || '',
      signingRootVersion: toOptionalTrimmedString(input.ceremony.signingRootVersion) || '',
      authorityScope: registrationEd25519AuthorityScopeFromAuthority(input.authority),
      branch: input.branch,
      signingWorkerId: yaoRuntime.signingWorkerId,
      materialActivation: createRouterAbEd25519YaoMaterialActivationRefV1({
        walletId: input.ceremony.intent.walletId,
        signingWorkerId: yaoRuntime.signingWorkerId,
      }),
    });
    const admitted = await yaoRuntime.bindAndAdmitVerifiedRegistration({
      kind: 'verified_registration_intent',
      registrationIntentGrant: registrationIntentGrantFromString(input.registrationBearerToken),
      intent: input.ceremony.intent,
      admissionRequest,
      expiresAtMs: input.ceremony.expiresAtMs,
    });
    if (!admitted.ok) return { ok: false, code: admitted.code, message: admitted.message };
    return {
      ok: true,
      branch: buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
        branchKey: input.branch.branchKey,
        admissionRequest,
        admissionReceipt: admitted.value,
      }),
      deferred: { status: 'deferred', admissionRequest, admissionReceipt: admitted.value },
    };
  }

  /**
   * Refactor 94C. `/wallets/register/activate` — activation and finalization
   * as one irreversible step behind one Gateway operation row.
   *
   * Previously activation and finalization were separate requests with
   * separate idempotency: activation claimed and CAS'd the ceremony branch,
   * then finalize opened its own side-effect journal *and* maintained a second
   * replay cache. Three records guarding one irreversible commit, each with
   * its own failure window.
   *
   * Here the operation row is the only one. Its claim is the activation claim,
   * its completion record holds the exact terminal response bytes, and an
   * identical retry returns those bytes without repeating any custody effect.
   * A conflicting fingerprint is refused before execution; an ambiguous
   * outcome after the custody call stays `uncertain` rather than being
   * guessed either way.
   */
  async activateWalletRegistration(
    input: WalletRegistrationActivateInput,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationActivateResponseV2> {
    try {
      /* No ceremony read here, deliberately. A successful activation deletes
         the ceremony, so an exact replay has to be answerable from the
         operation row alone; reading the ceremony first would turn every
         retry-after-success into a spurious `not_found`. The Gateway-signed
         claims carry everything needed to reach the row. */
      const verifiedSetup = await verifyWalletRegistrationSetupClaims(
        input.verifier,
        input.signedSetup,
        { registrationCeremonyId: input.registrationCeremonyId, nowMs: Date.now() },
      );
      if (!verifiedSetup.ok) {
        return { ok: false, code: verifiedSetup.code, message: verifiedSetup.message };
      }
      const claims = verifiedSetup.claims;
      const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
      if (!idempotencyKey) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration activate idempotencyKey is required',
        };
      }

      /* Activate's own canonical digest, over activate's own bytes. */
      const activateDigestB64u = base64UrlEncode(
        await sha256BytesUtf8(
          alphabetizeStringify({
            version: 'wallet_registration_activate_digest_v1',
            registrationCeremonyId: claims.registrationCeremonyId,
            setupDigestB64u: claims.setupDigestB64u,
            idempotencyKey,
            ecdsa: input.ecdsa,
            ...(input.emailOtpEnrollment ? { emailOtpEnrollment: input.emailOtpEnrollment } : {}),
          }),
        ),
      );
      const run = await runRouterAbEd25519YaoRegistrationSideEffectV1(this.activateSideEffects, {
        kind: 'prepared_resumable',
        operation: 'registration_activate',
        key: `registration-activate:${claims.registrationCeremonyId}:${idempotencyKey}`,
        requestFingerprint: activateDigestB64u,
        resumeAfterMs: D1_WALLET_REGISTRATION_OPERATION_RESUME_AFTER_MS,
        nowMs: Date.now,
        prepare: async () => allocateWalletRegistrationOperationPrepared(),
        derivePreparedArtifactFingerprint: async (prepared) =>
          base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared))),
        execute: this.executeWalletRegistrationActivation.bind(this, {
          registrationCeremonyId: claims.registrationCeremonyId,
          idempotencyKey,
          input,
          traceContext,
        }),
      });
      switch (run.kind) {
        case 'executed':
        case 'exact_replay':
          /* Exact terminal bytes, byte-identical across retries. */
          return run.value;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'registration activate idempotency key was reused for a different request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'registration activation is already in progress; retry later',
          };
        case 'uncertain':
          /* Ambiguous after the custody call: never guessed either way. */
          return {
            ok: false,
            code: 'internal',
            message: run.message || 'Failed to reconcile wallet registration activation',
          };
        default:
          return {
            ok: false,
            code: 'internal',
            message: 'registration activation returned an unsupported outcome',
          };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate wallet registration',
      };
    }
  }

  /**
   * Router/SigningWorker activation followed by the blocking finalize
   * persistence, as one unit inside the operation row. The commit is told the
   * operation row owns idempotency, so it maintains no replay cache of its own.
   */
  private async executeWalletRegistrationActivation(
    context: {
      readonly registrationCeremonyId: string;
      readonly idempotencyKey: string;
      readonly input: WalletRegistrationActivateInput;
      readonly traceContext?: RouterAbTraceContextV1;
    },
    prepared: D1WalletRegistrationOperationPreparedV1,
  ): Promise<WalletRegistrationActivateResponseV2> {
    /* Fresh execution only — the ceremony still exists here. Activation
       persists wallet identity, so the proof must already be bound. */
    const ceremony = await this.getRegistrationCeremonyIntentStore().getCeremony(
      context.registrationCeremonyId,
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
    }
    const ceremonyAuthority = verifiedRegistrationCeremonyAuthority(ceremony);
    if (!ceremonyAuthority) {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'registration ceremony has not verified its authority proof',
      };
    }
    /* Ed25519-only: no ECDSA Router activation, and no Yao output required.
       The wallet is created pending so it exists before its sole signer does —
       which is what lets the client overlap the Yao computation with this
       call instead of serializing behind it. */
    if (!registrationSignerBranchesFromPlan(ceremony.signerPlan).evmFamilyEcdsa) {
      return await this.commitEd25519PendingWallet({
        ceremony,
        authority: ceremonyAuthority,
        walletAuthMethodId: prepared.walletAuthMethodId,
        enrollment: {
          ...(context.input.emailOtpEnrollment
            ? { emailOtpEnrollment: context.input.emailOtpEnrollment as never }
            : {}),
        },
      });
    }
    if (!context.input.ecdsa) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'browser-verified clientActivation is required for this signer plan',
      };
    }
    const activated = await this.activateWalletRegistrationEcdsa(
      {
        registrationCeremonyId: context.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_v1',
          activationCorrelationId: context.input.ecdsa.activationCorrelationId,
          activationRequestDigestB64u: context.input.ecdsa.activationRequestDigestB64u,
          publicFacts: context.input.ecdsa.clientActivation,
        },
      } as ActivateWalletRegistrationEcdsaInput,
      context.traceContext,
      context.idempotencyKey,
    );
    if (!activated.ok) {
      /* Pre-effect failures stay retryable; the boundary re-raises them so the
         claim is released rather than recorded as a terminal outcome. */
      return throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(activated);
    }
    /* The handle the activation just produced. The old two-request flow had
       the client echo this back so a mismatched pair could be caught; in one
       request there is no pair, so the commit is bound to the handle it was
       produced with. */
    const keyHandle = activated.ecdsa.bootstrap?.keyHandle;
    if (!keyHandle) {
      return {
        ok: false,
        code: 'internal',
        message: 'ECDSA activation completed without a key handle to commit',
      };
    }
    const commit = await this.executeWalletRegistrationFinalize(
      {
        kind: 'evm_family_ecdsa',
        registrationCeremonyId: context.registrationCeremonyId,
        idempotencyKey: context.idempotencyKey,
        ecdsa: { expectedKeyHandles: [keyHandle] as const },
        ...(context.input.emailOtpEnrollment
          ? { emailOtpEnrollment: context.input.emailOtpEnrollment }
          : {}),
        ...(context.input.walletCustodyCommit !== undefined
          ? { walletCustodyCommit: context.input.walletCustodyCommit }
          : {}),
      } as FinalizeWalletRegistrationInput,
      prepared,
    );
    if (!commit.ok) return throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(commit);
    /* The terminal response is both legs merged. Activation produced the
       receipt and the derivation bootstrap; the commit produced the wallet
       keys. Returning only the commit half would drop what the client needs
       to bring the wallet online — the whole point of folding the legs is
       that one response carries the result of both. */
    if (commit.kind !== 'evm_family_ecdsa') {
      return {
        ok: false,
        code: 'internal',
        message: 'registration activation committed a non-ECDSA branch',
      };
    }
    const runtimePolicyScope = registrationPreparedContextRuntimePolicyScope(
      ceremony.preparedContext,
    );
    if (!runtimePolicyScope) {
      throw new Error('ECDSA registration is missing runtime policy scope');
    }
    const registrationEstablishedSession = await this.issueRegistrationEstablishedEcdsaSession({
      registrationCeremonyId: context.registrationCeremonyId,
      authority: commit.authority,
      registrationAuthority: ceremonyAuthority,
      walletAuthMethodId: prepared.walletAuthMethodId,
      expiresAtMs: activated.ecdsa.bootstrap.expiresAtMs,
      remainingUses: activated.ecdsa.bootstrap.remainingUses,
      bootstrap: activated.ecdsa.bootstrap,
      runtimePolicyScope,
      keyManifestDigestB64u: commit.custodyKeyManifestDigestB64u,
      proof: await this.registrationOwnerProof({
        registrationCeremonyId: context.registrationCeremonyId,
        authMethod: commit.authMethod,
        authority: commit.authority,
      }),
    });
    return {
      ok: true,
      kind: 'evm_family_ecdsa',
      walletId: commit.walletId,
      authority: commit.authority,
      authMethod: commit.authMethod,
      ...(commit.rpId ? { rpId: commit.rpId } : {}),
      /* Carried from the commit leg: this response *is* the client's only view
         of what happened to its custody run. */
      ...(commit.walletCustody ? { walletCustody: commit.walletCustody } : {}),
      ecdsa: {
        ...commit.ecdsa,
        activation: activated.ecdsa.activation,
        bootstrap: activated.ecdsa.bootstrap,
      },
      registrationEstablishedSession,
    } as WalletRegistrationActivateResponseV2;
  }

  async activateWalletRegistrationEcdsa(
    request: ActivateWalletRegistrationEcdsaInput,
    traceContext: RouterAbTraceContextV1 | undefined,
    /**
     * The activate operation-row identity (idempotency key). The activation
     * claim is owned by exactly one operation: a concurrent activate with a
     * different key must not adopt the claim and re-run Router custody.
     */
    activationOwner: string,
  ): Promise<WalletRegistrationEcdsaActivationResponse> {
    /* Same contract as respondWalletRegistrationEcdsaDerivation: stripped into
       a Server-Timing header at the route, never serialized to the wire. */
    const serverTiming: Array<readonly [string, number]> = [];
    const totalStartedAtMs = Date.now();
    const markServerTiming = (name: string, startedAtMs: number): void => {
      serverTiming.push([name, Math.max(0, Date.now() - startedAtMs)]);
    };
    const withServerTiming = <T extends { ok: true }>(response: T): T => {
      markServerTiming('ecdsa_activate_total', totalStartedAtMs);
      return { ...response, gatewayServerTiming: serverTiming };
    };
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const claimStartedAtMs = Date.now();
      const owner = toOptionalTrimmedString(activationOwner);
      if (!owner) {
        return {
          ok: false,
          code: 'internal',
          message: 'ECDSA activation requires an owning operation identity',
        };
      }
      let claimed = await store.claimEcdsaActivation({
        registrationCeremonyId: request.registrationCeremonyId,
        publicFacts: request.ecdsa.publicFacts,
        activationRequestDigestB64u: request.ecdsa.activationRequestDigestB64u,
        activationOwner: owner,
      });
      markServerTiming('ecdsa_activate_d1_claim', claimStartedAtMs);
      if (!claimed) {
        const reconcileStartedAtMs = Date.now();
        const existing = await store.getCeremonySnapshot(request.registrationCeremonyId);
        markServerTiming('ecdsa_activate_reconcile', reconcileStartedAtMs);
        if (!existing) {
          return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
        }
        const ceremony = existing.ceremony;
        if (
          !registrationCeremonyWalletsMatch({ ceremony }) ||
          ceremony.signerState.kind !== 'signer_set_registration'
        ) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration state is required',
          };
        }
        const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (ecdsaBranch?.kind === 'evm_family_ecdsa_activated') {
          if (
            alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts)
          ) {
            return {
              ok: false,
              code: 'scope_mismatch',
              message: 'ECDSA activation replay changed the verified client facts',
            };
          }
          if (ecdsaBranch.activationOwner !== owner) {
            return {
              ok: false,
              code: 'conflict',
              message: 'ECDSA activation belongs to another activate operation',
            };
          }
          return withServerTiming({
            ok: true,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            ecdsa: {
              kind: 'router_ab_ecdsa_registration_activated_v1',
              activation: ecdsaBranch.activation,
              bootstrap: ecdsaBranch.bootstrap,
            },
          } as const);
        }
        if (ecdsaBranch?.kind !== 'evm_family_ecdsa_activation_claimed') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA registration activation is not claimable',
          };
        }
        if (
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts) ||
          ecdsaBranch.activationRequestDigestB64u !== request.ecdsa.activationRequestDigestB64u
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation claim belongs to different verified client facts',
          };
        }
        /* One activation owner per ceremony. Matching facts are not enough:
           a concurrent activate under a different idempotency key would
           otherwise adopt this claim and run Router custody a second time.
           Only the claiming operation — crash-resume or takeover of the SAME
           operation row — may resume. Legacy claims with no recorded owner
           deny adoption rather than allow it. */
        if (ecdsaBranch.activationOwner !== owner) {
          return {
            ok: false,
            code: 'conflict',
            message: 'ECDSA activation claim belongs to another activate operation',
          };
        }
        claimed = existing;
      }
      const ceremony = claimed.ceremony;
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        throw new Error('Claimed ECDSA activation ceremony has an invalid signer state');
      }
      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      if (!ecdsaBranch || ecdsaBranch.kind !== 'evm_family_ecdsa_activation_claimed') {
        throw new Error('Claimed ECDSA activation branch is invalid');
      }
      const routerStartedAtMs = Date.now();
      const activated = await this.ecdsaStrictRegistration.activate({
        activationCorrelationId: request.ecdsa.activationCorrelationId,
        activationRequestDigestB64u: ecdsaBranch.activationRequestDigestB64u,
        pendingActivation: ecdsaBranch.pendingActivation,
        clientActivation: ecdsaBranch.publicFacts,
        requestPolicy: {
          policyVersion: WALLET_REGISTRATION_ROUTER_POLICY_VERSION,
          requestDigestB64u: ecdsaBranch.publicFacts.registrationRequestDigestB64u,
        },
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
        traceContext,
        onServerTiming: (header) => mergeRouterServerTiming(serverTiming, header),
        /* Presence only: a fixed metric name, never the header contents. */
        onHeaderPresence: (presence) =>
          serverTiming.push([`ecdsa_role_timing_${presence.serverTiming}`, 1]),
      });
      markServerTiming('ecdsa_activate_router', routerStartedAtMs);
      if (!activated.ok) {
        if (!activated.retryable) {
          await store.commitEcdsaClaim({
            expected: claimed,
            next: {
              ...ceremony,
              signerState: {
                kind: 'registration_failed',
                failedAtMs: Date.now(),
                failure: {
                  code: activated.code,
                  message: activated.message,
                },
              },
            },
          });
        }
        return {
          ok: false,
          code: activated.code,
          message: activated.message,
        };
      }
      try {
        const bootstrapStartedAtMs = Date.now();
        const bootstrap = await buildActivatedEcdsaFamilyBootstrap({
          branch: ecdsaBranch,
          publicFacts: ecdsaBranch.publicFacts,
          activation: activated.value,
        });
        markServerTiming('ecdsa_activate_bootstrap', bootstrapStartedAtMs);
        const activatedBranch: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch = {
          kind: 'evm_family_ecdsa_activated',
          activationOwner: ecdsaBranch.activationOwner,
          branchKey: ecdsaBranch.branchKey,
          derivationKind: ecdsaBranch.derivationKind,
          chainTargets: ecdsaBranch.chainTargets,
          prepare: ecdsaBranch.prepare,
          strictRegistration: ecdsaBranch.strictRegistration,
          strictRegistrationBindingJson: ecdsaBranch.strictRegistrationBindingJson,
          registrationRequest: ecdsaBranch.registrationRequest,
          publicFacts: ecdsaBranch.publicFacts,
          activation: activated.value,
          publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
            registrationFacts: ecdsaBranch.strictRegistration,
            registrationRequest: ecdsaBranch.registrationRequest,
            clientActivation: ecdsaBranch.publicFacts,
            activationReceipt: activated.value,
          }),
          bootstrap: {
            formatVersion: bootstrap.formatVersion,
            walletId: bootstrap.walletId,
            evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
            ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
            relayerKeyId: bootstrap.relayerKeyId,
            applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
            contextBinding32B64u: bootstrap.contextBinding32B64u,
            publicIdentity: bootstrap.publicIdentity,
            clientShareRetryCounter: bootstrap.clientShareRetryCounter,
            relayerShareRetryCounter: bootstrap.relayerShareRetryCounter,
            publicTranscriptDigest32B64u: bootstrap.publicTranscriptDigest32B64u,
            keyHandle: bootstrap.keyHandle,
            signingRootId: bootstrap.signingRootId,
            signingRootVersion: bootstrap.signingRootVersion,
            thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
            ethereumAddress: bootstrap.ethereumAddress,
            relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
            thresholdSessionId: bootstrap.thresholdSessionId,
            activationEpoch: bootstrap.activationEpoch,
            expiresAtMs: bootstrap.expiresAtMs,
            expiresAt: bootstrap.expiresAt,
            remainingUses: bootstrap.remainingUses,
            participantIds: [...exactEcdsaParticipantPair(bootstrap.participantIds)],
            routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
          },
        };
        const commitStartedAtMs = Date.now();
        try {
          await store.commitEcdsaClaim({
            expected: claimed,
            next: {
              ...ceremony,
              signerState: replaceStoredWalletRegistrationSignerBranch({
                state: ceremony.signerState,
                replacement: activatedBranch,
              }),
            },
          });
        } catch (error: unknown) {
          const reconciled = await store.getCeremony(request.registrationCeremonyId);
          const reconciledBranch =
            reconciled?.signerState.kind === 'signer_set_registration'
              ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciled.signerState)
              : null;
          if (
            reconciledBranch?.kind !== 'evm_family_ecdsa_activated' ||
            reconciledBranch.activationOwner !== activatedBranch.activationOwner ||
            alphabetizeStringify(reconciledBranch.publicFacts) !==
              alphabetizeStringify(activatedBranch.publicFacts) ||
            alphabetizeStringify(reconciledBranch.activation) !==
              alphabetizeStringify(activatedBranch.activation) ||
            alphabetizeStringify(reconciledBranch.bootstrap) !==
              alphabetizeStringify(activatedBranch.bootstrap)
          ) {
            throw error;
          }
        } finally {
          markServerTiming('ecdsa_activate_d1_commit', commitStartedAtMs);
        }
        return withServerTiming({
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activated_v1',
            activation: activated.value,
            bootstrap: activatedBranch.bootstrap,
          },
        } as const);
      } catch (error: unknown) {
        const message =
          errorMessage(error) || 'ECDSA activation could not establish normal signing';
        await store.commitEcdsaClaim({
          expected: claimed,
          next: {
            ...ceremony,
            signerState: {
              kind: 'registration_failed',
              failedAtMs: Date.now(),
              failure: {
                code: 'ecdsa_activation_terminal_failure',
                message,
              },
            },
          },
        });
        return {
          ok: false,
          code: 'ecdsa_activation_terminal_failure',
          message,
        };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate ECDSA wallet registration',
      };
    }
  }

  private async executeWalletRegistrationFinalize(
    request: FinalizeWalletRegistrationInput,
    prepared: D1WalletRegistrationOperationPreparedV1,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const finalizeTiming = createD1RegistrationRouteTimingRecorder('wallets_register_finalize');
    const totalTiming = startD1RegistrationRouteTiming('registerFinalizeTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (!idempotencyKey) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration finalize idempotencyKey is required',
        };
      }
      const requestFingerprint = await walletRegistrationFinalizeRequestFingerprint(request);
      const ceremonyLoadTiming = startD1RegistrationRouteTiming('registrationCeremonyLoadMs');
      let ceremony: Awaited<ReturnType<typeof store.getCeremony>>;
      try {
        ceremony = await store.getCeremony(request.registrationCeremonyId);
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, ceremonyLoadTiming);
      }
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
      /* Finalization persists wallet identity, so it requires the proof that
         respond binds. A ceremony still awaiting one cannot be finalized. */
      const ceremonyAuthority = verifiedRegistrationCeremonyAuthority(ceremony);
      if (!ceremonyAuthority) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'registration ceremony has not verified its authority proof',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      const requestedNearEd25519 = signerBranches.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.evmFamilyEcdsa;
      if (!requestedNearEd25519 && !requestedEvmFamilyEcdsa) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'registration signer set requires a signer branch',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const storedEcdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
        ceremony.signerState,
      );
      const sequenceFailure = finalizeSignerWorkSequenceFailure({
        request,
        hasNearEd25519: requestedNearEd25519 !== null,
        hasEvmFamilyEcdsa: requestedEvmFamilyEcdsa !== null,
        ecdsaFinalized: storedEcdsaBranch?.kind === 'evm_family_ecdsa_finalized',
      });
      if (sequenceFailure) {
        return { ok: false, ...sequenceFailure };
      }
      /* Refactor 94 Phase 4+5. Which half this call commits comes from the
         request, not from the plan: a mixed plan finalizes ECDSA first and
         Ed25519 later, so the plan alone no longer says what is being
         committed now. The sequence check above has already confirmed the
         requested half is admitted and legal at this point. */
      const finalizeEvmFamilyEcdsa =
        request.kind === 'evm_family_ecdsa' ? requestedEvmFamilyEcdsa : null;
      const finalizeNearEd25519 = request.kind === 'near_ed25519' ? requestedNearEd25519 : null;
      /* True when this ECDSA finalize is step one of two, so the ceremony must
         survive for the Ed25519 finalize to resume from. */
      const ed25519FinalizePending =
        finalizeEvmFamilyEcdsa !== null && requestedNearEd25519 !== null;
      const walletCustodyCommitPayload = walletCustodyCeremonyCommitPayloadFromWire(
        request.walletCustodyCommit,
      );
      if (!walletCustodyCommitPayload) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration finalize requires its wallet custody commit',
        };
      }
      if (walletCustodyCommitPayload.walletId !== ceremony.intent.walletId) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'wallet custody commit does not name the registered wallet',
        };
      }
      const expectedCustodyKeySet = finalizeEvmFamilyEcdsa
        ? 'evm_family_ecdsa_v1'
        : 'near_ed25519_v1';
      if (walletCustodyCommitPayload.keySet !== expectedCustodyKeySet) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'wallet custody commit does not name the finalized key set',
        };
      }
      let custodyKeyManifestDigestB64u;
      try {
        custodyKeyManifestDigestB64u = parseDigestB64u(
          walletCustodyCommitPayload.keyManifestDigestB64u,
        );
      } catch {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'wallet custody commit carries an invalid key manifest digest',
        };
      }
      let custodyClientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u | null = null;
      if (finalizeEvmFamilyEcdsa) {
        try {
          custodyClientRootPublicKey33B64u = ecdsaClientRootPublicKey33B64uFromString(
            walletCustodyCommitPayload.clientRootPublicKey33B64u ?? '',
          );
        } catch {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA custody commit carries an invalid client root public key',
          };
        }
      }
      const ecdsaWalletKeys: WalletRegistrationEcdsaWalletKey[] = [];
      let ecdsaMaterialActivation: MpcMaterialActivationRef | null = null;
      let ecdsaFinalizeState: D1RegistrationEcdsaFinalizeState = {
        kind: 'ecdsa_registration_disabled',
      };
      let activatedEcdsaBranch: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch | null = null;
      if (finalizeEvmFamilyEcdsa) {
        const ecdsaState = storedEcdsaBranch;
        if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_activated') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA family activation is required before finalize',
          };
        }
        activatedEcdsaBranch = ecdsaState;
        if (!request.ecdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA finalize requires the activated family key handle',
          };
        }
        const expectedKeyHandles = request.ecdsa.expectedKeyHandles;
        const actualKeyHandles = [ecdsaState.bootstrap.keyHandle];
        if (hasEcdsaKeyHandleSetMismatch(expectedKeyHandles, actualKeyHandles)) {
          return {
            ok: false,
            code: 'key_handle_mismatch',
            message: 'ECDSA finalize expected key handle mismatch',
          };
        }
        const ecdsaVerifyTiming = startD1RegistrationRouteTiming(
          'registrationEcdsaBootstrapVerifyMs',
        );
        let walletKeyResult: ReturnType<typeof buildD1EcdsaWalletKeysFromBootstrap>;
        try {
          walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
            bootstraps: ecdsaState.chainTargets.map((chainTarget) => ({
              chainTarget,
              bootstrap: ecdsaState.bootstrap,
            })),
            publicCapability: ecdsaState.publicCapability,
            errorContext: 'ECDSA registration finalize',
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, ecdsaVerifyTiming);
        }
        if (!walletKeyResult.ok) return walletKeyResult;
        ecdsaWalletKeys.push(...walletKeyResult.walletKeys);
        ecdsaMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
          ecdsaState.activation.ecdsa_activation.material_activation,
        );
        ecdsaFinalizeState = {
          kind: 'ecdsa_registration_responded',
          state: ecdsaState,
        };
      } else if (storedEcdsaBranch?.kind === 'evm_family_ecdsa_finalized') {
        const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
          bootstraps: storedEcdsaBranch.chainTargets.map((chainTarget) => ({
            chainTarget,
            bootstrap: storedEcdsaBranch.bootstrap,
          })),
          publicCapability: storedEcdsaBranch.publicCapability,
          errorContext: 'ECDSA registration final Ed25519 finalize',
        });
        if (!walletKeyResult.ok) return walletKeyResult;
        ecdsaWalletKeys.push(...walletKeyResult.walletKeys);
        ecdsaMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
          storedEcdsaBranch.activation.ecdsa_activation.material_activation,
        );
      }

      const now = Date.now();
      const emailOtpEnrollmentTiming = startD1RegistrationRouteTiming(
        'registrationEmailOtpEnrollmentPlanMs',
      );
      let emailOtpEnrollment: Awaited<
        ReturnType<typeof this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize>
      >;
      try {
        emailOtpEnrollment =
          await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
            authority: ceremonyAuthority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          });
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, emailOtpEnrollmentTiming);
      }
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;

      const walletAuthAuthority = registrationWalletAuthAuthority({
        authority: ceremonyAuthority,
        walletAuthMethodId: prepared.walletAuthMethodId,
      });
      let ed25519PublicResult: WalletRegistrationEd25519YaoPublicResult | null = null;
      let resolvedNearAccount: ResolvedRegistrationNearAccount | null = null;
      let ed25519SignerRecord: WalletEd25519SignerRecord | null = null;
      let ed25519MaterialActivation: MpcMaterialActivationRef | null = null;
      let ed25519RegisteredPublicKeyB64u: string | null = null;
      let ed25519CapabilityInstallation: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 | null =
        null;
      if (finalizeNearEd25519) {
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao product registration is not configured',
          };
        }
        const storedYao = findStoredWalletRegistrationNearEd25519YaoBranch(ceremony.signerState);
        if (!storedYao || !request.ed25519) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'authorized Ed25519 Yao registration is required before finalize',
          };
        }
        if (ceremony.preparedContext.runtimePolicy.kind !== 'runtime_policy_scope') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 Yao wallet session requires a runtime policy scope',
          };
        }
        const runtimePolicyScope = ceremony.preparedContext.runtimePolicy.scope;
        const activationReference = request.ed25519.activationReference;
        /* Bind before consume. The consume below is a first-writer CAS that
           permanently records its consumer, so a foreign activation reference
           must be rejected before it can be burned — otherwise this ceremony's
           signedSetup could consume another ceremony's activation and brick
           its provisioning. The Yao lifecycle is keyed by the ceremony id
           (routerAbEd25519YaoProductRegistration mints lifecycle_id from
           registrationCeremonyId), so ownership is checkable without I/O. */
        if (activationReference.lifecycle_id !== ceremony.registrationCeremonyId) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'Ed25519 activation reference does not belong to this registration ceremony',
          };
        }
        const consumed = await yaoRuntime.consumeActivated({
          reference: {
            lifecycleId: activationReference.lifecycle_id,
            sessionId: activationReference.session_id,
          },
          consumerBinding: requestFingerprint,
        });
        if (!consumed.ok) {
          return { ok: false, code: consumed.code, message: consumed.message };
        }
        if (
          alphabetizeStringify(consumed.activation.admissionRequest) !==
          alphabetizeStringify(storedYao.admissionRequest)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'activated Ed25519 Yao registration does not match the stored signer branch',
          };
        }
        const firstParticipantId = finalizeNearEd25519.participantIds[0];
        const secondParticipantId = finalizeNearEd25519.participantIds[1];
        if (
          finalizeNearEd25519.participantIds.length !== 2 ||
          firstParticipantId === undefined ||
          secondParticipantId === undefined
        ) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 Yao registration requires exactly two participants',
          };
        }
        const participantIds: readonly [number, number] = [firstParticipantId, secondParticipantId];
        const publicKeyBytes = consumed.activation.result.public_receipt.registered_public_key;
        ed25519RegisteredPublicKeyB64u = base64UrlEncode(Uint8Array.from(publicKeyBytes));
        if (walletCustodyCommitPayload.registeredPublicKeyB64u !== ed25519RegisteredPublicKeyB64u) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'NEAR custody commit changed the activated public key',
          };
        }
        const publicKey = ed25519NearPublicKeyFromBytes(publicKeyBytes);
        let nearAccountId = implicitNearAccountIdFromEd25519PublicKeyBytes(publicKeyBytes);
        let sponsoredTransactionHash: string | undefined;
        const sponsoredAccountId = sponsoredNamedRegistrationAccountId(
          finalizeNearEd25519.accountProvisioning,
        );
        if (sponsoredAccountId) {
          const created = await this.createSponsoredNamedNearAccount({
            accountId: sponsoredAccountId,
            publicKey,
            // Scoped to the activation session so a retry of this exact
            // registration replays its prepared transaction rather than
            // creating a second sponsored account.
            idempotencyKey: bytesToUnprefixedHex(
              Uint8Array.from(consumed.activation.result.binding.session_id),
            ),
          });
          switch (created.kind) {
            case 'rejected':
              return {
                ok: false,
                code: 'account_creation_failed',
                message: created.message,
              };
            case 'retryable':
              return {
                ok: false,
                code: 'account_creation_retryable',
                message: created.message,
                retryAfterMs: created.retryAfterMs,
              };
            case 'created':
              nearAccountId = created.accountId;
              sponsoredTransactionHash = created.transactionHash;
              break;
            default:
              return assertNeverSponsoredNamedNearAccountCreationResult(created);
          }
        }
        const resolved = resolvedRegistrationNearAccount({
          accountProvisioning: finalizeNearEd25519.accountProvisioning,
          nearAccountId,
          nearEd25519SigningKeyId:
            consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
          ...(sponsoredTransactionHash ? { sponsoredTransactionHash } : {}),
        });
        if (!resolved.ok) return resolved;
        resolvedNearAccount = resolved.value;
        ed25519CapabilityInstallation = {
          kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
          activeCapabilityBinding: consumed.activation.result.binding.session_id,
          nearAccountId,
          registrationAdmissionRequest: consumed.activation.admissionRequest,
          registrationAdmissionReceipt: consumed.activation.admissionReceipt,
          registrationResult: consumed.activation.result,
          runtimePolicyScope,
        };
        const activeYaoCapability = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(
          ed25519CapabilityInstallation,
        );
        if (!activeYaoCapability.ok) {
          return {
            ok: false,
            code: activeYaoCapability.code,
            message: activeYaoCapability.message,
          };
        }
        const activatedEd25519PublicResult: WalletRegistrationEd25519YaoPublicResult = {
          signerSlot: finalizeNearEd25519.signerSlot,
          nearAccountId,
          nearEd25519SigningKeyId:
            consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
          publicKey,
          relayerKeyId: yaoRuntime.signingWorkerId,
          keyVersion: finalizeNearEd25519.keyVersion,
          recoveryExportCapable: true,
          participantIds,
          thresholdSessionId: consumed.activation.admissionRequest.scope.threshold_session_id,
          runtimePolicyScope,
          routerAbNormalSigning: {
            kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
            signingWorkerId: yaoRuntime.signingWorkerId,
          },
        };
        ed25519PublicResult = activatedEd25519PublicResult;
        ed25519MaterialActivation = routerAbMpcMaterialActivationRefFromWire(
          consumed.activation.admissionRequest.scope.material_activation,
        );
        ed25519SignerRecord = buildYaoEd25519WalletSignerRecord({
          walletId: ceremony.intent.walletId,
          nearAccountId,
          nearEd25519SigningKeyId: activatedEd25519PublicResult.nearEd25519SigningKeyId,
          thresholdSessionId: consumed.activation.admissionRequest.scope.threshold_session_id,
          signerSlot: finalizeNearEd25519.signerSlot,
          publicKey,
          signingWorkerId: yaoRuntime.signingWorkerId,
          keyVersion: finalizeNearEd25519.keyVersion,
          participantIds,
          signingRootId: ceremony.preparedContext.signingRootId,
          signingRootVersion: ceremony.preparedContext.signingRootVersion,
          runtimePolicyScope,
          activeYaoCapability: activeYaoCapability.record,
          custodyKeyManifestDigestB64u,
          now,
        });
      }

      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        now,
      });
      if (activatedEcdsaBranch && !custodyClientRootPublicKey33B64u) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA registration is missing its custody client root public key',
        };
      }
      const walletSigners: WalletSignerRecord[] = [];
      if (activatedEcdsaBranch) {
        const custodyClientRootPublicKey = custodyClientRootPublicKey33B64u;
        if (!custodyClientRootPublicKey) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA registration is missing its custody client root public key',
          };
        }
        walletSigners.push(
          ...buildD1WalletEcdsaSignerRecords({
            walletId: ceremony.intent.walletId,
            walletKeys: ecdsaWalletKeys,
            activationReceipt: activatedEcdsaBranch.activation,
            runtimePolicyScope: activatedEcdsaBranch.prepare.runtimePolicyScope,
            custodyKeyManifestDigestB64u,
            custodyClientRootPublicKey33B64u: custodyClientRootPublicKey,
            now,
          }),
        );
      }
      if (ed25519SignerRecord) walletSigners.push(ed25519SignerRecord);
      const foundingAuthorityAlreadyCommitted =
        finalizeNearEd25519 !== null && storedEcdsaBranch?.kind === 'evm_family_ecdsa_finalized';
      const foundingCommitComplete =
        /* The first leg of a mixed plan is already an established ECDSA
           wallet. Its session is issued immediately, so the authority and
           method must be committed in the same batch before that issuance. */
        finalizeEvmFamilyEcdsa !== null ||
        (finalizeNearEd25519 !== null && requestedEvmFamilyEcdsa === null);
      let foundingAuthorityRecords: FoundingAuthorityRecords | null = null;
      if (foundingCommitComplete && !foundingAuthorityAlreadyCommitted) {
        const ecdsaWalletKey = ecdsaWalletKeys[0];
        if (ed25519SignerRecord && ed25519MaterialActivation && ed25519RegisteredPublicKeyB64u) {
          if (!ecdsaWalletKey || !ecdsaMaterialActivation) {
            if (requestedEvmFamilyEcdsa !== null) {
              return {
                ok: false,
                code: 'invalid_state',
                message: 'Complete registration is missing ECDSA founding facts',
              };
            }
            foundingAuthorityRecords = await buildFoundingAuthorityRecords({
              authority: ceremonyAuthority,
              walletId: ceremony.intent.walletId,
              prepared,
              signerFacts: {
                kind: 'ed25519',
                keyFamilies: ['ed25519'],
                ed25519: {
                  signer: ed25519SignerRecord,
                  registeredPublicKeyB64u: ed25519RegisteredPublicKeyB64u,
                  materialActivation: ed25519MaterialActivation,
                },
              },
              now,
            });
          } else {
            foundingAuthorityRecords = await buildFoundingAuthorityRecords({
              authority: ceremonyAuthority,
              walletId: ceremony.intent.walletId,
              prepared,
              signerFacts: {
                kind: 'both',
                keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
                ed25519: {
                  signer: ed25519SignerRecord,
                  registeredPublicKeyB64u: ed25519RegisteredPublicKeyB64u,
                  materialActivation: ed25519MaterialActivation,
                },
                ecdsa: {
                  walletKey: requireSingleFoundingEcdsaWalletKey(ecdsaWalletKeys),
                  materialActivation: ecdsaMaterialActivation,
                },
              },
              now,
            });
          }
        } else if (ecdsaWalletKey && ecdsaMaterialActivation) {
          foundingAuthorityRecords = await buildFoundingAuthorityRecords({
            authority: ceremonyAuthority,
            walletId: ceremony.intent.walletId,
            prepared,
            signerFacts: {
              kind: 'ecdsa_secp256k1',
              keyFamilies: ['ecdsa_secp256k1'],
              ecdsa: {
                walletKey: requireSingleFoundingEcdsaWalletKey(ecdsaWalletKeys),
                materialActivation: ecdsaMaterialActivation,
              },
            },
            now,
          });
        } else {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Complete registration is missing founding signer facts',
          };
        }
      }
      const persistenceTiming = startD1RegistrationRouteTiming('relayPersistenceMs');
      try {
        switch (ceremonyAuthority.kind) {
          case 'passkey':
            if (emailOtpEnrollment.persistence) {
              return {
                ok: false,
                code: 'invalid_state',
                message: 'Passkey registration cannot persist Email OTP enrollment state',
              };
            }
            if (foundingAuthorityRecords) {
              await this.walletRegistrationCommitStore.commit({
                kind: 'passkey_wallet_registration_commit_v1',
                wallet,
                walletSigners,
                authority: ceremonyAuthority,
                foundingAuthority: foundingAuthorityRecords.authority,
                foundingAuthMethod: foundingAuthorityRecords.authMethod,
                now,
              });
            } else {
              await this.walletRegistrationCommitStore.commit({
                kind: 'passkey_wallet_registration_commit_v1',
                wallet,
                walletSigners,
                authority: ceremonyAuthority,
                now,
              });
            }
            break;
          case 'email_otp': {
            if (!emailOtpEnrollment.persistence) {
              return {
                ok: false,
                code: 'invalid_state',
                message: 'Email OTP registration is missing enrollment persistence state',
              };
            }
            const emailOtp =
              this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationCommitPlan(
                emailOtpEnrollment.persistence,
              );
            if (foundingAuthorityRecords) {
              await this.walletRegistrationCommitStore.commit({
                kind: 'email_otp_wallet_registration_commit_v1',
                wallet,
                walletSigners,
                authority: ceremonyAuthority,
                emailOtp,
                foundingAuthority: foundingAuthorityRecords.authority,
                foundingAuthMethod: foundingAuthorityRecords.authMethod,
                now,
              });
            } else {
              await this.walletRegistrationCommitStore.commit({
                kind: 'email_otp_wallet_registration_commit_v1',
                wallet,
                walletSigners,
                authority: ceremonyAuthority,
                emailOtp,
                now,
              });
            }
            break;
          }
        }
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, persistenceTiming);
      }
      if (ed25519CapabilityInstallation) {
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao product registration is not configured',
          };
        }
        const installed = await yaoRuntime.installRegistrationFinalizeCapability(
          ed25519CapabilityInstallation,
        );
        if (!installed.ok) {
          return {
            ok: false,
            code: installed.code,
            message: installed.message,
          };
        }
      }
      /* The custody commit, and the only place it happens.

         Both legs reach here — activate's ECDSA branch and the deferred NEAR
         provisioning — so one seam covers both, and it is the *only* correct
         one: an Ed25519-only wallet's activate returns `near_pending` with no
         Yao result yet, so its custody can only be sealed on the deferred leg.
         Wiring this into activate alone would silently never fire for exactly
         the wallets the first client slice creates.

         It runs after the registration commit above, deliberately. The wallet
         must exist before an envelope claims to be its custody, and the
         wallet-equality check the gate performs is only meaningful against a
         registration this leg actually committed. */
      const walletCustody = await commitRegistrationCustody({
        payload: walletCustodyCommitPayload,
        verifiedWalletId: ceremony.intent.walletId,
        /* The verified authority, never the payload: the factor is what the
           envelope's AAD binds the seed to, so a payload-supplied one could
           address this wallet's custody to a credential its owner does not
           control. */
        verifiedAuthority: walletAuthAuthority,
        /* Email OTP names the enrollment, which is not on the authority — it
           is on the material this same leg just finalized. */
        ...(emailOtpEnrollment.persistence
          ? {
              verifiedEmailOtpEnrollment: {
                enrollmentId: emailOtpEnrollment.persistence.enrollment.enrollmentId,
                enrollmentSealKeyVersion:
                  emailOtpEnrollment.persistence.enrollment.enrollmentSealKeyVersion,
              },
            }
          : {}),
        nowMs: now,
        store: this.walletCustodyCommitStore,
      });
      if (walletCustody.status === 'rejected') {
        /* Reported, not thrown — the registration is already committed. Logged
           because a rejection is a wallet whose seed is not yet recoverable,
           and the client's retry is the only thing that fixes it. */
        console.warn('[wallet-registration] custody commit rejected', {
          registrationCeremonyId: ceremony.registrationCeremonyId,
          reason: walletCustody.reason,
        });
      }
      const custodyField = walletCustody.status === 'not_requested' ? {} : { walletCustody };
      const authMethod = walletRegistrationFinalizeAuthMethodFromAuthority(ceremonyAuthority);
      let response: WalletRegistrationFinalizeSuccess;
      if (ed25519PublicResult && finalizeNearEd25519 && resolvedNearAccount) {
        const authorityScope =
          thresholdEd25519AuthorityScopeFromWalletAuthAuthority(walletAuthAuthority);
        response =
          authMethod.kind === 'passkey'
            ? {
                ok: true,
                kind: 'near_ed25519',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                rpId: finalizePasskeyRpId(ceremonyAuthority),
                authMethod,
                ...custodyField,
                custodyKeyManifestDigestB64u,
                authorityScope,
                accountProvisioning: finalizeNearEd25519.accountProvisioning,
                resolvedAccount: resolvedNearAccount,
                ed25519: ed25519PublicResult,
              }
            : {
                ok: true,
                kind: 'near_ed25519',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                authMethod,
                ...custodyField,
                custodyKeyManifestDigestB64u,
                authorityScope,
                accountProvisioning: finalizeNearEd25519.accountProvisioning,
                resolvedAccount: resolvedNearAccount,
                ed25519: ed25519PublicResult,
              };
      } else {
        response =
          authMethod.kind === 'passkey'
            ? {
                ok: true,
                kind: 'evm_family_ecdsa',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                rpId: finalizePasskeyRpId(ceremonyAuthority),
                authMethod,
                ...custodyField,
                custodyKeyManifestDigestB64u,
                ecdsa: { walletKeys: ecdsaWalletKeys },
              }
            : {
                ok: true,
                kind: 'evm_family_ecdsa',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                authMethod,
                ...custodyField,
                custodyKeyManifestDigestB64u,
                ecdsa: { walletKeys: ecdsaWalletKeys },
              };
      }
      /* Refactor 94 Phase 4+5. On a mixed plan this is step one of two: mark
         the ECDSA branch finalized and keep the ceremony, which is what the
         Ed25519 finalize resumes from. Deleting here would strand it. */
      if (ed25519FinalizePending) {
        if (!activatedEcdsaBranch) {
          return {
            ok: false,
            code: 'internal',
            message: 'ECDSA finalize completed without an activated branch to advance',
          };
        }
        await store.updateCeremony({
          expected: ceremony,
          next: {
            ...ceremony,
            signerState: replaceStoredWalletRegistrationSignerBranch({
              state: ceremony.signerState,
              replacement: buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch({
                activated: activatedEcdsaBranch,
                finalizedAtMs: now,
              }),
            }),
          },
        });
        finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
        return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
      }
      /* The commit above is irreversible, so a tombstone failure must not fail
         the response — but it must not be silent either. `false` means the row
         was already gone (a replayed finalize), which is benign; a throw means
         D1 refused the delete and the ceremony survives until its TTL. The
         activation owner binding keeps a surviving ceremony from re-running
         custody, so the residue is a stale row, not a second wallet. */
      try {
        await store.deleteCeremony(ceremony.registrationCeremonyId);
      } catch (error: unknown) {
        console.warn('[wallet-registration] ceremony tombstone delete failed after commit', {
          registrationCeremonyId: ceremony.registrationCeremonyId,
          message: errorMessage(error),
        });
      }
      finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
      return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet registration ceremony',
      };
    }
  }
}
