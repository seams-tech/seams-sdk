import {
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  type AddSignerIntentV1,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { alphabetizeStringify } from '@shared/utils/digests';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerEcdsaActivationRequest,
  WalletAddSignerEcdsaActivationResponse,
  WalletAddSignerEcdsaDerivationRespondRequest,
  WalletAddSignerEcdsaDerivationRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
} from '../../core/registrationContracts';
import { registrationPreparationIdFromString } from '../../core/registrationContracts';
import type { D1WalletStore } from '../../core/d1WalletStore';
import type { RouterAbNormalSigningRuntime } from '../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type {
  StoredEd25519YaoAddSignerActivation,
  StoredEcdsaAddSignerActivated,
  StoredWalletAddSignerCeremony,
  StoredWalletAddSignerFinalizeRequest,
  StoredWalletAddSignerSignerState,
} from '../../core/RegistrationCeremonyStore';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  normalizeThresholdEcdsaChainTargets,
  parseD1RuntimePolicyScope,
  parseWalletIdForIntent,
} from './d1RegistrationCeremonyRecords';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import {
  buildRouterAbEd25519YaoAddSignerAdmissionRequestV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../routerAbEd25519YaoProductRegistration';
import { buildRouterAbEd25519YaoRegistrationCapabilityRecordV1 } from '../routerAbEd25519YaoRecovery';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
  implicitNearAccountIdFromEd25519PublicKeyBytes,
} from './d1Ed25519YaoWalletSigner';
import {
  buildRouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  routerAbEcdsaStrictRegistrationRequestMatchesFacts,
  type RouterAbEcdsaStrictRegistrationPort,
} from '../routerAbEcdsaStrictRegistration';
import {
  buildActivatedEcdsaFamilyBootstrap,
  ecdsaStrictRegistrationAuthority,
  exactEcdsaParticipantPair,
} from './d1WalletRegistrationService';

type StartWalletAddSignerInput = WalletAddSignerStartRequest;
type RespondWalletAddSignerDerivationInput = WalletAddSignerEcdsaDerivationRespondRequest;
type ActivateWalletAddSignerEcdsaInput = WalletAddSignerEcdsaActivationRequest;
type FinalizeWalletAddSignerInput = WalletAddSignerFinalizeRequest;

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type RouterAbNormalSigningRuntimeProvider = () => RouterAbNormalSigningRuntime | null;
type WalletStoreProvider = () => D1WalletStore;
type Ed25519YaoProductRegistrationProvider =
  () => RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;

type Ed25519AddSignerIntent = AddSignerIntentV1 & {
  readonly signerSelection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>;
};

const ADD_SIGNER_CEREMONY_TTL_MS = 10 * 60_000;
const ADD_SIGNER_REPLAY_TTL_MS = 10 * 60_000;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function resolveEd25519AddSignerParticipantIds(
  selection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>,
): readonly [number, number] | null {
  const participantIds = selection.ed25519.participantIds;
  const firstParticipantId = participantIds[0];
  const secondParticipantId = participantIds[1];
  if (
    participantIds.length !== 2 ||
    firstParticipantId === undefined ||
    secondParticipantId === undefined ||
    !Number.isSafeInteger(firstParticipantId) ||
    !Number.isSafeInteger(secondParticipantId) ||
    firstParticipantId <= 0 ||
    secondParticipantId <= 0 ||
    firstParticipantId === secondParticipantId
  ) {
    return null;
  }
  return [firstParticipantId, secondParticipantId];
}

async function cleanupFinalizedAddSignerCeremony(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly addSignerCeremonyId: string;
}): Promise<void> {
  try {
    await input.store.takeAddSignerCeremony(input.addSignerCeremonyId);
  } catch {
    // The replay record remains authoritative until its TTL expires.
  }
}

function finalizeRequestsMatch(
  left: StoredWalletAddSignerFinalizeRequest,
  right: StoredWalletAddSignerFinalizeRequest,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function normalizeWalletAddSignerFinalizeRequest(
  request: FinalizeWalletAddSignerInput,
  idempotencyKey: string,
): StoredWalletAddSignerFinalizeRequest {
  if (request.kind === 'near_ed25519') {
    return {
      kind: 'near_ed25519',
      addSignerCeremonyId: request.addSignerCeremonyId,
      idempotencyKey,
      activationReference: {
        lifecycleId: request.ed25519.activationReference.lifecycle_id,
        sessionId: request.ed25519.activationReference.session_id,
      },
    };
  }
  const expectedKeyHandle = toOptionalTrimmedString(request.ecdsa.expectedKeyHandles[0]);
  if (!expectedKeyHandle) throw new Error('one exact ECDSA key handle is required');
  return {
    kind: 'evm_family_ecdsa',
    addSignerCeremonyId: request.addSignerCeremonyId,
    idempotencyKey,
    expectedKeyHandles: [expectedKeyHandle],
  };
}

function updateAddSignerCeremonyState(input: {
  readonly ceremony: StoredWalletAddSignerCeremony;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly signerState: StoredWalletAddSignerSignerState;
}): StoredWalletAddSignerCeremony {
  return {
    addSignerCeremonyId: input.ceremony.addSignerCeremonyId,
    intent: input.ceremony.intent,
    digestB64u: input.ceremony.digestB64u,
    orgId: input.ceremony.orgId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    expiresAtMs: input.ceremony.expiresAtMs,
    auth: input.ceremony.auth,
    signerState: input.signerState,
  };
}

function bootstrapWithProvisionedSession(input: {
  readonly bootstrap: StoredEcdsaAddSignerActivated['bootstrap'];
  readonly provisioned: {
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly participantIds: readonly number[];
  };
}): StoredEcdsaAddSignerActivated['bootstrap'] {
  return {
    formatVersion: input.bootstrap.formatVersion,
    walletId: input.bootstrap.walletId,
    evmFamilySigningKeySlotId: input.bootstrap.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: input.bootstrap.ecdsaThresholdKeyId,
    relayerKeyId: input.bootstrap.relayerKeyId,
    applicationBindingDigestB64u: input.bootstrap.applicationBindingDigestB64u,
    contextBinding32B64u: input.bootstrap.contextBinding32B64u,
    publicIdentity: input.bootstrap.publicIdentity,
    clientShareRetryCounter: input.bootstrap.clientShareRetryCounter,
    relayerShareRetryCounter: input.bootstrap.relayerShareRetryCounter,
    publicTranscriptDigest32B64u: input.bootstrap.publicTranscriptDigest32B64u,
    keyHandle: input.bootstrap.keyHandle,
    signingRootId: input.bootstrap.signingRootId,
    signingRootVersion: input.bootstrap.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: input.bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: input.bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: input.bootstrap.relayerVerifyingShareB64u,
    thresholdSessionId: input.bootstrap.thresholdSessionId,
    signingGrantId: input.bootstrap.signingGrantId,
    expiresAtMs: input.provisioned.expiresAtMs,
    expiresAt: new Date(input.provisioned.expiresAtMs).toISOString(),
    remainingUses: input.provisioned.remainingUses,
    participantIds: [...input.provisioned.participantIds],
  };
}

export class CloudflareD1WalletAddSignerService {
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
  private readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
  private readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
    readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
    readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getEd25519YaoProductRegistration = input.getEd25519YaoProductRegistration;
    this.getRouterAbNormalSigningRuntime = input.getRouterAbNormalSigningRuntime;
    this.ecdsaStrictRegistration = input.ecdsaStrictRegistration;
    this.getWalletStore = input.getWalletStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async getWalletAddSignerRuntimePolicyScope(
    addSignerCeremonyId: string,
  ): Promise<NonNullable<ReturnType<typeof parseD1RuntimePolicyScope>> | null> {
    const store = this.getRegistrationCeremonyIntentStore();
    if (!store) return null;
    const ceremony = await store.getAddSignerCeremony(addSignerCeremonyId);
    if (!ceremony) return null;
    return parseD1RuntimePolicyScope(ceremony.intent.runtimePolicyScope) ?? null;
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
      if (
        intentPreview.intent.signerSelection.mode === 'ed25519' &&
        request.auth.kind !== 'webauthn_assertion'
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Ed25519 Yao add-signer requires a fresh WebAuthn assertion',
        };
      }
      const storedAuth = await this.walletAuthMethods.resolveAddSignerExistingAuth({
        auth: request.auth,
        walletId,
        intent: intentPreview.intent,
        nowMs: Date.now(),
      });
      if (!storedAuth.ok) return storedAuth;
      const walletStore = this.getWalletStore();
      const wallet = await walletStore.getWallet({ walletId });
      if (!wallet) {
        return {
          ok: false,
          code: 'not_found',
          message: 'wallet not found',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(intentPreview.intent.runtimePolicyScope);
      if (!runtimePolicyScope) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer requires a runtime policy scope',
        };
      }
      if (intentPreview.intent.signerSelection.mode === 'ed25519') {
        const selection = intentPreview.intent.signerSelection.ed25519;
        if (selection.mode !== 'create_implicit_near_account') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Ed25519 Yao add-signer requires implicit NEAR account creation',
          };
        }
        const participantIds = resolveEd25519AddSignerParticipantIds(
          intentPreview.intent.signerSelection,
        );
        if (!participantIds) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Ed25519 Yao add-signer requires two distinct positive participants',
          };
        }
        const occupied = await walletStore.getEd25519SignerBySlot({
          walletId,
          signerSlot: selection.signerSlot,
        });
        if (occupied) {
          return {
            ok: false,
            code: 'signer_conflict',
            message: 'Ed25519 signer slot is already occupied',
          };
        }
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
        if (!yaoRuntime || !normalSigningRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao add-signer is not configured on this server',
          };
        }
      }
      const storedIntent = await store.takeAddSignerIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      const selection = storedIntent.intent.signerSelection;
      const signingRootId = storedIntent.signingRootId || deriveSigningRootId(runtimePolicyScope);
      const signingRootVersion =
        toOptionalTrimmedString(storedIntent.signingRootVersion) ||
        runtimePolicyScope.signingRootVersion;
      const addSignerCeremonyId = `wasc_${secureRandomBase64Url(24)}`;
      const expiresAtMs = Math.min(
        storedIntent.expiresAtMs,
        Date.now() + ADD_SIGNER_CEREMONY_TTL_MS,
      );
      if (selection.mode === 'ed25519') {
        if (storedAuth.auth.kind !== 'webauthn_assertion') {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'Ed25519 Yao add-signer requires a fresh WebAuthn assertion',
          };
        }
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao add-signer is not configured on this server',
          };
        }
        const ed25519Intent: Ed25519AddSignerIntent = {
          version: 'add_signer_intent_v1',
          walletId: storedIntent.intent.walletId,
          signerSelection: selection,
          runtimePolicyScope,
          nonceB64u: storedIntent.intent.nonceB64u,
        };
        const admissionRequest = await buildRouterAbEd25519YaoAddSignerAdmissionRequestV1({
          addSignerCeremonyId,
          walletId,
          signingRootId,
          signingRootVersion,
          selection,
          signingWorkerId: yaoRuntime.signingWorkerId,
        });
        const bound = await yaoRuntime.bindVerifiedIntent({
          kind: 'verified_add_signer_intent',
          addSignerIntentGrant: storedIntent.grant,
          intent: ed25519Intent,
          admissionRequest,
          expiresAtMs,
        });
        if (!bound.ok) return bound;
        await store.putAddSignerCeremony({
          addSignerCeremonyId,
          intent: ed25519Intent,
          digestB64u: storedIntent.digestB64u,
          orgId: runtimePolicyScope.orgId,
          signingRootId,
          signingRootVersion,
          expiresAtMs,
          auth: storedAuth.auth,
          signerState: {
            kind: 'near_ed25519_yao_add_signer_authorized',
            admissionRequest,
          },
        });
        return {
          ok: true,
          kind: 'near_ed25519',
          addSignerCeremonyId,
          intent: ed25519Intent,
          ed25519: { admissionRequest },
        };
      }
      const chainTargets = normalizeThresholdEcdsaChainTargets(selection.ecdsa.chainTargets);
      if (!chainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer contains an invalid chain target',
        };
      }

      const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationCeremonyId: addSignerCeremonyId,
        registrationPreparationId: registrationPreparationIdFromString(
          `regprep_${secureRandomBase64Url(24)}`,
        ),
        walletId,
        signingRootId,
        signingRootVersion,
        chainTargets,
        participantIds: [...selection.ecdsa.participantIds],
        runtimePolicyScope,
        strictRegistration: this.ecdsaStrictRegistration,
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
        expiresAtMs,
        auth: storedAuth.auth,
        signerState: {
          kind: 'ecdsa_add_signer_prepared',
          derivationKind: ecdsa.kind,
          chainTargets: ecdsa.chainTargets,
          prepare: ecdsa.prepare,
          strictRegistration: ecdsa.strictRegistration,
        },
      });
      return {
        ok: true,
        kind: 'evm_family_ecdsa',
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

  async respondWalletAddSignerEcdsaDerivation(
    request: RespondWalletAddSignerDerivationInput,
  ): Promise<WalletAddSignerEcdsaDerivationRespondResponse> {
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
      if (ceremony.signerState.kind === 'ecdsa_add_signer_pending_activation') {
        if (
          !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
            request: request.ecdsa.strictRegistration,
            facts: ceremony.signerState.strictRegistration,
          })
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA add-signer replay changed the admitted registration request',
          };
        }
        return {
          ok: true,
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: ceremony.signerState.publicResponse,
          },
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one prepared ECDSA add-signer registration is required',
        };
      }
      if (
        !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
          request: request.ecdsa.strictRegistration,
          facts: ceremony.signerState.strictRegistration,
        })
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA add-signer request does not match the admitted ceremony facts',
        };
      }
      const registered = await this.ecdsaStrictRegistration.register({
        request: request.ecdsa.strictRegistration,
        authority: ecdsaStrictRegistrationAuthority(ceremony.signerState.strictRegistration),
      });
      if (!registered.ok) {
        return {
          ok: false,
          code: registered.code,
          message: registered.message,
        };
      }
      await store.updateAddSignerCeremony(
        updateAddSignerCeremonyState({
          ceremony,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
          signerState: {
            kind: 'ecdsa_add_signer_pending_activation',
            derivationKind: ceremony.signerState.derivationKind,
            chainTargets: ceremony.signerState.chainTargets,
            prepare: ceremony.signerState.prepare,
            strictRegistration: ceremony.signerState.strictRegistration,
            registrationRequest: request.ecdsa.strictRegistration,
            pendingActivation: registered.value.pendingActivation,
            publicResponse: registered.value.publicResponse,
          },
        }),
      );
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_forwarded_v1',
          strictResult: registered.value.publicResponse,
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

  async activateWalletAddSignerEcdsa(
    request: ActivateWalletAddSignerEcdsaInput,
  ): Promise<WalletAddSignerEcdsaActivationResponse> {
    const store = this.getRegistrationCeremonyIntentStore();
    if (!store) return missingRegistrationCeremonyDoStore();
    const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
    }
    const state = ceremony.signerState;
    if (state.kind === 'ecdsa_add_signer_activated') {
      if (
        alphabetizeStringify(state.publicFacts) !==
        alphabetizeStringify(request.ecdsa.publicFacts)
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA add-signer activation replay changed the verified client facts',
        };
      }
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          activation: state.activation,
          bootstrap: state.bootstrap,
        },
      };
    }
    if (
      ceremony.intent.signerSelection.mode !== 'ecdsa' ||
      state.kind !== 'ecdsa_add_signer_pending_activation'
    ) {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'one pending ECDSA add-signer activation is required',
      };
    }
    const activated = await this.ecdsaStrictRegistration.activate({
      pendingActivation: state.pendingActivation,
      clientActivation: request.ecdsa.publicFacts,
      authority: ecdsaStrictRegistrationAuthority(state.strictRegistration),
    });
    if (!activated.ok) {
      if (!activated.retryable) await store.takeAddSignerCeremony(ceremony.addSignerCeremonyId);
      return { ok: false, code: activated.code, message: activated.message };
    }
    try {
      const bootstrap = await buildActivatedEcdsaFamilyBootstrap({
        branch: state,
        publicFacts: request.ecdsa.publicFacts,
        activation: activated.value,
      });
      const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
      if (!normalSigningRuntime) {
        throw new Error('Router A/B normal signing is not configured');
      }
      const provisioned = await normalSigningRuntime.provisionRouterAbEcdsaNormalSigningSession({
        kind: 'router_ab_ecdsa_normal_signing_session_v1',
        walletId: bootstrap.walletId,
        evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
        relayerKeyId: bootstrap.relayerKeyId,
        thresholdSessionId: bootstrap.thresholdSessionId,
        signingGrantId: bootstrap.signingGrantId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
        participantIds: exactEcdsaParticipantPair(bootstrap.participantIds),
        expiresAtMs: bootstrap.expiresAtMs,
        remainingUses: bootstrap.remainingUses,
      });
      if (!provisioned.ok) throw new Error(provisioned.message);
      const activatedState: StoredEcdsaAddSignerActivated = {
        kind: 'ecdsa_add_signer_activated',
        derivationKind: state.derivationKind,
        chainTargets: state.chainTargets,
        prepare: state.prepare,
        strictRegistration: state.strictRegistration,
        registrationRequest: state.registrationRequest,
        publicFacts: request.ecdsa.publicFacts,
        activation: activated.value,
        publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
          registrationFacts: state.strictRegistration,
          registrationRequest: state.registrationRequest,
          clientActivation: request.ecdsa.publicFacts,
          activationReceipt: activated.value,
        }),
        bootstrap: bootstrapWithProvisionedSession({ bootstrap, provisioned }),
      };
      await store.updateAddSignerCeremony(
        updateAddSignerCeremonyState({
          ceremony,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
          signerState: activatedState,
        }),
      );
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          activation: activatedState.activation,
          bootstrap: activatedState.bootstrap,
        },
      };
    } catch (error: unknown) {
      await store.takeAddSignerCeremony(ceremony.addSignerCeremonyId);
      return {
        ok: false,
        code: 'ecdsa_activation_terminal_failure',
        message: errorMessage(error) || 'ECDSA add-signer activation failed',
      };
    }
  }

  async finalizeWalletAddSigner(
    request: FinalizeWalletAddSignerInput,
  ): Promise<WalletAddSignerFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (!idempotencyKey) {
        return { ok: false, code: 'invalid_body', message: 'idempotencyKey is required' };
      }
      const finalizeRequest = normalizeWalletAddSignerFinalizeRequest(request, idempotencyKey);
      const exactReplay = await store.getAddSignerFinalizeReplay({
        addSignerCeremonyId: request.addSignerCeremonyId,
        idempotencyKey,
      });
      const replay =
        exactReplay ||
        (await store.getAddSignerFinalizeReplayForCeremony(request.addSignerCeremonyId));
      if (replay) {
        if (!finalizeRequestsMatch(replay.request, finalizeRequest)) {
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'idempotencyKey is already bound to another add-signer finalize request',
          };
        }
        await cleanupFinalizedAddSignerCeremony({
          store,
          addSignerCeremonyId: request.addSignerCeremonyId,
        });
        return replay.response;
      }
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (request.kind === 'near_ed25519') {
        if (finalizeRequest.kind !== 'near_ed25519') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'normalized Ed25519 add-signer finalize request changed branch',
          };
        }
        if (
          ceremony.intent.signerSelection.mode !== 'ed25519' ||
          ceremony.auth.kind !== 'webauthn_assertion'
        ) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'authorized WebAuthn Ed25519 Yao add-signer state is required',
          };
        }
        const runtimePolicyScope = parseD1RuntimePolicyScope(ceremony.intent.runtimePolicyScope);
        const participantIds = resolveEd25519AddSignerParticipantIds(
          ceremony.intent.signerSelection,
        );
        if (!runtimePolicyScope || !participantIds) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 Yao add-signer scope is invalid',
          };
        }
        const signingRootId = toOptionalTrimmedString(ceremony.signingRootId);
        const signingRootVersion = toOptionalTrimmedString(ceremony.signingRootVersion);
        if (
          !signingRootId ||
          signingRootId !== deriveSigningRootId(runtimePolicyScope) ||
          !signingRootVersion ||
          signingRootVersion !== runtimePolicyScope.signingRootVersion
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'Ed25519 Yao add-signer signing-root scope is invalid',
          };
        }
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
        if (!yaoRuntime || !normalSigningRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao add-signer is not configured on this server',
          };
        }
        const walletStore = this.getWalletStore();
        const wallet = await walletStore.getWallet({ walletId: ceremony.intent.walletId });
        if (!wallet) return { ok: false, code: 'not_found', message: 'wallet not found' };
        const selection = ceremony.intent.signerSelection.ed25519;
        const requestedActivationReference = finalizeRequest.activationReference;
        const currentState = ceremony.signerState;
        let activation: StoredEd25519YaoAddSignerActivation;
        if (currentState.kind === 'near_ed25519_yao_add_signer_authorized') {
          const occupied = await walletStore.getEd25519SignerBySlot({
            walletId: ceremony.intent.walletId,
            signerSlot: selection.signerSlot,
          });
          if (occupied) {
            return {
              ok: false,
              code: 'signer_conflict',
              message: 'Ed25519 signer slot is already occupied',
            };
          }
          const consumed = await yaoRuntime.consumeActivated({
            reference: requestedActivationReference,
            consumerBinding: alphabetizeStringify(finalizeRequest),
          });
          if (!consumed.ok) return consumed;
          if (
            alphabetizeStringify(consumed.activation.admissionRequest) !==
            alphabetizeStringify(currentState.admissionRequest)
          ) {
            return {
              ok: false,
              code: 'scope_mismatch',
              message: 'activated Ed25519 Yao add-signer result does not match its ceremony',
            };
          }
          activation = {
            finalizeRequest,
            activation: consumed.activation,
          };
          await store.updateAddSignerCeremony(
            updateAddSignerCeremonyState({
              ceremony,
              signingRootId,
              signingRootVersion,
              signerState: {
                kind: 'near_ed25519_yao_add_signer_activated',
                finalizeRequest: activation.finalizeRequest,
                activation: activation.activation,
              },
            }),
          );
        } else if (
          currentState.kind === 'near_ed25519_yao_add_signer_activated' ||
          currentState.kind === 'near_ed25519_yao_add_signer_finalizing'
        ) {
          activation = currentState;
          if (!finalizeRequestsMatch(activation.finalizeRequest, finalizeRequest)) {
            return {
              ok: false,
              code: 'idempotency_conflict',
              message: 'Ed25519 Yao finalize request does not match the stored finalize state',
            };
          }
        } else {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'authorized Ed25519 Yao add-signer state is required',
          };
        }

        let response: Extract<
          Extract<WalletAddSignerFinalizeResponse, { ok: true }>,
          { kind: 'near_ed25519' }
        >;
        let signer: Parameters<D1WalletStore['putEd25519SignerIfSlotAvailable']>[0];
        let finalizingAtMs: number;
        if (currentState.kind === 'near_ed25519_yao_add_signer_finalizing') {
          response = currentState.response;
          signer = currentState.signer;
          finalizingAtMs = currentState.finalizingAtMs;
        } else {
          const publicKeyBytes = activation.activation.result.public_receipt.registered_public_key;
          const publicKey = ed25519NearPublicKeyFromBytes(publicKeyBytes);
          const nearAccountId = implicitNearAccountIdFromEd25519PublicKeyBytes(publicKeyBytes);
          const nearEd25519SigningKeyId =
            activation.activation.admissionRequest.application_binding.near_ed25519_signing_key_id;
          const capabilityInstallation = {
            kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
            activeCapabilityBinding: activation.activation.result.binding.session_id,
            nearAccountId,
            registrationAdmissionRequest: activation.activation.admissionRequest,
            registrationResult: activation.activation.result,
            runtimePolicyScope,
          } as const;
          const activeYaoCapability =
            buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(capabilityInstallation);
          if (!activeYaoCapability.ok) return activeYaoCapability;
          const authority = buildPasskeyWalletAuthAuthority({
            walletId: ceremony.intent.walletId,
            rpId: ceremony.auth.rpId,
            credentialIdB64u: ceremony.auth.credentialIdB64u,
          });
          const session = await yaoRuntime.mintWalletSession({
            kind: 'add_signer_wallet_session_v1',
            walletId: ceremony.intent.walletId,
            nearAccountId,
            nearEd25519SigningKeyId,
            authority,
            thresholdSessionId: activation.activation.admissionRequest.scope.wallet_session_id,
            participantIds,
            runtimePolicyScope,
          });
          if (!session.ok) return session;
          finalizingAtMs = Date.now();
          const ed25519 = {
            signerSlot: selection.signerSlot,
            nearAccountId,
            nearEd25519SigningKeyId,
            publicKey,
            relayerKeyId: yaoRuntime.signingWorkerId,
            keyVersion: selection.keyVersion,
            recoveryExportCapable: true,
            participantIds,
            session: session.session,
          } as const;
          response = {
            ok: true,
            kind: 'near_ed25519',
            walletId: ceremony.intent.walletId,
            rpId: ceremony.auth.rpId,
            credentialIdB64u: ceremony.auth.credentialIdB64u,
            ed25519,
          };
          signer = buildYaoEd25519WalletSignerRecord({
            walletId: ceremony.intent.walletId,
            nearAccountId,
            nearEd25519SigningKeyId,
            thresholdSessionId: session.session.thresholdSessionId,
            signerSlot: selection.signerSlot,
            publicKey,
            signingWorkerId: yaoRuntime.signingWorkerId,
            keyVersion: selection.keyVersion,
            participantIds,
            signingRootId,
            signingRootVersion,
            runtimePolicyScope,
            activeYaoCapability: activeYaoCapability.record,
            now: finalizingAtMs,
          });
          await store.updateAddSignerCeremony(
            updateAddSignerCeremonyState({
              ceremony,
              signingRootId,
              signingRootVersion,
              signerState: {
                kind: 'near_ed25519_yao_add_signer_finalizing',
                finalizeRequest: activation.finalizeRequest,
                activation: activation.activation,
                response,
                signer,
                finalizingAtMs,
              },
            }),
          );
        }

        if (
          response.walletId !== ceremony.intent.walletId ||
          response.rpId !== ceremony.auth.rpId ||
          response.credentialIdB64u !== ceremony.auth.credentialIdB64u ||
          response.ed25519.signerSlot !== selection.signerSlot ||
          response.ed25519.session.thresholdSessionId !==
            activation.activation.admissionRequest.scope.wallet_session_id ||
          signer.walletId !== response.walletId ||
          signer.signerSlot !== response.ed25519.signerSlot ||
          signer.nearAccountId !== response.ed25519.nearAccountId ||
          signer.nearEd25519SigningKeyId !== response.ed25519.nearEd25519SigningKeyId ||
          signer.thresholdSessionId !== response.ed25519.session.thresholdSessionId ||
          signer.publicKey !== response.ed25519.publicKey ||
          signer.signingWorkerId !== response.ed25519.relayerKeyId ||
          signer.keyVersion !== response.ed25519.keyVersion ||
          signer.signingRootId !== signingRootId ||
          signer.signingRootVersion !== signingRootVersion ||
          alphabetizeStringify(signer.participantIds) !==
            alphabetizeStringify(response.ed25519.participantIds) ||
          alphabetizeStringify(signer.runtimePolicyScope) !==
            alphabetizeStringify(runtimePolicyScope)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'stored Ed25519 Yao add-signer finalize plan is invalid',
          };
        }
        const provisioned =
          await normalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession({
            kind: 'router_ab_ed25519_yao_normal_signing_session_v1',
            walletId: ceremony.intent.walletId,
            nearAccountId: response.ed25519.nearAccountId,
            nearEd25519SigningKeyId: response.ed25519.nearEd25519SigningKeyId,
            authorityScope: response.ed25519.session.authorityScope,
            thresholdSessionId: response.ed25519.session.thresholdSessionId,
            signingGrantId: response.ed25519.session.signingGrantId,
            signingWorkerId: yaoRuntime.signingWorkerId,
            expiresAtMs: response.ed25519.session.expiresAtMs,
            participantIds,
            remainingUses: response.ed25519.session.remainingUses,
          });
        if (!provisioned.ok) return provisioned;
        const inserted = await walletStore.putEd25519SignerIfSlotAvailable(signer);
        if (!inserted) {
          const existing = await walletStore.getEd25519SignerBySlot({
            walletId: ceremony.intent.walletId,
            signerSlot: selection.signerSlot,
          });
          if (!existing || alphabetizeStringify(existing) !== alphabetizeStringify(signer)) {
            return {
              ok: false,
              code: 'signer_conflict',
              message: 'Ed25519 signer slot is already occupied',
            };
          }
        }
        const installed = await yaoRuntime.installPersistedActiveCapability(
          signer.activeYaoCapability,
        );
        if (!installed.ok) return installed;
        await store.putAddSignerFinalizeReplay({
          kind: 'wallet_add_signer_finalize_replay_v1',
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
          idempotencyKey,
          request: finalizeRequest,
          response,
          createdAtMs: finalizingAtMs,
          expiresAtMs: finalizingAtMs + ADD_SIGNER_REPLAY_TTL_MS,
        });
        await cleanupFinalizedAddSignerCeremony({
          store,
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
        });
        return response;
      }
      if (
        ceremony.intent.signerSelection.mode !== 'ecdsa' ||
        ceremony.signerState.kind !== 'ecdsa_add_signer_activated'
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'activated ECDSA add-signer registration is required before finalize',
        };
      }
      const expectedKeyHandle = request.ecdsa.expectedKeyHandles[0];
      if (expectedKeyHandle !== ceremony.signerState.bootstrap.keyHandle) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA add-signer finalize expected key handle mismatch',
        };
      }
      const bootstraps: {
        chainTarget: StoredEcdsaAddSignerActivated['chainTargets'][number];
        bootstrap: StoredEcdsaAddSignerActivated['bootstrap'];
      }[] = [];
      for (const chainTarget of ceremony.signerState.chainTargets) {
        bootstraps.push({
          chainTarget,
          bootstrap: ceremony.signerState.bootstrap,
        });
      }
      const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
        bootstraps,
        publicCapability: ceremony.signerState.publicCapability,
        errorContext: 'ECDSA add-signer finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;
      const walletKeys = walletKeyResult.walletKeys;
      const signerWriteNow = Date.now();
      const walletStore = this.getWalletStore();
      const wallet = await walletStore.getWallet({ walletId: ceremony.intent.walletId });
      if (!wallet) return { ok: false, code: 'not_found', message: 'wallet not found' };
      const walletSigners = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys,
        now: signerWriteNow,
      });
      await walletStore.putSigners(walletSigners);
      const response: Extract<WalletAddSignerFinalizeResponse, { ok: true }> = {
        ok: true,
        kind: 'evm_family_ecdsa',
        walletId: ceremony.intent.walletId,
        ...(ceremony.auth.kind === 'webauthn_assertion' ? { rpId: ceremony.auth.rpId } : {}),
        ecdsa: {
          walletKeys,
        },
      };
      await store.putAddSignerFinalizeReplay({
        kind: 'wallet_add_signer_finalize_replay_v1',
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        idempotencyKey,
        request: finalizeRequest,
        response,
        createdAtMs: signerWriteNow,
        expiresAtMs: signerWriteNow + ADD_SIGNER_REPLAY_TTL_MS,
      });
      await cleanupFinalizedAddSignerCeremony({
        store,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
      });
      return response;
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-signer ceremony',
      };
    }
  }
}
