import { parseRouterAbEcdsaRegistrationActivationReceiptV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletRegistrationActivateResponseV2 } from '../../core/threeRouteRegistrationContracts';
import {
  D1WalletAuthMethodStore,
  type WalletAuthMethodStore,
} from '../../core/d1WalletAuthMethodStore';
import { D1WalletStore } from '../../core/d1WalletStore';
import { D1IdentityStore } from '../../core/d1IdentityStore';
import { D1EmailRecoveryPreparationStore } from '../../core/EmailRecoveryPreparationStore';
import { D1WebAuthnCredentialBindingStore } from '../../core/WebAuthnCredentialBindingStore';
import type { IdentityStore, LinkIdentityResult } from '../../core/IdentityStore';
import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import { normalizeLogger } from '../../core/logger';
import { toPublicKeyStringFromSecretKey } from '../../core/nearKeys';
import { signGasRelayerNearTransactionWithDeps } from '../../core/authService/nearTransactions';
import { ensureSignerWasmRuntime, type SignerWasmRuntimeState } from '../../core/authService/wasm';
import { MinimalNearClient } from '../../core/rpcClients/near/NearClient';
import {
  executeSignedDelegateWithRelayer,
  type ExecuteSignedDelegateRequest,
  type ExecuteSignedDelegateResult,
} from '../../delegateAction';
import type { ActionArgsWasm } from '@shared/near/actions';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from '../../core/types';
import { EmailRecoveryAuthOperations } from '../../core/authService/emailRecoveryAuthOperations';
import type { RouterApiServiceBag } from '../authServicePort';
import type { RouterApiEmailRecoveryAuthService } from '../routerApi';
import { CloudflareD1RegistrationCeremonyIntentStore } from './d1RegistrationCeremonyStore';
import { isRecordValue, sha256BytesPortable } from './d1RouterApiAuthBoundary';
import { CloudflareD1NearPublicKeyStore } from './d1NearPublicKeyStore';
import { CloudflareD1WebAuthnStore } from './d1WebAuthnStore';
import { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import { CloudflareD1EmailOtpDeliveryRuntime } from './d1EmailOtpDeliveryRuntime';
import { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import { CloudflareD1EmailOtpGrantStore } from './d1EmailOtpGrantStore';
import { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import { CloudflareD1EmailOtpRecoveryEscrowStore } from './d1EmailOtpRecoveryEscrowStore';
import { CloudflareD1EmailOtpServerSealRuntime } from './d1EmailOtpServerSealRuntime';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import { CloudflareD1EmailOtpChallengeIssuer } from './d1EmailOtpChallengeIssuer';
import { CloudflareD1EmailOtpChallengeService } from './d1EmailOtpChallengeService';
import { CloudflareD1EmailOtpRecoveryService } from './d1EmailOtpRecoveryService';
import { CloudflareD1RouterAbSigningRuntime } from './d1RouterAbSigningRuntime';
import { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';
import { CloudflareD1GoogleEmailOtpSessionResolver } from './d1GoogleEmailOtpSessionResolver';
import { CloudflareD1SessionStore } from './d1SessionStore';
import { CloudflareD1SessionService } from './d1SessionService';
import { CloudflareD1IdentityService } from './d1IdentityService';
import { CloudflareD1OidcVerificationService } from './d1OidcVerificationService';
import { CloudflareD1WebAuthnAuthService } from './d1WebAuthnAuthService';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import {
  CloudflareD1WalletRegistrationService,
  parseD1WalletRegistrationStartSideEffectRecord,
  type D1WalletRegistrationFinalizePreparedV1,
  type D1WalletRegistrationActivateSideEffectRecord,
  type D1WalletRegistrationActivateSideEffectStore,
  type D1WalletRegistrationFinalizeSideEffectRecord,
  type D1WalletRegistrationFinalizeSideEffectStore,
  type D1WalletRegistrationStartSideEffectRecord,
  type D1WalletRegistrationStartSideEffectStore,
  type SponsoredNamedNearAccountCreationResult,
} from './d1WalletRegistrationService';
import { parseD1WalletRegistrationFinalizeTerminalResponse } from './d1RegistrationCeremonyRecords';
import { CloudflareD1WalletRegistrationCommitStore } from './d1WalletRegistrationCommitStore';
import {
  CloudflareD1WalletAddSignerService,
  parseD1WalletAddSignerFinalizeSideEffectRecord,
  parseD1WalletAddSignerStartSideEffectRecord,
  type D1WalletAddSignerFinalizeSideEffectRecord,
  type D1WalletAddSignerFinalizeSideEffectStore,
  type D1WalletAddSignerStartSideEffectRecord,
  type D1WalletAddSignerStartSideEffectStore,
} from './d1WalletAddSignerService';
import { CloudflareD1RegistrationIntentService } from './d1RegistrationIntentService';
import {
  broadcastPreparedSponsoredNearAccountCreation,
  fundImplicitNearAccountWithRelayer,
  preparedSponsoredNearAccountCreationArtifactFingerprint,
  prepareSponsoredNearAccountCreationWithRelayer,
  type PreparedSponsoredNearAccountCreationV1,
} from '../../core/nearRelayerAccountProvisioning';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../routerAbEd25519YaoRegistrationSideEffectBoundary';
import { createCloudflareD1VersionedJsonRecordStore } from './d1VersionedJsonRecordStore';
import type { CloudflareVersionedJsonObject } from './versionedJsonRecordStore';
import {
  normalizeD1RouterApiAuthOptions,
  type CloudflareD1RouterApiAuthServiceOptions,
  type NormalizedCloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';
import type { RouterAbEd25519YaoProductRegistrationRuntimeV1 } from '../routerAbEd25519YaoProductRegistration';

export type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
  CloudflareD1EmailOtpServerSealConfig,
  CloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';

export type CloudflareD1RouterApiAuthService = Omit<RouterApiServiceBag, 'thresholdRuntime'> & {
  readonly thresholdRuntime: RouterApiServiceBag['thresholdRuntime'] &
    Pick<CloudflareD1RouterAbSigningRuntime, 'getRouterAbLocalSigningSeedRuntime'>;
  readonly executeSignedDelegate: (
    input: ExecuteSignedDelegateRequest,
  ) => Promise<ExecuteSignedDelegateResult>;
};

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

type D1IdentityLinkInput = {
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity?: boolean;
};

type SponsoredNamedNearAccountInput = {
  readonly accountId: string;
  readonly publicKey: string;
  /**
   * Registration-scoped key for the durable claim. Two attempts at the same
   * registration share a key so the second replays the first's transaction.
   */
  readonly idempotencyKey: string;
};

type CloudflareD1RouterApiLazyStoreState = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  walletStore: D1WalletStore | null;
  walletAuthMethodStore: WalletAuthMethodStore | null;
  registrationCeremonyIntentStore: CloudflareD1RegistrationCeremonyIntentStore | null;
};

type CloudflareD1RouterApiAuthAssembly = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly emailOtpServerSeal: CloudflareD1EmailOtpServerSealRuntime;
  readonly emailOtpChallengeService: CloudflareD1EmailOtpChallengeService;
  readonly emailOtpRecoveryService: CloudflareD1EmailOtpRecoveryService;
  readonly identityService: CloudflareD1IdentityService;
  readonly oidcVerification: CloudflareD1OidcVerificationService;
  readonly sessionService: CloudflareD1SessionService;
  readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  readonly nearPublicKeys: CloudflareD1NearPublicKeyStore;
  readonly webAuthnAuthService: CloudflareD1WebAuthnAuthService;
  readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  readonly walletRegistrations: CloudflareD1WalletRegistrationService;
  readonly walletAddSigners: CloudflareD1WalletAddSignerService;
  readonly registrationIntents: CloudflareD1RegistrationIntentService;
  readonly routerAbSigning: CloudflareD1RouterAbSigningRuntime;
  readonly signedDelegateExecutor: CloudflareD1SignedDelegateExecutor;
};

type D1WalletRegistrationRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'registrationIntents' | 'walletRegistrations'
>;

type D1WalletAuthMethodRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'registrationIntents' | 'walletAuthMethods' | 'walletAddSigners'
>;

type D1WalletUnlockRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'emailOtpRecoveryService' | 'webAuthnAuthService'
>;

type D1EmailOtpRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  | 'emailOtpServerSeal'
  | 'emailOtpChallengeService'
  | 'emailOtpRecoveryService'
  | 'googleEmailOtpSessions'
  | 'oidcVerification'
>;

type D1WebAuthnRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'webAuthnAuthService'
>;

type D1IdentityRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'googleEmailOtpSessions' | 'identityService' | 'oidcVerification'
>;

type D1SessionVersionRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'sessionService'
>;

type D1ThresholdRuntimeRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'routerAbSigning'
>;

type D1NearFundingRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'nearPublicKeys' | 'options'
>;

type D1RecoveryRouteServiceAssembly = Pick<CloudflareD1RouterApiAuthAssembly, 'sessionService'>;

type D1EmailRecoveryAuthServiceAssembly = Pick<CloudflareD1RouterApiAuthAssembly, 'options'>;

type D1RouterAccountRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'routerAbSigning'
>;

class CloudflareD1SignedDelegateExecutor {
  private signerWasmState: SignerWasmRuntimeState = { signerWasmReady: false };
  private readonly logger = normalizeLogger();

  constructor(private readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions) {}

  async execute(input: ExecuteSignedDelegateRequest): Promise<ExecuteSignedDelegateResult> {
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    const nearRpcUrl = this.options.nearRpcUrl;
    if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl) {
      return {
        ok: false,
        code: 'not_configured',
        error: 'Signed delegate execution is not configured on this server',
      };
    }

    try {
      const relayerPublicKey =
        this.options.relayerPublicKey || toPublicKeyStringFromSecretKey(relayerPrivateKey);
      return await executeSignedDelegateWithRelayer({
        nearClient: new MinimalNearClient(nearRpcUrl),
        relayerAccount,
        relayerPublicKey,
        hash: input.hash,
        signedDelegate: input.signedDelegate,
        policy: input.policy,
        signGasRelayerNearTransaction: this.signGasRelayerNearTransaction.bind(this),
      });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'delegate_execution_failed',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async ensureSignerWasm(): Promise<void> {
    this.signerWasmState = await ensureSignerWasmRuntime({
      state: this.signerWasmState,
      override: this.options.signerWasmModuleOrPath,
      logger: this.logger,
    });
  }

  private async signGasRelayerNearTransaction(input: {
    readonly receiverId: string;
    readonly nonce: string;
    readonly blockHash: string;
    readonly actions: ActionArgsWasm[];
  }): ReturnType<typeof signGasRelayerNearTransactionWithDeps> {
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    if (!relayerAccount || !relayerPrivateKey) {
      throw new Error('Signed delegate relayer credentials are not configured');
    }
    return await signGasRelayerNearTransactionWithDeps({
      ...input,
      ensureSignerWasm: this.ensureSignerWasm.bind(this),
      relayerAccount,
      relayerPrivateKey,
    });
  }
}

function d1RouterApiErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

async function linkD1Identity(
  identityStore: IdentityStore,
  input: D1IdentityLinkInput,
): Promise<LinkIdentityResult> {
  try {
    return await identityStore.linkSubjectToUserId(input);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: d1RouterApiErrorMessage(error) || 'Failed to link identity',
    };
  }
}

function createLazyStoreState(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiLazyStoreState {
  return {
    options,
    walletStore: null,
    walletAuthMethodStore: null,
    registrationCeremonyIntentStore: null,
  };
}

function getRegistrationCeremonyIntentStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): CloudflareD1RegistrationCeremonyIntentStore {
  if (state.registrationCeremonyIntentStore) return state.registrationCeremonyIntentStore;
  state.registrationCeremonyIntentStore = new CloudflareD1RegistrationCeremonyIntentStore({
    kind: 'partitioned_d1',
    database: state.options.database,
    scope: {
      namespace: state.options.namespace,
      orgId: state.options.orgId,
      projectId: state.options.projectId,
      envId: state.options.envId,
    },
    keyPrefix: 'gateway-registration:',
  });
  return state.registrationCeremonyIntentStore;
}

function getWalletAuthMethodStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): WalletAuthMethodStore {
  if (state.walletAuthMethodStore) return state.walletAuthMethodStore;
  state.walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletAuthMethodStore;
}

function getWalletStoreForState(state: CloudflareD1RouterApiLazyStoreState): D1WalletStore {
  if (state.walletStore) return state.walletStore;
  state.walletStore = new D1WalletStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletStore;
}

function scopePrepareForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  sql: string,
  values: readonly unknown[],
): D1PreparedStatementLike {
  return options.database.prepare(sql).bind(...scopeValuesForOptions(options, values));
}

function scopeValuesForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  values: readonly unknown[],
): readonly unknown[] {
  return [options.namespace, options.orgId, options.projectId, options.envId, ...values];
}

async function ensureD1EmailRecoverySignerRuntimeReady(): Promise<void> {}

class CloudflareD1EmailRecoveryAuthService implements RouterApiEmailRecoveryAuthService {
  private readonly operations: EmailRecoveryAuthOperations;

  constructor(assembly: D1EmailRecoveryAuthServiceAssembly) {
    const options = assembly.options;
    this.operations = new EmailRecoveryAuthOperations({
      ensureSignerAndRelayerAccount: ensureD1EmailRecoverySignerRuntimeReady,
      getDefaultRuntimePolicyScope: () => ({
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        signingRootVersion: 'default',
      }),
      webAuthnCredentialBindingStore: new D1WebAuthnCredentialBindingStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
      emailRecoveryPreparationStore: new D1EmailRecoveryPreparationStore({
        database: options.database,
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
        ensureSchema: false,
      }),
    });
  }

  async prepareEmailRecovery(
    request: Parameters<RouterApiEmailRecoveryAuthService['prepareEmailRecovery']>[0],
  ): ReturnType<RouterApiEmailRecoveryAuthService['prepareEmailRecovery']> {
    return await this.operations.prepareEmailRecovery(request);
  }
}

async function fundImplicitNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: FundImplicitNearAccountRequest,
): Promise<FundImplicitNearAccountResult> {
  if (!options.implicitNearAccountTestFundingEnabled) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account test funding is not enabled on this server',
    };
  }
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const fundedAmountYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !fundedAmountYocto) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account funding is not configured on this server',
    };
  }
  return await fundImplicitNearAccountWithRelayer({
    ...input,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    fundedAmountYocto,
  });
}

/**
 * Validates a persisted claim before it is trusted to skip a broadcast or to be
 * replayed. An invalid record makes the D1 read fail, which leaves the effect
 * uncertain and prevents any network action on unvalidated bytes.
 */
function parseSponsoredNearAccountSideEffectRecord(
  raw: unknown,
): RouterAbEd25519YaoRegistrationSideEffectRecordV1<
  AccountCreationResult,
  PreparedSponsoredNearAccountCreationV1
> | null {
  if (!isRecordValue(raw)) return null;
  const record = raw;
  if (record.operation !== 'finalize') return null;
  const requestFingerprint = parseSideEffectFingerprint(record.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(
    record.preparedArtifactFingerprint,
  );
  if (requestFingerprint === null || preparedArtifactFingerprint === null) return null;
  if (!isNonNegativeSafeInteger(record.claimedAtMs)) return null;
  const prepared = parsePreparedSponsoredNearAccountCreation(record.prepared);
  if (prepared === null) return null;
  if (record.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'finalize',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: record.claimedAtMs,
      prepared,
    };
  }
  if (record.kind === 'router_ab_ed25519_yao_registration_side_effect_completion_v1') {
    if (!isNonNegativeSafeInteger(record.completedAtMs)) return null;
    const response = parseAccountCreationResult(record.response);
    if (response === null) return null;
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: record.claimedAtMs,
      completedAtMs: record.completedAtMs,
      prepared,
      response,
    };
  }
  return null;
}

function parseWalletRegistrationFinalizePrepared(
  raw: unknown,
): D1WalletRegistrationFinalizePreparedV1 | null {
  return isRecordValue(raw) && raw.kind === 'd1_wallet_registration_finalize_prepared_v1'
    ? { kind: 'd1_wallet_registration_finalize_prepared_v1' }
    : null;
}

function parseWalletRegistrationFinalizeSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationFinalizeSideEffectRecord | null {
  if (
    !isRecordValue(raw) ||
    raw.operation !== 'finalize' ||
    !isNonNegativeSafeInteger(raw.claimedAtMs)
  ) {
    return null;
  }
  const requestFingerprint = parseSideEffectFingerprint(raw.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(raw.preparedArtifactFingerprint);
  const prepared = parseWalletRegistrationFinalizePrepared(raw.prepared);
  if (requestFingerprint === null || preparedArtifactFingerprint === null || prepared === null) {
    return null;
  }
  if (raw.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'finalize',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: raw.claimedAtMs,
      prepared,
    };
  }
  if (
    raw.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1' ||
    !isNonNegativeSafeInteger(raw.completedAtMs)
  ) {
    return null;
  }
  const response = parseD1WalletRegistrationFinalizeTerminalResponse(raw.response);
  if (!response) return null;
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: 'finalize',
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs: raw.claimedAtMs,
    completedAtMs: raw.completedAtMs,
    prepared,
    response,
  };
}

/**
 * Refactor 94C. The activate operation row. Same record shape as the
 * finalize journal it absorbs, tagged with its own operation so an activate
 * row can never be read as a finalize row or vice versa.
 */
/**
 * The activate terminal response is the finalize commit merged with the
 * activation receipt and derivation bootstrap. Validating the commit half
 * through the existing parser keeps one definition of that shape; the
 * activation half must simply be present, since a stored response missing it
 * could not bring a wallet online and is not a usable replay.
 */
function parseD1WalletRegistrationActivateTerminalResponse(
  raw: unknown,
): WalletRegistrationActivateResponseV2 | null {
  const commit = parseD1WalletRegistrationFinalizeTerminalResponse(raw);
  if (!commit) return null;
  if (!commit.ok) return commit;
  if (commit.kind !== 'evm_family_ecdsa' || !isRecordValue(raw)) return null;
  const stored = isRecordValue(raw.ecdsa) ? raw.ecdsa : null;
  if (!stored || !isRecordValue(stored.bootstrap)) return null;
  let activation: ReturnType<typeof parseRouterAbEcdsaRegistrationActivationReceiptV1>;
  try {
    activation = parseRouterAbEcdsaRegistrationActivationReceiptV1(stored.activation);
  } catch {
    return null;
  }
  return {
    ...commit,
    ecdsa: {
      ...commit.ecdsa,
      activation,
      /* The bootstrap is the Gateway's own derivation payload, written by
         this service and never client-supplied; there is no separate parser
         for it, so presence is the check. */
      bootstrap: stored.bootstrap as WalletRegistrationActivateResponseV2 extends { ecdsa: infer E }
        ? E extends { bootstrap: infer B }
          ? B
          : never
        : never,
    },
  };
}

function parseWalletRegistrationActivateSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationActivateSideEffectRecord | null {
  if (
    !isRecordValue(raw) ||
    raw.operation !== 'registration_activate' ||
    !isNonNegativeSafeInteger(raw.claimedAtMs)
  ) {
    return null;
  }
  const requestFingerprint = parseSideEffectFingerprint(raw.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(raw.preparedArtifactFingerprint);
  const prepared = parseWalletRegistrationFinalizePrepared(raw.prepared);
  if (requestFingerprint === null || preparedArtifactFingerprint === null || prepared === null) {
    return null;
  }
  if (raw.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'registration_activate',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: raw.claimedAtMs,
      prepared,
    };
  }
  if (
    raw.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1' ||
    !isNonNegativeSafeInteger(raw.completedAtMs)
  ) {
    return null;
  }
  const response = parseD1WalletRegistrationActivateTerminalResponse(raw.response);
  if (!response) return null;
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: 'registration_activate',
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs: raw.claimedAtMs,
    completedAtMs: raw.completedAtMs,
    prepared,
    response,
  };
}

function parsePreparedSponsoredNearAccountCreation(
  value: unknown,
): PreparedSponsoredNearAccountCreationV1 | null {
  if (!isRecordValue(value) || value.kind !== 'prepared_sponsored_near_account_creation_v1') {
    return null;
  }
  const accountId = parseNonEmptyString(value.accountId);
  const publicKey = parseNonEmptyString(value.publicKey);
  const relayerAccountId = parseNonEmptyString(value.relayerAccountId);
  const relayerPublicKey = parseNonEmptyString(value.relayerPublicKey);
  const initialBalanceYocto = parseNonEmptyString(value.initialBalanceYocto);
  const transactionHash = parseNonEmptyString(value.transactionHash);
  const nextNonce = parseNonEmptyString(value.nextNonce);
  const blockHash = parseNonEmptyString(value.blockHash);
  const signedTransactionBorshB64u = parseBoundedBase64Url(value.signedTransactionBorshB64u);
  if (
    accountId === null ||
    publicKey === null ||
    relayerAccountId === null ||
    relayerPublicKey === null ||
    initialBalanceYocto === null ||
    transactionHash === null ||
    nextNonce === null ||
    blockHash === null ||
    signedTransactionBorshB64u === null
  ) {
    return null;
  }
  return {
    kind: 'prepared_sponsored_near_account_creation_v1',
    accountId,
    publicKey,
    relayerAccountId,
    relayerPublicKey,
    initialBalanceYocto,
    transactionHash,
    nextNonce,
    blockHash,
    signedTransactionBorshB64u,
  };
}

function parseAccountCreationResult(value: unknown): AccountCreationResult | null {
  if (!isRecordValue(value) || typeof value.success !== 'boolean') return null;
  const accountId = parseOptionalString(value.accountId);
  const transactionHash = parseOptionalString(value.transactionHash);
  const error = parseOptionalString(value.error);
  const message = parseOptionalString(value.message);
  if (
    ('accountId' in value && accountId === null) ||
    ('transactionHash' in value && transactionHash === null) ||
    ('error' in value && error === null) ||
    ('message' in value && message === null)
  ) {
    return null;
  }
  if (value.success && (accountId === undefined || transactionHash === undefined)) return null;
  const normalizedAccountId = accountId ?? undefined;
  const normalizedTransactionHash = transactionHash ?? undefined;
  const normalizedError = error ?? undefined;
  const normalizedMessage = message ?? undefined;
  return {
    success: value.success,
    ...(normalizedAccountId === undefined ? {} : { accountId: normalizedAccountId }),
    ...(normalizedTransactionHash === undefined
      ? {}
      : { transactionHash: normalizedTransactionHash }),
    ...(normalizedError === undefined ? {} : { error: normalizedError }),
    ...(normalizedMessage === undefined ? {} : { message: normalizedMessage }),
  };
}

function parseNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function parseSideEffectFingerprint(value: unknown): string | null {
  return typeof value === 'string' && /^[a-zA-Z0-9:_-]{32,192}$/u.test(value) ? value : null;
}

function parseBoundedBase64Url(value: unknown): string | null {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 8_192 &&
    /^[\w-]+$/u.test(value)
    ? value
    : null;
}

function parseOptionalString(value: unknown): string | undefined | null {
  return value === undefined ? undefined : parseNonEmptyString(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function resolveEd25519YaoProductRegistration(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): RouterAbEd25519YaoProductRegistrationRuntimeV1 | null {
  return options.ed25519YaoProductRegistration || null;
}

function sponsoredNearAccountSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): RouterAbEd25519YaoRegistrationSideEffectStoreV1<
  AccountCreationResult,
  PreparedSponsoredNearAccountCreationV1
> {
  return createCloudflareD1VersionedJsonRecordStore<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<
      AccountCreationResult,
      PreparedSponsoredNearAccountCreationV1
    >
  >({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'router-ab-yao-sponsored-account:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseSponsoredNearAccountSideEffectRecord,
  });
}

function walletRegistrationFinalizeSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletRegistrationFinalizeSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletRegistrationFinalizeSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-registration-finalize:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseWalletRegistrationFinalizeSideEffectRecord,
  });
}

function walletRegistrationActivateSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletRegistrationActivateSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletRegistrationActivateSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-registration-activate:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseWalletRegistrationActivateSideEffectRecord,
  });
}

function walletRegistrationStartSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletRegistrationStartSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletRegistrationStartSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-registration-start:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseD1WalletRegistrationStartSideEffectRecord,
  });
}

function walletAddSignerStartSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletAddSignerStartSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletAddSignerStartSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-add-signer-start:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseD1WalletAddSignerStartSideEffectRecord,
  });
}

function walletAddSignerFinalizeSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletAddSignerFinalizeSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletAddSignerFinalizeSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-add-signer-finalize:',
    encode: (value) => value as unknown as CloudflareVersionedJsonObject,
    parse: parseD1WalletAddSignerFinalizeSideEffectRecord,
  });
}

/**
 * Creates the sponsored account through a durable claim. The signed transaction
 * and its hash are persisted before the broadcast, so a lost response replays
 * those exact bytes instead of building a second transaction under a fresh
 * nonce. Rebroadcasting an identical signed transaction reuses its hash, so the
 * network treats the retry as the same transaction.
 */
async function createSponsoredNamedNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: SponsoredNamedNearAccountInput,
): Promise<SponsoredNamedNearAccountCreationResult> {
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const initialBalanceYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !initialBalanceYocto) {
    return {
      kind: 'rejected',
      message: 'Sponsored NEAR account creation is not configured on this server',
    };
  }
  const relayerInput = {
    accountId: input.accountId,
    publicKey: input.publicKey,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    initialBalanceYocto,
  };
  const requestFingerprint = base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        kind: 'sponsored_near_account_creation_v1',
        accountId: input.accountId,
        publicKey: input.publicKey,
        relayerAccountId: relayerAccount,
        initialBalanceYocto,
      }),
    ),
  );
  const outcome = await runRouterAbEd25519YaoRegistrationSideEffectV1<
    AccountCreationResult,
    PreparedSponsoredNearAccountCreationV1
  >(sponsoredNearAccountSideEffectStore(options), {
    kind: 'prepared_resumable',
    resumeAfterMs: 30_000,
    operation: 'finalize',
    key: `sponsored-account:${input.idempotencyKey}`,
    requestFingerprint,
    nowMs: () => Date.now(),
    prepare: async () => {
      const prepared = await prepareSponsoredNearAccountCreationWithRelayer(relayerInput);
      if (!prepared.ok) throw new Error(prepared.message);
      return prepared.prepared;
    },
    derivePreparedArtifactFingerprint: preparedSponsoredNearAccountCreationArtifactFingerprint,
    execute: async (prepared, attempt) => {
      if (!prepared) throw new Error('Sponsored NEAR account transaction was not prepared');
      const broadcast = await broadcastPreparedSponsoredNearAccountCreation({
        prepared,
        nearRpcUrl,
        relayerAccountId: relayerAccount,
        // A resumed attempt follows a broadcast whose outcome was never
        // observed, so settle it against the chain before resubmitting.
        reconcileFirst: attempt === 'resumed',
      });
      if (broadcast.kind === 'uncertain') {
        // Throwing keeps the claim open so a later retry reconciles. Returning
        // here would persist a possibly-landed transaction as a terminal failure.
        throw new Error(broadcast.message);
      }
      return broadcast.result;
    },
  });
  switch (outcome.kind) {
    case 'executed':
    case 'exact_replay': {
      if (outcome.value.success && outcome.value.accountId && outcome.value.transactionHash) {
        return {
          kind: 'created',
          accountId: outcome.value.accountId,
          transactionHash: outcome.value.transactionHash,
        };
      }
      return {
        kind: 'rejected',
        message:
          outcome.value.message ||
          outcome.value.error ||
          'Sponsored NEAR account creation was rejected',
      };
    }
    case 'in_progress':
    case 'uncertain': {
      const message =
        outcome.kind === 'uncertain'
          ? outcome.message
          : 'Sponsored NEAR account creation is already in progress for this registration';
      return { kind: 'retryable', message, retryAfterMs: 30_000 };
    }
    case 'request_conflict':
      return {
        kind: 'rejected',
        message: 'Sponsored NEAR account creation idempotency key conflicts with another request',
      };
  }
}

function createCloudflareD1RouterApiAuthAssembly(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthAssembly {
  const options = normalizeD1RouterApiAuthOptions(input);
  const prepare: ScopedD1Prepare = scopePrepareForOptions.bind(undefined, options);
  const lazyStores = createLazyStoreState(options);
  const getRegistrationCeremonyIntentStore = getRegistrationCeremonyIntentStoreForState.bind(
    undefined,
    lazyStores,
  );
  const getWalletAuthMethodStore = getWalletAuthMethodStoreForState.bind(undefined, lazyStores);
  const getWalletStore = getWalletStoreForState.bind(undefined, lazyStores);
  const createSponsoredNamedNearAccount = createSponsoredNamedNearAccountForOptions.bind(
    undefined,
    options,
  );

  const identityStore = new D1IdentityStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
    ensureSchema: false,
  });
  const linkIdentity = linkD1Identity.bind(undefined, identityStore);
  const sessionStore = new CloudflareD1SessionStore({ prepare });
  const sessionService = new CloudflareD1SessionService({ sessionStore });
  const googleEmailOtpRegistrationAttempts = new CloudflareD1GoogleEmailOtpRegistrationAttemptStore(
    {
      prepare,
      orgId: options.orgId,
    },
  );
  const nearPublicKeys = new CloudflareD1NearPublicKeyStore({ prepare });
  const webAuthnStore = new CloudflareD1WebAuthnStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const webAuthnAuthService = new CloudflareD1WebAuthnAuthService({ webAuthnStore });
  const emailOtpChallenges = new CloudflareD1EmailOtpChallengeStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const emailOtpDelivery = new CloudflareD1EmailOtpDeliveryRuntime(options.emailOtp);
  const emailOtpEnrollments = new CloudflareD1EmailOtpEnrollmentStore({ prepare });
  const emailOtpGrants = new CloudflareD1EmailOtpGrantStore({ prepare });
  const emailOtpRateLimits = new CloudflareD1EmailOtpRateLimitStore({
    prepare,
    rateLimits: options.emailOtp.rateLimits,
  });
  const emailOtpRecoveryEscrows = new CloudflareD1EmailOtpRecoveryEscrowStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const emailOtpServerSeal = new CloudflareD1EmailOtpServerSealRuntime(options.emailOtpServerSeal);
  const googleEmailOtpSessions = new CloudflareD1GoogleEmailOtpSessionResolver({
    emailOtpEnrollments,
    emailOtpRateLimits,
    identityStore,
    linkIdentity,
    production: options.emailOtp.production,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
  });
  const identityService = new CloudflareD1IdentityService({
    accountIdDerivationSecret: options.accountIdDerivationSecret,
    identityStore,
    relayerAccount: options.relayerAccount,
    resolveGoogleEmailOtpSession: googleEmailOtpSessions.resolve.bind(googleEmailOtpSessions),
  });
  const oidcVerification = new CloudflareD1OidcVerificationService({
    googleOidcClientId: options.googleOidcClientId,
    identityStore,
    linkIdentity,
    oidcExchange: options.oidcExchange,
  });
  const emailOtpRegistrationEnrollmentFinalizer =
    new CloudflareD1EmailOtpRegistrationEnrollmentFinalizer({
      emailOtpEnrollments,
      emailOtpRecoveryEscrows,
      googleEmailOtpSessions,
    });
  const emailOtpChallengeVerifier = new CloudflareD1EmailOtpChallengeVerifier({
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpRateLimits,
    lockoutTtlMs: options.emailOtp.lockoutTtlMs,
  });
  const walletAuthMethods = new CloudflareD1WalletAuthMethodService({
    emailOtpChallengeVerifier,
    getRegistrationCeremonyIntentStore,
    getWalletAuthMethodStore,
    googleEmailOtpRegistrationAttempts,
    sha256Bytes: sha256BytesPortable,
    webAuthnStore,
  });
  const walletRegistrationCommitStore = new CloudflareD1WalletRegistrationCommitStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const routerAbSigning = new CloudflareD1RouterAbSigningRuntime({
    relayerAccount: options.relayerAccount,
    relayerPublicKey: options.relayerPublicKey,
    routerAbSigningRuntimes: options.routerAbSigningRuntimes,
    thresholdStore: options.thresholdStore,
    auth: {
      verifyWebAuthnAuthenticationLite:
        webAuthnAuthService.verifyWebAuthnAuthenticationLite.bind(webAuthnAuthService),
    },
  });
  const signedDelegateExecutor = new CloudflareD1SignedDelegateExecutor(options);
  const walletRegistrations = new CloudflareD1WalletRegistrationService({
    createSponsoredNamedNearAccount,
    emailOtpRegistrationEnrollmentFinalizer,
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => resolveEd25519YaoProductRegistration(options),
    getRouterAbNormalSigningRuntime:
      routerAbSigning.getRouterAbNormalSigningRuntime.bind(routerAbSigning),
    ecdsaStrictRegistration: options.ecdsaStrictRegistration,
    getWalletStore,
    startSideEffects: walletRegistrationStartSideEffectStore(options),
    finalizeSideEffects: walletRegistrationFinalizeSideEffectStore(options),
    activateSideEffects: walletRegistrationActivateSideEffectStore(options),
    walletRegistrationCommitStore,
    walletAuthMethods,
  });
  const walletAddSigners = new CloudflareD1WalletAddSignerService({
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => resolveEd25519YaoProductRegistration(options),
    getRouterAbNormalSigningRuntime:
      routerAbSigning.getRouterAbNormalSigningRuntime.bind(routerAbSigning),
    ecdsaStrictRegistration: options.ecdsaStrictRegistration,
    getWalletStore,
    walletAuthMethods,
    startSideEffects: walletAddSignerStartSideEffectStore(options),
    finalizeSideEffects: walletAddSignerFinalizeSideEffectStore(options),
  });
  const registrationIntents = new CloudflareD1RegistrationIntentService({
    getRegistrationCeremonyIntentStore,
    signerWallets: emailOtpEnrollments,
  });
  const emailOtpChallengeIssuer = new CloudflareD1EmailOtpChallengeIssuer({
    config: {
      challengeTtlMs: options.emailOtp.challengeTtlMs,
      codeLength: options.emailOtp.codeLength,
      maxActiveChallengesPerContext: options.emailOtp.maxActiveChallengesPerContext,
      maxAttempts: options.emailOtp.maxAttempts,
    },
    emailOtpChallenges,
    emailOtpDelivery,
    emailOtpEnrollments,
    emailOtpRateLimits,
  });
  const emailOtpChallengeService = new CloudflareD1EmailOtpChallengeService({
    challenges: emailOtpChallenges,
    devOutboxEnabled: options.emailOtp.devOutboxEnabled,
    finalizer: emailOtpRegistrationEnrollmentFinalizer,
    grantTtlMs: options.emailOtp.grantTtlMs,
    grants: emailOtpGrants,
    issuer: emailOtpChallengeIssuer,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
    verifier: emailOtpChallengeVerifier,
  });
  const emailOtpRecoveryService = new CloudflareD1EmailOtpRecoveryService({
    challengeVerifier: emailOtpChallengeVerifier,
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpGrants,
    emailOtpRateLimits,
    emailOtpRecoveryEscrows,
    grantTtlMs: options.emailOtp.grantTtlMs,
    sha256Bytes: sha256BytesPortable,
  });

  return {
    options,
    emailOtpServerSeal,
    emailOtpChallengeService,
    emailOtpRecoveryService,
    identityService,
    oidcVerification,
    sessionService,
    googleEmailOtpSessions,
    nearPublicKeys,
    webAuthnAuthService,
    walletAuthMethods,
    walletRegistrations,
    walletAddSigners,
    registrationIntents,
    routerAbSigning,
    signedDelegateExecutor,
  };
}

function createD1WalletRegistrationRouteService(
  assembly: D1WalletRegistrationRouteServiceAssembly,
): RouterApiServiceBag['walletRegistration'] {
  return {
    listWalletEcdsaKeyFactsInventory:
      assembly.walletRegistrations.listWalletEcdsaKeyFactsInventory.bind(
        assembly.walletRegistrations,
      ),
    createRegistrationIntent: assembly.registrationIntents.createRegistrationIntent.bind(
      assembly.registrationIntents,
    ),
    cancelRegistrationIntent: assembly.registrationIntents.cancelRegistrationIntent.bind(
      assembly.registrationIntents,
    ),
    setupWalletRegistration: assembly.walletRegistrations.setupWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    respondWalletRegistration: assembly.walletRegistrations.respondWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    activateWalletRegistration: assembly.walletRegistrations.activateWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    startWalletRegistration: assembly.walletRegistrations.startWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    respondWalletRegistrationEcdsaDerivation:
      assembly.walletRegistrations.respondWalletRegistrationEcdsaDerivation.bind(
        assembly.walletRegistrations,
      ),
    activateWalletRegistrationEcdsa:
      assembly.walletRegistrations.activateWalletRegistrationEcdsa.bind(
        assembly.walletRegistrations,
      ),
    getWalletRegistrationRuntimePolicyScope:
      assembly.walletRegistrations.getWalletRegistrationRuntimePolicyScope.bind(
        assembly.walletRegistrations,
      ),
    finalizeWalletRegistration: assembly.walletRegistrations.finalizeWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    refreshEd25519YaoWalletSession:
      assembly.walletRegistrations.refreshEd25519YaoWalletSession.bind(
        assembly.walletRegistrations,
      ),
    recoverEd25519YaoEmailOtpWalletSession:
      assembly.walletRegistrations.recoverEd25519YaoEmailOtpWalletSession.bind(
        assembly.walletRegistrations,
      ),
    recordEcdsaPostRegistrationProof:
      assembly.walletRegistrations.recordEcdsaPostRegistrationProof.bind(
        assembly.walletRegistrations,
      ),
    activateEcdsaPostRegistrationSession:
      assembly.walletRegistrations.activateEcdsaPostRegistrationSession.bind(
        assembly.walletRegistrations,
      ),
  };
}

function createD1WalletAuthMethodRouteService(
  assembly: D1WalletAuthMethodRouteServiceAssembly,
): RouterApiServiceBag['walletAuthMethods'] {
  return {
    createAddAuthMethodIntent: assembly.registrationIntents.createAddAuthMethodIntent.bind(
      assembly.registrationIntents,
    ),
    createAddSignerIntent: assembly.registrationIntents.createAddSignerIntent.bind(
      assembly.registrationIntents,
    ),
    finalizeWalletAddAuthMethod: assembly.walletAuthMethods.finalizeWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    finalizeWalletAddSigner: assembly.walletAddSigners.finalizeWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
    respondWalletAddSignerEcdsaDerivation:
      assembly.walletAddSigners.respondWalletAddSignerEcdsaDerivation.bind(
        assembly.walletAddSigners,
      ),
    activateWalletAddSignerEcdsa: assembly.walletAddSigners.activateWalletAddSignerEcdsa.bind(
      assembly.walletAddSigners,
    ),
    getWalletAddSignerRuntimePolicyScope:
      assembly.walletAddSigners.getWalletAddSignerRuntimePolicyScope.bind(
        assembly.walletAddSigners,
      ),
    revokeWalletAuthMethod: assembly.walletAuthMethods.revokeWalletAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddAuthMethod: assembly.walletAuthMethods.startWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddSigner: assembly.walletAddSigners.startWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
  };
}

function createD1WalletUnlockRouteService(
  assembly: D1WalletUnlockRouteServiceAssembly,
): RouterApiServiceBag['walletUnlock'] {
  return {
    createEmailOtpUnlockChallenge:
      assembly.emailOtpRecoveryService.createEmailOtpUnlockChallenge.bind(
        assembly.emailOtpRecoveryService,
      ),
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    verifyEmailOtpUnlockProof: assembly.emailOtpRecoveryService.verifyEmailOtpUnlockProof.bind(
      assembly.emailOtpRecoveryService,
    ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1EmailOtpRouteService(
  assembly: D1EmailOtpRouteServiceAssembly,
): RouterApiServiceBag['emailOtp'] {
  return {
    applyEmailOtpServerSeal: assembly.emailOtpServerSeal.applyEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    cleanupGoogleEmailOtpDevRegistrationState:
      assembly.googleEmailOtpSessions.cleanupDevRegistrationState.bind(
        assembly.googleEmailOtpSessions,
      ),
    consumeEmailOtpGrant: assembly.emailOtpRecoveryService.consumeEmailOtpGrant.bind(
      assembly.emailOtpRecoveryService,
    ),
    consumeEmailOtpRecoveryKey: assembly.emailOtpRecoveryService.consumeEmailOtpRecoveryKey.bind(
      assembly.emailOtpRecoveryService,
    ),
    createEmailOtpChallenge: assembly.emailOtpChallengeService.createEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    createEmailOtpDeviceRecoveryChallenge:
      assembly.emailOtpChallengeService.createEmailOtpDeviceRecoveryChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    createEmailOtpEnrollmentChallenge:
      assembly.emailOtpChallengeService.createEmailOtpEnrollmentChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    getEmailOtpRecoveryCodeStatus:
      assembly.emailOtpRecoveryService.getEmailOtpRecoveryCodeStatus.bind(
        assembly.emailOtpRecoveryService,
      ),
    isEmailOtpStrongAuthRequired:
      assembly.emailOtpRecoveryService.isEmailOtpStrongAuthRequired.bind(
        assembly.emailOtpRecoveryService,
      ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    readActiveEmailOtpEnrollment:
      assembly.emailOtpRecoveryService.readActiveEmailOtpEnrollment.bind(
        assembly.emailOtpRecoveryService,
      ),
    readEmailOtpEnrollment: assembly.emailOtpRecoveryService.readEmailOtpEnrollment.bind(
      assembly.emailOtpRecoveryService,
    ),
    readEmailOtpOutboxEntry: assembly.emailOtpChallengeService.readEmailOtpOutboxEntry.bind(
      assembly.emailOtpChallengeService,
    ),
    recordEmailOtpRecoveryKeyAttemptFailure:
      assembly.emailOtpRecoveryService.recordEmailOtpRecoveryKeyAttemptFailure.bind(
        assembly.emailOtpRecoveryService,
      ),
    removeEmailOtpServerSeal: assembly.emailOtpServerSeal.removeEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    rotateEmailOtpRecoveryKeys: assembly.emailOtpRecoveryService.rotateEmailOtpRecoveryKeys.bind(
      assembly.emailOtpRecoveryService,
    ),
    validateGoogleEmailOtpRegistrationCandidateWallet:
      assembly.googleEmailOtpSessions.validateRegistrationCandidateWallet.bind(
        assembly.googleEmailOtpSessions,
      ),
    verifyEmailOtpChallenge: assembly.emailOtpChallengeService.verifyEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyEmailOtpDeviceRecoveryChallenge:
      assembly.emailOtpRecoveryService.verifyEmailOtpDeviceRecoveryChallenge.bind(
        assembly.emailOtpRecoveryService,
      ),
    verifyEmailOtpEnrollment: assembly.emailOtpChallengeService.verifyEmailOtpEnrollment.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
  };
}

function createD1WebAuthnRouteService(
  assembly: D1WebAuthnRouteServiceAssembly,
): RouterApiServiceBag['webAuthn'] {
  return {
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    createWebAuthnSyncAccountOptions:
      assembly.webAuthnAuthService.createWebAuthnSyncAccountOptions.bind(
        assembly.webAuthnAuthService,
      ),
    listWebAuthnAuthenticatorsForUser:
      assembly.webAuthnAuthService.listWebAuthnAuthenticatorsForUser.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnAuthenticationLite:
      assembly.webAuthnAuthService.verifyWebAuthnAuthenticationLite.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
    verifyWebAuthnSyncAccount: assembly.webAuthnAuthService.verifyWebAuthnSyncAccount.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1IdentityRouteService(
  assembly: D1IdentityRouteServiceAssembly,
): RouterApiServiceBag['identity'] {
  return {
    consumeGoogleEmailOtpRegistrationAttemptRateLimit:
      assembly.googleEmailOtpSessions.consumeRegistrationAttemptRateLimit.bind(
        assembly.googleEmailOtpSessions,
      ),
    getGoogleOidcPublicConfig: assembly.oidcVerification.getGoogleOidcPublicConfig.bind(
      assembly.oidcVerification,
    ),
    linkIdentity: assembly.identityService.linkIdentity.bind(assembly.identityService),
    listIdentities: assembly.identityService.listIdentities.bind(assembly.identityService),
    resolveGoogleEmailOtpSession: assembly.googleEmailOtpSessions.resolve.bind(
      assembly.googleEmailOtpSessions,
    ),
    resolveOidcWalletId: assembly.identityService.resolveOidcWalletId.bind(
      assembly.identityService,
    ),
    unlinkIdentity: assembly.identityService.unlinkIdentity.bind(assembly.identityService),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
    verifyOidcJwtExchange: assembly.oidcVerification.verifyOidcJwtExchange.bind(
      assembly.oidcVerification,
    ),
  };
}

function createD1SessionVersionRouteService(
  assembly: D1SessionVersionRouteServiceAssembly,
): RouterApiServiceBag['sessionVersions'] {
  return {
    getOrCreateAppSessionVersion: assembly.sessionService.getOrCreateAppSessionVersion.bind(
      assembly.sessionService,
    ),
    rotateAppSessionVersion: assembly.sessionService.rotateAppSessionVersion.bind(
      assembly.sessionService,
    ),
    validateAppSessionVersion: assembly.sessionService.validateAppSessionVersion.bind(
      assembly.sessionService,
    ),
  };
}

function createD1ThresholdRuntimeRouteService(
  assembly: D1ThresholdRuntimeRouteServiceAssembly,
): CloudflareD1RouterApiAuthService['thresholdRuntime'] {
  return {
    getRouterAbNormalSigningRuntime: assembly.routerAbSigning.getRouterAbNormalSigningRuntime.bind(
      assembly.routerAbSigning,
    ),
    getRouterAbEcdsaPresignRuntime: assembly.routerAbSigning.getRouterAbEcdsaPresignRuntime.bind(
      assembly.routerAbSigning,
    ),
    getRouterAbLocalSigningSeedRuntime:
      assembly.routerAbSigning.getRouterAbLocalSigningSeedRuntime.bind(assembly.routerAbSigning),
  };
}

function createD1NearFundingRouteService(
  assembly: D1NearFundingRouteServiceAssembly,
): RouterApiServiceBag['nearFunding'] {
  return {
    fundImplicitNearAccount: fundImplicitNearAccountForOptions.bind(undefined, assembly.options),
    listNearPublicKeysForUser: assembly.nearPublicKeys.listForRelayUser.bind(
      assembly.nearPublicKeys,
    ),
  };
}

function createD1RecoveryRouteService(
  assembly: D1RecoveryRouteServiceAssembly,
): RouterApiServiceBag['recovery'] {
  return {
    getRecoverySession: assembly.sessionService.getRecoverySession.bind(assembly.sessionService),
    recordRecoveryExecution: assembly.sessionService.recordRecoveryExecution.bind(
      assembly.sessionService,
    ),
    updateRecoverySessionStatus: assembly.sessionService.updateRecoverySessionStatus.bind(
      assembly.sessionService,
    ),
  };
}

function createD1EmailRecoveryAuthService(
  assembly: D1EmailRecoveryAuthServiceAssembly,
): RouterApiEmailRecoveryAuthService {
  return new CloudflareD1EmailRecoveryAuthService(assembly);
}

function createD1RouterAccountRouteService(
  assembly: D1RouterAccountRouteServiceAssembly,
): RouterApiServiceBag['router'] {
  return {
    getConfiguredRelayerAccount: assembly.routerAbSigning.getConfiguredRelayerAccount.bind(
      assembly.routerAbSigning,
    ),
    getRelayerAccount: assembly.routerAbSigning.getRelayerAccount.bind(assembly.routerAbSigning),
  };
}

export function createCloudflareD1RouterApiAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthService {
  const assembly = createCloudflareD1RouterApiAuthAssembly(input);
  return {
    walletRegistration: createD1WalletRegistrationRouteService(assembly),
    walletAuthMethods: createD1WalletAuthMethodRouteService(assembly),
    walletUnlock: createD1WalletUnlockRouteService(assembly),
    emailOtp: createD1EmailOtpRouteService(assembly),
    webAuthn: createD1WebAuthnRouteService(assembly),
    identity: createD1IdentityRouteService(assembly),
    sessionVersions: createD1SessionVersionRouteService(assembly),
    thresholdRuntime: createD1ThresholdRuntimeRouteService(assembly),
    nearFunding: createD1NearFundingRouteService(assembly),
    recovery: createD1RecoveryRouteService(assembly),
    router: createD1RouterAccountRouteService(assembly),
    executeSignedDelegate: assembly.signedDelegateExecutor.execute.bind(
      assembly.signedDelegateExecutor,
    ),
  };
}

export function createCloudflareD1RouterApiEmailRecoveryAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): RouterApiEmailRecoveryAuthService {
  const assembly = createCloudflareD1RouterApiAuthAssembly(input);
  return createD1EmailRecoveryAuthService(assembly);
}
