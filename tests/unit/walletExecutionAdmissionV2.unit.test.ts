import { expect, test } from '@playwright/test';
import {
  buildAuthorizationGrantRef,
  buildEvmEcdsaMpcOperationRef,
  buildNearEd25519MpcOperationRef,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseAuthFactorId,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  buildWalletSessionAuthorizationV2,
  buildActiveWalletSessionQuota,
  buildExactWalletSessionQuotaProjectionV1,
  buildWalletSessionCapabilitySubjectsV1,
  buildAuthorizedOperation,
  parseSessionOrigin,
  parseVerifiedOwnerProofId,
  type WalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import {
  buildVerifiedOwnerProof,
  buildVerifiedWalletSessionPasskeyFactorResult,
} from '../../packages/wallet-server/src/authorization/factorEvidence';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
  parseSigningOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type { AuthorizedOperation } from '../../packages/wallet-server/src/authorization/domain';
import {
  authorizeRouterAbEcdsaDerivationNormalSigningRoute,
  authorizeRouterAbEd25519NormalSigningRoute,
  buildRouterAbEd25519PrivateSigningWorkerBody,
  type RouterAbNormalSigningAdmissionAdapter,
} from '../../packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker';
import {
  resolveWalletSessionAuthorizationV2Admission,
  type WalletSessionAuthorizationV2RequestedOperation,
} from '../../packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission';
import {
  resolveWalletSessionOperationCredentialAdmission,
  validateRouterAbEd25519WalletSessionInputs,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
} from '../../packages/wallet-server/src/router/auth/commonRouterUtils';
import {
  authorizeStrictEcdsaSessionActivationFromOperationCredential,
  handleStrictEcdsaSessionActivation,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa';
import { authenticateDeviceLinkingOwnerWalletSessionRequestV1 } from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type {
  RouterApiAuthorizedOperationService,
  RouterApiAuthorizationSessionService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
  RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext,
  RouterApiWalletRegistrationService,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEd25519YaoExportAuthorizationIdentityV1 } from '@shared/utils/routerAbEd25519Yao';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { buildRouterAbEd25519NearTransactionPrepareRequestV2 } from '../../packages/wallet/src/core/rpcClients/relayer/routerAbNormalSigning';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';

type SignerFamily = 'ed25519' | 'ecdsa_secp256k1' | 'both';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function buildSignerManifest(
  family: SignerFamily,
  walletId: WalletId,
  label: string,
): ReturnType<typeof parseExactAdministeredSignerManifestV1> {
  const ed25519 = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ed25519`,
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(3)),
  };
  const ecdsa = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ecdsa`,
    thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(4)])),
    evmAddress: `0x${'1'.repeat(40)}`,
  };
  switch (family) {
    case 'ed25519':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519'],
        signers: [ed25519],
      });
    case 'ecdsa_secp256k1':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ecdsa_secp256k1'],
        signers: [ecdsa],
      });
    case 'both':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        signers: [ed25519, ecdsa],
      });
  }
}

function buildSignerActivations(family: SignerFamily, walletId: WalletId, label: string) {
  const manifest = buildSignerManifest(family, walletId, label);
  const materialOwner = String(walletId);
  switch (family) {
    case 'ed25519':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
        },
      });
    case 'ecdsa_secp256k1':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
    case 'both':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
  }
}

async function buildAuthority(
  family: SignerFamily,
  label: string,
): Promise<ActiveWalletAuthorityV1> {
  const walletId = required(parseWalletId(`wallet:admission-${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:admission-${label}`));
  const deviceId = required(parseDeviceId(`device:admission-${label}`));
  const signerActivations = buildSignerActivations(family, walletId, label);
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(8))),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    state: 'active',
    activatedAtMs: 100,
  });
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function buildAuthMethod(
  authority: ActiveWalletAuthorityV1,
  label: string,
  status: 'active' | 'revoked',
): WalletAuthMethodRecordV2 {
  const walletAuthMethodId = required(parseWalletAuthMethodId(`passkey:admission-${label}`));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u(`credential:admission-${label}`));
  const common = {
    version: 'wallet_auth_method_v2' as const,
    walletAuthMethodId,
    walletId: authority.walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey' as const,
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
    counter: 0,
    createdAtMs: 200,
    updatedAtMs: 200,
  };
  if (status === 'active') {
    return buildWalletAuthMethodRecordV2({
      ...common,
      status: 'active',
      activatedAtMs: 200,
    });
  }
  return buildWalletAuthMethodRecordV2({
    ...common,
    status: 'revoked',
    activatedAtMs: 200,
    revokedAtMs: 300,
  });
}

async function passkeyAuthorityRefForAuthMethod(
  authMethod: Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey' }>,
) {
  return await walletAuthAuthorityRef({
    authority: {
      walletId: authMethod.walletId,
      factor: { kind: 'passkey', credentialIdB64u: authMethod.credentialIdB64u },
      verifier: { kind: 'webauthn', rpId: authMethod.rpId },
      bindingId: authMethod.walletAuthMethodId,
    },
  });
}

function buildSession(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethodId: WalletAuthMethodId;
  readonly label: string;
  readonly capabilitySubjects: WalletSessionAuthorizationV2['capabilitySubjects'];
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly expiresAtMs: number;
}): WalletSessionAuthorizationV2 {
  return buildWalletSessionAuthorizationV2({
    tenantId: required(parseTenantId(`tenant:admission-${input.label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${input.label}`)),
    walletId: input.authority.walletId,
    authorityId: input.authority.authorityId,
    walletAuthMethodId: input.authMethodId,
    authorityDigestB64u: input.authorityDigestB64u,
    authorityRevocationEpoch: input.authorityRevocationEpoch,
    mintId: required(parseWalletSessionMintId(`mint:admission-${input.label}`)),
    authorizationId: required(
      parseWalletSessionAuthorizationId(`authorization:admission-${input.label}`),
    ),
    walletSessionId: required(parseWalletSessionId(`wallet-session:admission-${input.label}`)),
    quotaId: required(parseMpcWalletSigningQuotaId(`quota:admission-${input.label}`)),
    capabilitySubjects: input.capabilitySubjects,
    createdAtMs: 300,
    expiresAtMs: input.expiresAtMs,
  });
}

async function unsupportedAuthorizationSessionOperation(): Promise<never> {
  throw new Error('authorization session operation is outside this test boundary');
}

async function unsupportedAuthorizedOperationOperation(): Promise<never> {
  throw new Error('authorized operation service operation is outside this test boundary');
}

class WalletSessionAuthorizationV2Fixture implements RouterApiAuthorizationSessionService {
  readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
  statusReads = 0;

  constructor(
    private readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext,
    private readonly expectedToken: string | null = null,
    private readonly exhaustedCandidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext | null = null,
    private readonly activeReadFailure = false,
  ) {
    this.tenantId = context.authorization.session.tenantId;
  }

  readonly readWalletSessionAuthorizationV2ByOperationCredential = async (input: {
    readonly token: string;
  }) => {
    if (this.activeReadFailure) throw new Error('active Wallet Session quota is exhausted');
    return this.expectedToken === null || input.token === this.expectedToken ? this.context : null;
  };

  readonly readExhaustedWalletSessionAuthorizationV2CandidateByOperationCredential = async (input: {
    readonly token: string;
  }) => {
    return this.expectedToken === null || input.token === this.expectedToken
      ? this.exhaustedCandidate
      : null;
  };

  async readExactWalletSessionStatusByOperationCredential(): Promise<never> {
    this.statusReads += 1;
    throw new Error('exact ECDSA activation must use the admitted V2 quota projection');
  }

  async mintHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async redeemHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }
}

class WalletAuthorizedOperationFixture implements RouterApiAuthorizedOperationService {
  readonly tenantId: WalletSessionAuthorizationV2['tenantId'];
  readCalls = 0;
  admitCalls = 0;

  constructor(private readonly operation: AuthorizedOperation) {
    this.tenantId = operation.tenantId;
  }

  async buildVerifiedOwnerProof(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async recordVerifiedWalletOperationFactorEvidenceSet(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }

  async readAuthorizedOperationById(input: {
    readonly authorizedOperationId: AuthorizedOperation['authorizedOperationId'];
  }): Promise<AuthorizedOperation | null> {
    return input.authorizedOperationId === this.operation.authorizedOperationId
      ? this.operation
      : null;
  }

  async readAuthorizedOperation(input: {
    readonly operationFingerprintDigest: AuthorizedOperation['operationFingerprintDigest'];
  }): Promise<AuthorizedOperation | null> {
    this.readCalls += 1;
    return input.operationFingerprintDigest === this.operation.operationFingerprintDigest
      ? this.operation
      : null;
  }

  async admitAuthorizedOperation(input: {
    readonly operation: Parameters<
      RouterApiAuthorizedOperationService['admitAuthorizedOperation']
    >[0]['operation'];
  }): Promise<{ readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }> {
    this.admitCalls += 1;
    return {
      kind: 'operation_in_progress',
      operation: this.operation,
    };
  }

  async completeAuthorizedOperation(): Promise<never> {
    return await unsupportedAuthorizedOperationOperation();
  }
}

test('device-link owner approval requires the exact V2 operation credential', async () => {
  const authority = await buildAuthority('both', 'device-link-owner');
  const authMethod = buildAuthMethod(authority, 'device-link-owner', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'device-link-owner',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 10_000,
  });
  const quota = buildActiveWalletSessionQuota({
    tenantId: session.tenantId,
    principalId: session.principalId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    remainingUses: 3,
    expiresAtMs: session.expiresAtMs,
  });
  const context: RouterApiWalletSessionAuthorizationV2AdmissionContext = {
    authorization: { session, quota },
    authority,
    authMethod,
    retiredAtMs: null,
  };
  const request = new Request('https://wallet.example.test/wallet/device-linking/v1/claim', {
    method: 'POST',
    headers: {
      authorization: 'Bearer exact-device-link-owner',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  const authenticated = await authenticateDeviceLinkingOwnerWalletSessionRequestV1({
    request,
    method: 'POST',
    pathname: '/wallet/device-linking/v1/claim',
    bodyDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(21))),
    requestedAtMs: 500,
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      context,
      'exact-device-link-owner',
    ),
    nowV1: () => 500,
  });
  expect(authenticated.kind).toBe('authorized');
  if (authenticated.kind !== 'authorized') throw new Error(authenticated.message);
  expect(authenticated.owner.walletSessionId).toBe(session.walletSessionId);
  expect(authenticated.owner.authorizationId).toBe(session.authorizationId);

  const missingExact = await authenticateDeviceLinkingOwnerWalletSessionRequestV1({
    request,
    method: 'POST',
    pathname: '/wallet/device-linking/v1/claim',
    bodyDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(21))),
    requestedAtMs: 500,
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(context, 'different-token'),
    nowV1: () => 500,
  });
  expect(missingExact).toEqual({
    kind: 'denied',
    code: 'unauthorized',
    message: 'An exact owner Wallet Session is required',
  });
});

class Ed25519MaterialActivationFixture {
  readonly runtimePolicyScope: RuntimePolicyScope;

  constructor(
    private readonly materialActivation: RouterAbMpcMaterialActivationRefWire,
    private readonly exportIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
    runtimePolicyScope: RuntimePolicyScope = {
      orgId: 'org:admission',
      projectId: 'project:admission',
      envId: 'env:admission',
      signingRootVersion: 'root:admission',
    },
  ) {
    this.runtimePolicyScope = runtimePolicyScope;
  }

  async resolveEd25519MaterialActivation(
    input: Parameters<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>[0],
  ): ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']> {
    return {
      ok: true,
      materialActivation: this.materialActivation,
      nearAccountId: String(input.walletId),
      signerSlot: 1,
      signingWorkerId: this.materialActivation.signing_worker,
      participantIds: [11, 29],
      runtimePolicyScope: this.runtimePolicyScope,
      exportIdentity: this.exportIdentity,
    };
  }
}

class EcdsaMaterialActivationFixture {
  readonly runtimePolicyScope: RuntimePolicyScope;
  calls = 0;

  constructor(
    private readonly materialActivation: RouterAbMpcMaterialActivationRefWire,
    private readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1,
    runtimePolicyScope: RuntimePolicyScope = {
      orgId: 'org:admission',
      projectId: 'project:admission',
      envId: 'env:admission',
      signingRootVersion: 'root:admission',
    },
  ) {
    this.runtimePolicyScope = runtimePolicyScope;
  }

  async resolveEcdsaMaterialActivation(
    _input: Parameters<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>[0],
  ): ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']> {
    this.calls += 1;
    return {
      ok: true,
      materialActivation: this.materialActivation,
      keyHandle: 'key-handle:admission',
      relayerKeyId: 'relayer-key:admission',
      participantIds: [11, 29],
      runtimePolicyScope: this.runtimePolicyScope,
      routerAbEcdsaDerivationNormalSigning: this.normalSigning,
    };
  }
}

class AllowingNormalSigningAdmission implements RouterAbNormalSigningAdmissionAdapter {
  calls = 0;

  async evaluatePolicy(): Promise<{ readonly ok: true }> {
    this.calls += 1;
    return { ok: true };
  }
}

function buildAdmissionContext(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: WalletAuthMethodRecordV2;
  readonly session: WalletSessionAuthorizationV2;
}): RouterApiWalletSessionAuthorizationV2AdmissionContext {
  return {
    authorization: {
      session: input.session,
      quota: buildActiveWalletSessionQuota({
        tenantId: input.session.tenantId,
        principalId: input.session.principalId,
        walletSessionId: input.session.walletSessionId,
        quotaId: input.session.quotaId,
        remainingUses: 3,
        expiresAtMs: input.session.expiresAtMs,
      }),
    },
    authority: input.authority,
    authMethod: input.authMethod,
    retiredAtMs: null,
  };
}

function buildOperation(
  authority: ActiveWalletAuthorityV1,
  label: string,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  operationKind:
    | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)[keyof typeof NEAR_ED25519_MPC_OPERATION_KINDS]
    | (typeof EVM_ECDSA_MPC_OPERATION_KINDS)[keyof typeof EVM_ECDSA_MPC_OPERATION_KINDS],
): WalletSessionAuthorizationV2RequestedOperation {
  const identity = {
    tenantId: required(parseTenantId(`tenant:admission-${label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${label}`)),
    walletId: authority.walletId,
  };
  if (keyFamily === 'ed25519') {
    if (
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.exportKey
    ) {
      throw new Error('Ed25519 operation kind is invalid');
    }
    return { ...identity, keyFamily, operationKind };
  }
  if (
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction &&
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.exportKey
  ) {
    throw new Error('ECDSA operation kind is invalid');
  }
  return { ...identity, keyFamily, operationKind };
}

function buildEd25519ExportIdentityFixture(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  walletId: WalletId,
): RouterAbEd25519YaoExportAuthorizationIdentityV1 {
  return {
    scope: {
      lifecycle_id: 'lifecycle:admission-ed25519',
      root_share_epoch: 'epoch:admission-ed25519',
      account_id: String(walletId),
      threshold_session_id: 'threshold-session:admission-ed25519',
      signer_set_id: 'signer-set:admission-ed25519',
      signing_worker_id: materialActivation.signing_worker,
      material_activation: materialActivation,
    },
    application_binding: {
      wallet_id: String(walletId),
      near_ed25519_signing_key_id: 'near-key:admission-ed25519',
      signing_root_id: 'signing-root:admission-ed25519',
      key_creation_signer_slot: 1,
    },
    participant_ids: [11, 29],
    registered_public_key: new Array<number>(32).fill(3),
    state_epoch: 1,
    runtime_policy_binding: new Array<number>(32).fill(4),
  };
}

function buildEcdsaNormalSigningStateFixture(
  materialActivation: RouterAbMpcMaterialActivationRefWire,
  walletId: WalletId,
  label: string,
  signerIdentity?: {
    readonly thresholdPublicKey33B64u: string;
    readonly ethereumAddress20B64u: string;
  },
): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(walletId),
      ecdsa_threshold_key_id: `ecdsa-threshold-key:admission-${label}`,
      signing_root_id: `signing-root:admission-${label}`,
      signing_root_version: `signing-root-version:admission-${label}`,
      context: {
        application_binding_digest_b64u: parseDigestB64u(
          base64UrlEncode(new Uint8Array(32).fill(21)),
        ),
      },
      public_identity: {
        context_binding_b64u: base64UrlEncode(new Uint8Array(32).fill(22)),
        derivation_client_share_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...new Uint8Array(32).fill(23)]),
        ),
        server_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...new Uint8Array(32).fill(24)]),
        ),
        threshold_public_key33_b64u:
          signerIdentity?.thresholdPublicKey33B64u ??
          base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(25)])),
        ethereum_address20_b64u:
          signerIdentity?.ethereumAddress20B64u ?? base64UrlEncode(new Uint8Array(20).fill(26)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: materialActivation,
      signing_worker: {
        server_id: materialActivation.signing_worker,
        key_epoch: `key-epoch:admission-${label}`,
        recipient_encryption_key: `x25519:${'27'.repeat(32)}`,
      },
      activation_epoch: `activation-epoch:admission-${label}`,
    },
  };
}

function buildEcdsaNormalSigningRequestFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly label: string;
  readonly authorization?:
    | { readonly kind: 'reusable_wallet_session'; readonly wallet_session_id: string }
    | { readonly kind: 'operation_step_up' };
}): ReturnType<typeof buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
  const signingDigest32 = new Uint8Array(32).fill(11);
  return buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: input.normalSigning.scope,
    requestId: `request:admission-${input.label}`,
    operationId: `operation:admission-${input.label}`,
    operationDigests: {
      lane_digest_b64u: base64UrlEncode(new Uint8Array(32).fill(10)),
      intent_digest_b64u: base64UrlEncode(signingDigest32),
      display_digest_b64u: base64UrlEncode(new Uint8Array(32).fill(12)),
    },
    authorization:
      input.authorization ??
      ({
        kind: 'reusable_wallet_session',
        wallet_session_id: String(input.session.walletSessionId),
      } as const),
    materialActivation: input.materialActivation,
    clientPresignatureId: `presignature:admission-${input.label}`,
    expiresAtMs: Date.now() + 30_000,
    signingDigest32,
    clientRerandomizationCommitment32: new Uint8Array(32).fill(13),
  });
}

function ecdsaAddress20B64u(address: string): string {
  return base64UrlEncode(Uint8Array.from(Buffer.from(address.slice(2), 'hex')));
}

async function buildEcdsaVerifiedStepUpOperationFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly body: ReturnType<typeof buildEcdsaNormalSigningRequestFixture>;
}): Promise<AuthorizedOperation> {
  const operation = buildCapabilityOperationEnvelope({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    capabilityId: required(parseCapabilityId(input.materialActivation.capability)),
    operationId: required(parseCapabilityOperationId(input.body.operation_id)),
    operation: buildEvmEcdsaMpcOperationRef(EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction),
    digests: {
      laneDigest: parseDigestB64u(input.body.operation_digests.lane_digest_b64u),
      intentDigest: parseDigestB64u(input.body.operation_digests.intent_digest_b64u),
      displayDigest: parseDigestB64u(input.body.operation_digests.display_digest_b64u),
    },
  });
  return await buildAuthorizedOperation({
    tenantId: input.session.tenantId,
    authorizedOperationId: required(
      parseAuthorizedOperationId(`ecdsa-step-up-authorized-operation:${input.body.operation_id}`),
    ),
    auditEventId: required(
      parseAuthorizationAuditEventId(`ecdsa-step-up-audit:${input.body.operation_id}`),
    ),
    operation,
    authorization: {
      kind: 'verified_step_up',
      evidenceSetDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(13))),
    },
    quota: { kind: 'quota_neutral' },
    claimedAtMs: Date.now(),
  });
}

async function buildEd25519AuthorizedOperationFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}): Promise<AuthorizedOperation> {
  const operation: CapabilityOperationEnvelope = buildCapabilityOperationEnvelope({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    capabilityId: required(parseCapabilityId(input.materialActivation.capability)),
    operationId: required(parseCapabilityOperationId('operation:admission-ed25519')),
    operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
    digests: {
      laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
      intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(11))),
      displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(12))),
    },
  });
  return await buildAuthorizedOperation({
    tenantId: input.session.tenantId,
    authorizedOperationId: required(
      parseAuthorizedOperationId('authorized-operation:admission-ed25519'),
    ),
    auditEventId: required(parseAuthorizationAuditEventId('audit:admission-ed25519')),
    operation,
    authorization: {
      kind: 'authorization_grant',
      authorizationGrantRef: buildAuthorizationGrantRef(input.session.authorizationId),
    },
    quota: {
      kind: 'consume_reusable_wallet_session',
      quotaId: input.session.quotaId,
    },
    claimedAtMs: Date.now(),
  });
}

async function buildEd25519OperationStepUpPrepareRequestFixture(input: {
  readonly walletId: WalletId;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly requestId: string;
  readonly operationId: string;
  readonly expiresAtMs: number;
}) {
  return (
    await buildRouterAbEd25519NearTransactionPrepareRequestV2({
      scope: {
        request_id: input.requestId,
        account_id: String(input.walletId),
        authorization: { kind: 'operation_step_up' },
        material_activation: input.materialActivation,
        signing_worker_id: input.materialActivation.signing_worker,
      },
      expiresAtMs: input.expiresAtMs,
      operationId: input.operationId,
      operationFingerprint: `sha256:${base64UrlEncode(new Uint8Array(32).fill(10))}`,
      displayDigestB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
      nearAccountId: 'alice.testnet',
      nearNetworkId: 'testnet',
      transactions: [{ receiverId: 'receiver.testnet', actionFingerprint: 'action' }],
      unsignedTransactionBorshB64u: 'AQID',
      expectedSigningDigestB64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
    })
  ).request;
}

async function buildEd25519VerifiedStepUpOperationFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly body: Awaited<ReturnType<typeof buildEd25519OperationStepUpPrepareRequestFixture>>;
  readonly runtimePolicyScope: RuntimePolicyScope;
}): Promise<AuthorizedOperation> {
  const privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
    phase: 'prepare',
    body: input.body,
    authorization: {
      kind: 'operation_step_up',
      session: {
        tenantId: input.session.tenantId,
        principalId: input.session.principalId,
        sessionId: String(input.session.authorizationId),
        walletId: String(input.session.walletId),
        runtimePolicyScope: input.runtimePolicyScope,
        laneAuthorization: {
          kind: 'wallet_auth_method',
          walletAuthMethodId: input.session.walletAuthMethodId,
        },
      },
    },
    headers: { origin: 'https://wallet.example.test' },
  });
  if (!('admission_candidate' in privateBody)) {
    throw new Error('Ed25519 step-up fixture admission candidate is missing');
  }
  const operationId = required(parseCapabilityOperationId(input.body.intent.operation_id));
  const operation = buildCapabilityOperationEnvelope({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    capabilityId: required(parseCapabilityId(input.materialActivation.capability)),
    operationId,
    operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
    digests: {
      laneDigest: parseSigningOperationFingerprintDigest(input.body.intent.operation_fingerprint),
      intentDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
      ),
      displayDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(input.body.display_digest.bytes)),
      ),
    },
  });
  return await buildAuthorizedOperation({
    tenantId: input.session.tenantId,
    authorizedOperationId: required(
      parseAuthorizedOperationId(`normal-signing-operation:${input.body.scope.request_id}`),
    ),
    auditEventId: required(
      parseAuthorizationAuditEventId(`normal-signing-audit:${input.body.scope.request_id}`),
    ),
    operation,
    authorization: {
      kind: 'verified_step_up',
      evidenceSetDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(13))),
    },
    quota: { kind: 'quota_neutral' },
    claimedAtMs: Date.now(),
  });
}

function verifiedStepUpAuthorizedOperationReceiptFixture(
  operation: AuthorizedOperation,
  session: WalletSessionAuthorizationV2,
): Record<string, unknown> {
  if (operation.authorization.kind !== 'verified_step_up') {
    throw new Error('Ed25519 step-up fixture operation has the wrong authorization');
  }
  return {
    kind: 'verified_step_up_authorized_operation_v1',
    authorization_session_id: String(session.authorizationId),
    evidence_set_digest: String(operation.authorization.evidenceSetDigest),
    authorized_operation_id: String(operation.authorizedOperationId),
    operation_id: String(operation.operation.operationId),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operation.operation.operation.operationKind,
    lane_digest_b64u: String(operation.operation.digests.laneDigest),
    intent_digest_b64u: String(operation.operation.digests.intentDigest),
    display_digest_b64u: String(operation.operation.digests.displayDigest),
    operation_fingerprint_digest: String(operation.operationFingerprintDigest),
  };
}

function authorizedOperationReceiptFixture(
  operation: AuthorizedOperation,
): Record<string, unknown> {
  return {
    kind: 'reusable_wallet_session_authorized_operation_v1',
    authorized_operation_id: String(operation.authorizedOperationId),
    operation_id: String(operation.operation.operationId),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operation.operation.operation.operationKind,
    lane_digest_b64u: String(operation.operation.digests.laneDigest),
    intent_digest_b64u: String(operation.operation.digests.intentDigest),
    display_digest_b64u: String(operation.operation.digests.displayDigest),
    operation_fingerprint_digest: String(operation.operationFingerprintDigest),
  };
}

function ed25519V2FinalizeBodyFixture(input: {
  readonly session: WalletSessionAuthorizationV2;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly receipt: Record<string, unknown>;
  readonly expiresAtMs: number;
}): Record<string, unknown> {
  return {
    scope: {
      request_id: 'request:admission-ed25519-finalize',
      account_id: String(input.session.walletId),
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: String(input.session.walletSessionId),
      },
      material_activation: input.materialActivation,
      signing_worker_id: input.materialActivation.signing_worker,
    },
    expires_at_ms: input.expiresAtMs,
    authorized_operation: input.receipt,
    prepare_binding: {
      intent_digest: { bytes: new Array<number>(32).fill(11) },
    },
  };
}

test('admits exact Ed25519 and ECDSA Wallet Session V2 provenance', async () => {
  const authority = await buildAuthority('both', 'valid');
  const authMethod = buildAuthMethod(authority, 'valid', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'valid',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  const edAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ed25519',
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });
  const ecdsaAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ecdsa_secp256k1',
      EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });

  if (!edAdmission.ok || !ecdsaAdmission.ok) {
    throw new Error('valid signer admission was refused');
  }
  expect(edAdmission.keyFamily).toBe('ed25519');
  expect(edAdmission.operationKind).toBe(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
  expect(ecdsaAdmission.keyFamily).toBe('ecdsa_secp256k1');
  expect(ecdsaAdmission.operationKind).toBe(EVM_ECDSA_MPC_OPERATION_KINDS.exportKey);
  expect(edAdmission.walletKeyId).toBe(authority.signerActivations.ed25519.signer.walletKeyId);
  expect(ecdsaAdmission.walletKeyId).toBe(authority.signerActivations.ecdsa.signer.walletKeyId);

  const operationCredentialService = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'wst_shared-primary-credential',
  );
  const [edOperationAdmission, ecdsaOperationAdmission] = await Promise.all([
    resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: operationCredentialService,
      token: 'wst_shared-primary-credential',
      nowMs: 500,
      operation: {
        keyFamily: 'ed25519',
        operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
      },
    }),
    resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: operationCredentialService,
      token: 'wst_shared-primary-credential',
      nowMs: 500,
      operation: {
        keyFamily: 'ecdsa_secp256k1',
        operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
      },
    }),
  ]);
  if (edOperationAdmission.kind !== 'admitted' || ecdsaOperationAdmission.kind !== 'admitted') {
    throw new Error('shared primary Wallet Session credential was not admitted for both signers');
  }
  expect(edOperationAdmission.admission.curve).toBe('ed25519');
  expect(ecdsaOperationAdmission.admission.curve).toBe('ecdsa');
  expect(edOperationAdmission.admission.context.authorization.session.authorizationId).toBe(
    ecdsaOperationAdmission.admission.context.authorization.session.authorizationId,
  );
  expect(edOperationAdmission.admission.context.authorization.session.walletSessionId).toBe(
    ecdsaOperationAdmission.admission.context.authorization.session.walletSessionId,
  );
});

test('authorizes ECDSA activation from the shared exact operation credential', async () => {
  const authority = await buildAuthority('both', 'activation');
  const authMethod = buildAuthMethod(authority, 'activation', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'activation',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const operationCredentialService = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'wst_shared-activation-credential',
  );
  if (authMethod.kind !== 'passkey') throw new Error('Passkey auth method fixture is required');
  const authorityRef = await passkeyAuthorityRefForAuthMethod(authMethod);
  const proof = await buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId('proof:ecdsa-activation'),
    factor: buildVerifiedWalletSessionPasskeyFactorResult({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      authorityRef,
      requestOrigin: parseSessionOrigin('https://wallet.example.test'),
      audience: parseSessionOrigin('https://wallet.example.test'),
      factorId: required(parseAuthFactorId('factor:ecdsa-activation')),
      verifiedAtMs: 400,
      expiresAtMs: 900,
      credentialIdB64u: authMethod.credentialIdB64u,
      assertionDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(28))),
    }),
  });
  const operationCredential = {
    kind: 'opaque_wallet_session_operation_credential_v1' as const,
    token: 'wst_shared-activation-credential',
    walletSessionId: session.walletSessionId,
  };

  const admission = await authorizeStrictEcdsaSessionActivationFromOperationCredential({
    authorizationSessions: operationCredentialService,
    walletId: String(session.walletId),
    operationCredential,
    proof,
  });

  if (!admission.ok) throw new Error('shared exact operation credential was refused');
  expect(admission.kind).toBe('wallet_session_operation_credential_v1');
  expect(admission.admission.curve).toBe('ecdsa');
  expect(admission.admission.context.authorization.session.authorizationId).toBe(
    session.authorizationId,
  );
  expect(admission.admission.context.authorization.session.walletSessionId).toBe(
    operationCredential.walletSessionId,
  );
  expect(operationCredentialService.statusReads).toBe(0);

  const foreignAuthMethod = buildAuthMethod(authority, 'activation-foreign-method', 'active');
  if (foreignAuthMethod.kind !== 'passkey') {
    throw new Error('Foreign Passkey auth method fixture is required');
  }
  const foreignAuthorityRef = await passkeyAuthorityRefForAuthMethod(foreignAuthMethod);
  const foreignMethodProof = await buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId('proof:ecdsa-activation-foreign-method'),
    factor: buildVerifiedWalletSessionPasskeyFactorResult({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      authorityRef: foreignAuthorityRef,
      requestOrigin: parseSessionOrigin('https://wallet.example.test'),
      audience: parseSessionOrigin('https://wallet.example.test'),
      factorId: required(parseAuthFactorId('factor:ecdsa-activation-foreign-method')),
      verifiedAtMs: 400,
      expiresAtMs: 900,
      credentialIdB64u: foreignAuthMethod.credentialIdB64u,
      assertionDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(29))),
    }),
  });
  const foreignMethodAdmission = await authorizeStrictEcdsaSessionActivationFromOperationCredential(
    {
      authorizationSessions: operationCredentialService,
      walletId: String(session.walletId),
      operationCredential,
      proof: foreignMethodProof,
    },
  );
  expect(foreignMethodAdmission).toMatchObject({
    ok: false,
    code: 'wallet_session_scope_mismatch',
  });
});

test('rejects an ECDSA activation whose mint differs from the exact Wallet Session', async () => {
  const authority = await buildAuthority('both', 'activation-mint');
  const authMethod = buildAuthMethod(authority, 'activation-mint', 'active');
  if (authMethod.kind !== 'passkey') throw new Error('Passkey auth method fixture is required');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'activation-mint',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const operationCredentialService = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'wst_shared-activation-mint-credential',
  );
  const authorityRef = await passkeyAuthorityRefForAuthMethod(authMethod);
  const proof = await buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId('proof:ecdsa-activation-mint'),
    factor: buildVerifiedWalletSessionPasskeyFactorResult({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      authorityRef,
      requestOrigin: parseSessionOrigin('https://wallet.example.test'),
      audience: parseSessionOrigin('https://wallet.example.test'),
      factorId: required(parseAuthFactorId('factor:ecdsa-activation-mint')),
      verifiedAtMs: 400,
      expiresAtMs: 900,
      credentialIdB64u: authMethod.credentialIdB64u,
      assertionDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(30))),
    }),
  });
  const activationFixture = createEcdsaSessionActivationFixture({
    walletId: String(session.walletId),
    chain: 'ethereum',
  });
  const ecdsaActivation = authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('Combined authority fixture requires ECDSA activation');
  const request = parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1({
    ...activationFixture.request,
    public_capability: {
      ...activationFixture.request.public_capability,
      material_activation: routerAbMpcMaterialActivationRefToWire(
        ecdsaActivation.materialActivation,
      ),
    },
    session_policy: {
      ...activationFixture.request.session_policy,
      wallet_session_mint_id: 'mint:wrong-activation',
      remaining_uses: 3,
    },
  });
  const ctx = {
    service: {
      authorizationSessions: operationCredentialService,
      walletRegistration: {
        activateEcdsaPostRegistrationSession: async () => {
          throw new Error('wrong mint must fail before ECDSA activation');
        },
      },
    },
  } as unknown as FetchRouterApiContext;
  const response = await handleStrictEcdsaSessionActivation({
    ctx,
    body: request,
    source: 'wallet_session_operation_credential_v1',
    operationCredential: {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: 'wst_shared-activation-mint-credential',
      walletSessionId: session.walletSessionId,
    },
    proof,
  });

  expect(response.status).toBe(403);
  expect(await response.json()).toMatchObject({
    ok: false,
    code: 'wallet_session_scope_mismatch',
  });
});

test('rejects provenance drift, retirement, expiry, subject drift, and missing signer family', async () => {
  const authority = await buildAuthority('both', 'reject');
  const authMethod = buildAuthMethod(authority, 'reject', 'active');
  const subjects = buildWalletSessionCapabilitySubjectsV1(authority);
  const operation = buildOperation(
    authority,
    'reject',
    'ed25519',
    NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  );
  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const epochDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch + 1,
    expiresAtMs: 1_000,
  });
  const expired = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const foreignAuthority = await buildAuthority('both', 'foreign-subject');
  const subjectDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(foreignAuthority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: digestDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_digest_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: epochDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_revocation_epoch_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: expired,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authorization_expired' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: subjectDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'capability_subject_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: buildSession({
        authority,
        authMethodId: authMethod.walletAuthMethodId,
        label: 'reject',
        capabilitySubjects: subjects,
        authorityDigestB64u: authority.authorityDigestB64u,
        authorityRevocationEpoch: authority.revocationEpoch,
        expiresAtMs: 1_000,
      }),
      authority,
      authMethod: buildAuthMethod(authority, 'reject', 'revoked'),
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'auth_method_inactive' });

  const edOnlyAuthority = await buildAuthority('ed25519', 'missing-family');
  const edOnlyMethod = buildAuthMethod(edOnlyAuthority, 'missing-family', 'active');
  const edOnlySession = buildSession({
    authority: edOnlyAuthority,
    authMethodId: edOnlyMethod.walletAuthMethodId,
    label: 'missing-family',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(edOnlyAuthority),
    authorityDigestB64u: edOnlyAuthority.authorityDigestB64u,
    authorityRevocationEpoch: edOnlyAuthority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: edOnlySession,
      authority: edOnlyAuthority,
      authMethod: edOnlyMethod,
      operation: buildOperation(
        edOnlyAuthority,
        'missing-family',
        'ecdsa_secp256k1',
        EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
      ),
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'signer_family_mismatch' });
});

test('ordinary ECDSA admission consumes exact V2 credentials and rejects active-state drift', async () => {
  const authority = await buildAuthority('ecdsa_secp256k1', 'route-bridge');
  const authMethod = buildAuthMethod(authority, 'route-bridge', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const service = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admitted = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: service,
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.context.authorization.session.walletSessionId).toBe(session.walletSessionId);
    expect(admitted.admission.admission.operationKind).toBe(
      EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const rejectedDigest = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: digestDrift }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedDigest).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const rejectedAuthMethod = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({
        authority,
        authMethod: buildAuthMethod(authority, 'route-bridge', 'revoked'),
        session,
      }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedAuthMethod).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const expiredSession = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const rejectedExpiry = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: expiredSession }),
    ),
    nowMs: () => 500,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedExpiry).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });
});

test('ordinary ECDSA V2 admission rejects exact normal-signing scope drift before downstream admission', async () => {
  const authority = await buildAuthority('ecdsa_secp256k1', 'normal-scope');
  const authMethod = buildAuthMethod(authority, 'normal-scope', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'normal-scope',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    authority.signerActivations.ecdsa.materialActivation,
  );
  const normalSigning = buildEcdsaNormalSigningStateFixture(
    materialActivation,
    authority.walletId,
    'normal-scope',
  );
  const materialResolver = new EcdsaMaterialActivationFixture(materialActivation, normalSigning);
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admissionAdapter = new AllowingNormalSigningAdmission();
  const body = buildEcdsaNormalSigningRequestFixture({
    session,
    normalSigning,
    materialActivation,
    label: 'normal-scope',
  });

  const admitted = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body,
    rawBody: body,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations: null,
    authorizationSessions,
    admissionAdapter,
    resolveEcdsaMaterialActivation:
      materialResolver.resolveEcdsaMaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });
  expect(admitted).toMatchObject({
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
  });
  expect(admissionAdapter.calls).toBe(1);

  const driftedBody = {
    ...body,
    scope: {
      ...body.scope,
      signing_root_version: `${body.scope.signing_root_version}-drift`,
    },
  };
  const rejected = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body: driftedBody,
    rawBody: driftedBody,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations: null,
    authorizationSessions,
    admissionAdapter,
    resolveEcdsaMaterialActivation:
      materialResolver.resolveEcdsaMaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });
  expect(rejected).toMatchObject({
    ok: false,
    result: {
      status: 403,
      body: {
        ok: false,
        code: 'wallet_session_scope_mismatch',
      },
    },
  });
  expect(materialResolver.calls).toBe(2);
  expect(admissionAdapter.calls).toBe(1);
});

test('ordinary Ed25519 admission consumes exact V2 credentials and rejects active-state drift', async () => {
  const authority = await buildAuthority('ed25519', 'near-route-bridge');
  const authMethod = buildAuthMethod(authority, 'near-route-bridge', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const service = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const admitted = await validateRouterAbEd25519WalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: service,
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.context.authorization.session.walletSessionId).toBe(session.walletSessionId);
    expect(admitted.admission.admission.operationKind).toBe(
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const rejectedDigest = await validateRouterAbEd25519WalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: digestDrift }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedDigest).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const rejectedAuthMethod = await validateRouterAbEd25519WalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({
        authority,
        authMethod: buildAuthMethod(authority, 'near-route-bridge', 'revoked'),
        session,
      }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedAuthMethod).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });

  const expiredSession = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-route-bridge',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const rejectedExpiry = await validateRouterAbEd25519WalletSessionInputs({
    body: {},
    headers: { authorization: 'Bearer exact-v2-token' },
    authorizationSessions: new WalletSessionAuthorizationV2Fixture(
      buildAdmissionContext({ authority, authMethod, session: expiredSession }),
    ),
    nowMs: () => 500,
    operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  });
  expect(rejectedExpiry).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: expect.any(String),
  });
});

test('ordinary signing validators reject missing exact state without V1 token fallback', async () => {
  const authority = await buildAuthority('both', 'exact-only-validator');
  const authMethod = buildAuthMethod(authority, 'exact-only-validator', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'exact-only-validator',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const service = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'different-exact-credential',
  );

  const [ed25519, ecdsa] = await Promise.all([
    validateRouterAbEd25519WalletSessionInputs({
      body: {},
      headers: { authorization: 'Bearer retired-v1-token' },
      authorizationSessions: service,
      nowMs: () => 500,
      operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    }),
    validateRouterAbEcdsaDerivationWalletSessionInputs({
      body: {},
      headers: { authorization: 'Bearer retired-v1-token' },
      authorizationSessions: service,
      nowMs: () => 500,
      operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
    }),
  ]);

  expect(ed25519).toEqual({
    ok: false,
    code: 'wallet_session_invalid',
    message: expect.any(String),
  });
  expect(ecdsa).toEqual({
    ok: false,
    code: 'wallet_session_invalid',
    message: expect.any(String),
  });
});

test('strict Ed25519 V2 finalize admits the exact receipt operation and rejects drift', async () => {
  const authority = await buildAuthority('ed25519', 'finalize-route');
  const authMethod = buildAuthMethod(authority, 'finalize-route', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'finalize-route',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    authority.signerActivations.ed25519.materialActivation,
  );
  const authorizedOperation = await buildEd25519AuthorizedOperationFixture({
    session,
    materialActivation,
  });
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
  );
  const authorizedOperations = new WalletAuthorizedOperationFixture(authorizedOperation);
  const materialResolver = new Ed25519MaterialActivationFixture(
    materialActivation,
    buildEd25519ExportIdentityFixture(materialActivation, authority.walletId),
  );
  const admissionAdapter = new AllowingNormalSigningAdmission();
  const expiresAtMs = Date.now() + 30_000;
  const receipt = authorizedOperationReceiptFixture(authorizedOperation);
  const body = ed25519V2FinalizeBodyFixture({
    session,
    materialActivation,
    receipt,
    expiresAtMs,
  });

  const admitted = await authorizeRouterAbEd25519NormalSigningRoute({
    body,
    rawBody: body,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(admitted.ok).toBe(true);
  if (admitted.ok) {
    expect(admitted.kind).toBe('wallet_session_operation_credential_v1');
    expect(admitted.validated.admission.admission.operationKind).toBe(
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    );
  }

  const wrongOperationBody = ed25519V2FinalizeBodyFixture({
    session,
    materialActivation,
    receipt: {
      ...receipt,
      operation_kind: NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction,
    },
    expiresAtMs,
  });
  const rejected = await authorizeRouterAbEd25519NormalSigningRoute({
    body: wrongOperationBody,
    rawBody: wrongOperationBody,
    headers: { authorization: 'Bearer exact-v2-token' },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(rejected).toMatchObject({
    ok: false,
    result: {
      status: 400,
      body: { ok: false, code: 'invalid_authorized_operation' },
    },
  });
  expect(admissionAdapter.calls).toBe(1);
});

test('Ed25519 operation step-up admits a matching exhausted Wallet Session candidate', async () => {
  const authority = await buildAuthority('ed25519', 'near-exhausted-step-up');
  const authMethod = buildAuthMethod(authority, 'near-exhausted-step-up', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'near-exhausted-step-up',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext = {
    status: {
      kind: 'exhausted',
      session,
      quota: buildExactWalletSessionQuotaProjectionV1({
        lifecycle: 'exhausted',
        tenantId: session.tenantId,
        principalId: session.principalId,
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
        remainingUses: 0,
        expiresAtMs: session.expiresAtMs,
      }),
    },
    authority,
    authMethod,
    retiredAtMs: null,
  };
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    authority.signerActivations.ed25519.materialActivation,
  );
  const materialResolver = new Ed25519MaterialActivationFixture(
    materialActivation,
    buildEd25519ExportIdentityFixture(materialActivation, authority.walletId),
    {
      orgId: String(session.tenantId),
      projectId: 'project:admission-near-exhausted-step-up',
      envId: 'env:admission-near-exhausted-step-up',
      signingRootVersion: 'root:admission-near-exhausted-step-up',
    },
  );
  const body = await buildEd25519OperationStepUpPrepareRequestFixture({
    walletId: authority.walletId,
    materialActivation,
    requestId: 'near-exhausted-step-up',
    operationId: 'operation:near-exhausted-step-up',
    expiresAtMs: session.expiresAtMs - 1_000,
  });
  const authorizedOperation = await buildEd25519VerifiedStepUpOperationFixture({
    session,
    materialActivation,
    body,
    runtimePolicyScope: materialResolver.runtimePolicyScope,
  });
  const authorizedOperations = new WalletAuthorizedOperationFixture(authorizedOperation);
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'exhausted-near-step-up-token',
    candidate,
    true,
  );

  const admitted = await authorizeRouterAbEd25519NormalSigningRoute({
    body,
    rawBody: body,
    headers: {
      authorization: 'Bearer exhausted-near-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter: null,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });

  expect(admitted).toMatchObject({
    ok: true,
    kind: 'operation_step_up',
    phase: 'prepare',
    admissionKind: 'operation_in_progress',
  });
  if (!admitted.ok || admitted.kind !== 'operation_step_up') {
    throw new Error('exhausted candidate was not admitted');
  }
  expect(admitted.session.sessionId).toBe(String(session.authorizationId));
  expect(admitted.operation.authorization.kind).toBe('verified_step_up');
  expect(admitted.operation.quota.kind).toBe('quota_neutral');
  expect(admitted.operation.authorizedOperationId).toBe(authorizedOperation.authorizedOperationId);
  expect(authorizedOperations.readCalls).toBe(1);
  expect(authorizedOperations.admitCalls).toBe(1);
  expect(authorizationSessions.statusReads).toBe(0);

  const finalizeBody = {
    scope: body.scope,
    expires_at_ms: session.expiresAtMs - 1_000,
    authorized_operation: verifiedStepUpAuthorizedOperationReceiptFixture(
      authorizedOperation,
      session,
    ),
    prepare_binding: {
      intent_digest: { bytes: new Array<number>(32).fill(11) },
    },
  };
  const finalized = await authorizeRouterAbEd25519NormalSigningRoute({
    body: finalizeBody,
    rawBody: finalizeBody,
    headers: {
      authorization: 'Bearer exhausted-near-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter: null,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(finalized).toMatchObject({
    ok: true,
    kind: 'operation_step_up',
    phase: 'finalize',
    session: { sessionId: String(session.authorizationId) },
  });

  const driftedReceiptBody = {
    ...finalizeBody,
    authorized_operation: {
      ...finalizeBody.authorized_operation,
      kind: 'reusable_wallet_session_authorized_operation_v1',
    },
  };
  const driftedReceipt = await authorizeRouterAbEd25519NormalSigningRoute({
    body: driftedReceiptBody,
    rawBody: driftedReceiptBody,
    headers: {
      authorization: 'Bearer exhausted-near-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter: null,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(driftedReceipt).toMatchObject({
    ok: false,
    result: {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 verified step-up authorized operation is required',
      },
    },
  });

  const missingReceiptBody = { ...finalizeBody, authorized_operation: undefined };
  const missingReceipt = await authorizeRouterAbEd25519NormalSigningRoute({
    body: missingReceiptBody,
    rawBody: missingReceiptBody,
    headers: {
      authorization: 'Bearer exhausted-near-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter: null,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'finalize',
  });
  expect(missingReceipt).toMatchObject({
    ok: false,
    result: {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 verified step-up authorized operation is required',
      },
    },
  });

  const unpreclaimedBody = await buildEd25519OperationStepUpPrepareRequestFixture({
    walletId: authority.walletId,
    materialActivation,
    requestId: 'unpreclaimed-near-exhausted-step-up',
    operationId: 'operation:unpreclaimed-near-exhausted-step-up',
    expiresAtMs: session.expiresAtMs - 1_000,
  });
  const unpreclaimedOperation = await buildEd25519VerifiedStepUpOperationFixture({
    session,
    materialActivation,
    body: unpreclaimedBody,
    runtimePolicyScope: materialResolver.runtimePolicyScope,
  });
  const unpreclaimedAuthorizedOperations = new WalletAuthorizedOperationFixture(
    unpreclaimedOperation,
  );
  const missingPreclaim = await authorizeRouterAbEd25519NormalSigningRoute({
    body,
    rawBody: body,
    headers: {
      authorization: 'Bearer exhausted-near-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations: unpreclaimedAuthorizedOperations,
    authorizationSessions,
    admissionAdapter: null,
    resolveEd25519MaterialActivation:
      materialResolver.resolveEd25519MaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });
  expect(missingPreclaim).toMatchObject({
    ok: false,
    result: {
      status: 409,
      body: { ok: false, code: 'authorized_operation_missing' },
    },
  });
  expect(unpreclaimedAuthorizedOperations.readCalls).toBe(1);
  expect(unpreclaimedAuthorizedOperations.admitCalls).toBe(0);
});

test('ECDSA operation step-up admits a matching exhausted Wallet Session candidate', async () => {
  const authority = await buildAuthority('ecdsa_secp256k1', 'ecdsa-exhausted-step-up');
  const authMethod = buildAuthMethod(authority, 'ecdsa-exhausted-step-up', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'ecdsa-exhausted-step-up',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: Date.now() + 60_000,
  });
  const candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext = {
    status: {
      kind: 'exhausted',
      session,
      quota: buildExactWalletSessionQuotaProjectionV1({
        lifecycle: 'exhausted',
        tenantId: session.tenantId,
        principalId: session.principalId,
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
        remainingUses: 0,
        expiresAtMs: session.expiresAtMs,
      }),
    },
    authority,
    authMethod,
    retiredAtMs: null,
  };
  const ecdsaActivation = authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('ECDSA exhausted-session fixture is missing its signer');
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    ecdsaActivation.materialActivation,
  );
  const normalSigning = buildEcdsaNormalSigningStateFixture(
    materialActivation,
    authority.walletId,
    'ecdsa-exhausted-step-up',
    {
      thresholdPublicKey33B64u: ecdsaActivation.signer.thresholdPublicKey33B64u,
      ethereumAddress20B64u: ecdsaAddress20B64u(ecdsaActivation.signer.evmAddress),
    },
  );
  const materialResolver = new EcdsaMaterialActivationFixture(materialActivation, normalSigning, {
    orgId: String(session.tenantId),
    projectId: 'project:admission-ecdsa-exhausted-step-up',
    envId: 'env:admission-ecdsa-exhausted-step-up',
    signingRootVersion: 'root:admission-ecdsa-exhausted-step-up',
  });
  const body = buildEcdsaNormalSigningRequestFixture({
    session,
    normalSigning,
    materialActivation,
    label: 'ecdsa-exhausted-step-up',
    authorization: { kind: 'operation_step_up' },
  });
  const authorizedOperation = await buildEcdsaVerifiedStepUpOperationFixture({
    session,
    materialActivation,
    body,
  });
  const authorizedOperations = new WalletAuthorizedOperationFixture(authorizedOperation);
  const authorizationSessions = new WalletSessionAuthorizationV2Fixture(
    buildAdmissionContext({ authority, authMethod, session }),
    'exhausted-ecdsa-step-up-token',
    candidate,
    true,
  );
  const admissionAdapter = new AllowingNormalSigningAdmission();

  const admitted = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body,
    rawBody: body,
    headers: {
      authorization: 'Bearer exhausted-ecdsa-step-up-token',
      origin: 'https://wallet.example.test',
    },
    session: null,
    authorizedOperations,
    authorizationSessions,
    admissionAdapter,
    resolveEcdsaMaterialActivation:
      materialResolver.resolveEcdsaMaterialActivation.bind(materialResolver),
    phase: 'prepare',
  });

  expect(admitted).toMatchObject({
    ok: true,
    kind: 'operation_step_up',
    phase: 'prepare',
    admissionKind: 'operation_in_progress',
  });
  if (!admitted.ok || admitted.kind !== 'operation_step_up') {
    throw new Error('ECDSA exhausted candidate was not admitted');
  }
  expect(admitted.session.sessionId).toBe(String(session.authorizationId));
  expect(admitted.operation.authorization.kind).toBe('verified_step_up');
  expect(admitted.operation.quota.kind).toBe('quota_neutral');
  expect(admitted.operation.authorizedOperationId).toBe(authorizedOperation.authorizedOperationId);
  expect(authorizedOperations.readCalls).toBe(1);
  expect(authorizedOperations.admitCalls).toBe(1);
  expect(authorizationSessions.statusReads).toBe(0);
  expect(admissionAdapter.calls).toBe(1);
});
