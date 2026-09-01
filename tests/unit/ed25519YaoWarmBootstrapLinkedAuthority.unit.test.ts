import { expect, test } from '@playwright/test';
import {
  buildWarmRecoveryBootstrapResponse,
  type RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  type WarmBootstrapLinkedEd25519AuthorityProjectionV1,
  type WarmBootstrapLinkedEd25519AuthorityReaderV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
} from '../../packages/wallet-server/src/authorization/domain';
import {
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const LINKED_TARGET_SESSION_ID = 'linked-device-source-preserving:warm-bootstrap-test';
const FOUNDING_SESSION_ID = 'wrc_founding-registration-session';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function bytes32(seed: number): number[] {
  return Array.from({ length: 32 }, (_, index) => (index + seed) % 256);
}

type Fixture = Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>;

function buildAdmissionContext(
  fixture: Fixture,
): RouterApiWalletSessionAuthorizationV2AdmissionContext {
  const tenantId = required(parseTenantId('tenant:warm-bootstrap'));
  const principalId = required(parsePrincipalId('principal:warm-bootstrap'));
  const mintId = required(parseWalletSessionMintId('wallet-mint:warm-bootstrap'));
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId: fixture.walletId,
    authorityId: fixture.authority.authorityId,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authorityDigestB64u: fixture.authority.authorityDigestB64u,
    authorityRevocationEpoch: fixture.authority.revocationEpoch,
    mintId,
    authorizationId: fixture.ed25519Session.authorizationId,
    walletSessionId: fixture.ed25519Session.walletSessionId,
    quotaId: fixture.ed25519Session.quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(fixture.authority),
    createdAtMs: 300,
    expiresAtMs: fixture.ed25519Session.expiresAtMs,
  });
  return {
    authorization: {
      session,
      quota: buildActiveWalletSessionQuota({
        tenantId,
        principalId,
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
        remainingUses: fixture.ed25519Session.remainingUses,
        expiresAtMs: session.expiresAtMs,
      }),
    },
    authority: fixture.authority,
    authMethod: fixture.authMethod,
    retiredAtMs: null,
  };
}

/**
 * The one identity-scoped capability the wallet holds: founding material and
 * the founding threshold session, which a linked authority must never match
 * without the projection override.
 */
function buildFoundingCapability(fixture: Fixture): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  const foundingMaterial = buildMpcMaterialActivationRefFixture(
    'founding-runtime-ed25519',
    String(fixture.walletId),
    'worker:linked-runtime',
  );
  const runtimePolicyScope = fixture.ed25519Session.runtimePolicyScope;
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: routerAbMpcMaterialActivationRefToWire(foundingMaterial),
    activeCapabilityBinding: bytes32(5),
    registeredPublicKey: bytes32(9),
    nearAccountId: fixture.ed25519Session.nearAccountId,
    applicationBinding: {
      wallet_id: String(fixture.walletId),
      near_ed25519_signing_key_id: fixture.ed25519Session.nearEd25519SigningKeyId,
      signing_root_id: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
      key_creation_signer_slot: 1,
    },
    runtimePolicyScope,
    participantIds: fixture.ed25519Session.participantIds,
    lifecycle: {
      lifecycleId: 'lifecycle:founding-runtime',
      rootShareEpoch: runtimePolicyScope.signingRootVersion,
      accountId: String(fixture.walletId),
      thresholdSessionId: required(parseThresholdEd25519SessionId(FOUNDING_SESSION_ID)),
      signerSetId: 'signer-set:linked-runtime',
      signingWorkerId: fixture.ed25519Session.relayerKeyId,
    },
    stateEpoch: 1,
    registrationContinuity: {
      kind: 'recovery',
      activationTranscript: [3],
    },
  };
}

function buildLinkedProjection(
  fixture: Fixture,
  capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1,
): WarmBootstrapLinkedEd25519AuthorityProjectionV1 {
  const activation = fixture.authority.signerActivations.ed25519;
  if (!activation) throw new Error('linked fixture is missing its Ed25519 activation');
  const targetMaterialWire = routerAbMpcMaterialActivationRefToWire(activation.materialActivation);
  return {
    walletId: String(fixture.walletId),
    authorityId: String(fixture.authority.authorityId),
    walletAuthMethodId: String(fixture.authMethod.walletAuthMethodId),
    linkSessionId: 'link-session:linked-runtime',
    materialActivation: activation.materialActivation,
    targetBinding: {
      lifecycle: {
        lifecycle_id: LINKED_TARGET_SESSION_ID,
        work_kind: 'registration_prepare',
        primitive_request_kind: 'registration',
        root_share_epoch: capability.lifecycle.rootShareEpoch,
        account_id: capability.lifecycle.accountId,
        session_id: LINKED_TARGET_SESSION_ID,
        signer_set_id: capability.lifecycle.signerSetId,
        selected_server_id: capability.lifecycle.signingWorkerId,
      },
      operation: 'registration',
      session_id: bytes32(13),
      stable_key_context_binding: bytes32(17),
      material_activation: targetMaterialWire,
    },
    applicationBinding: capability.applicationBinding,
    participantIds: fixture.ed25519Session.participantIds,
    activationReceipt: {
      registered_public_key: [...capability.registeredPublicKey],
      material_activation: targetMaterialWire,
    },
  };
}

function buildWarmBootstrapRequest(
  fixture: Fixture,
  capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: String(fixture.walletId),
    nearAccountId: fixture.ed25519Session.nearAccountId,
    nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
    signerSlot: 1,
    thresholdSessionId: LINKED_TARGET_SESSION_ID,
    signingWorkerId: capability.lifecycle.signingWorkerId,
    participantIds: fixture.ed25519Session.participantIds,
  };
}

function readerFor(
  projection: WarmBootstrapLinkedEd25519AuthorityProjectionV1 | null,
): WarmBootstrapLinkedEd25519AuthorityReaderV1 {
  return {
    async readInstalledEd25519AuthorityByMaterialActivationV1() {
      return projection;
    },
  };
}

test('device-linked warm bootstrap binds the linked activation and threshold session', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const capability = buildFoundingCapability(fixture);
  const projection = buildLinkedProjection(fixture, capability);
  const activation = fixture.authority.signerActivations.ed25519;
  if (!activation) throw new Error('linked fixture is missing its Ed25519 activation');
  const response = await buildWarmRecoveryBootstrapResponse({
    request: buildWarmBootstrapRequest(fixture, capability),
    authorization: {
      kind: 'wallet_session_v2',
      context: buildAdmissionContext(fixture),
    },
    capability,
    linkedAuthorities: readerFor(projection),
  });
  expect(response).not.toBeNull();
  expect(String(response?.thresholdSessionId)).toBe(LINKED_TARGET_SESSION_ID);
  expect(String(response?.capability.lifecycle.thresholdSessionId)).toBe(LINKED_TARGET_SESSION_ID);
  expect(response?.capability.materialActivation).toEqual(
    routerAbMpcMaterialActivationRefToWire(activation.materialActivation),
  );
});

test('device-linked warm bootstrap fails closed without a linked-authority reader', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const capability = buildFoundingCapability(fixture);
  const response = await buildWarmRecoveryBootstrapResponse({
    request: buildWarmBootstrapRequest(fixture, capability),
    authorization: {
      kind: 'wallet_session_v2',
      context: buildAdmissionContext(fixture),
    },
    capability,
  });
  expect(response).toBeNull();
});

test('device-linked warm bootstrap rejects a projection outside the authority activation', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const capability = buildFoundingCapability(fixture);
  const projection = buildLinkedProjection(fixture, capability);
  const foreignMaterial = buildMpcMaterialActivationRefFixture(
    'foreign-runtime-ed25519',
    String(fixture.walletId),
    'worker:linked-runtime',
  );
  const response = await buildWarmRecoveryBootstrapResponse({
    request: buildWarmBootstrapRequest(fixture, capability),
    authorization: {
      kind: 'wallet_session_v2',
      context: buildAdmissionContext(fixture),
    },
    capability,
    linkedAuthorities: readerFor({
      ...projection,
      materialActivation: foreignMaterial,
    }),
  });
  expect(response).toBeNull();
});
