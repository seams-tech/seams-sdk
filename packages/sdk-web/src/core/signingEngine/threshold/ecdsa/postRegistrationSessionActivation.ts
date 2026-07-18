import { base64UrlEncode } from '@shared/utils/base64';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type {
  RouterAbEcdsaClientProofFinalizationV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  activateRouterAbEcdsaPostRegistrationSession,
  routerAbEcdsaActivationRefresh,
  routerAbEcdsaRecovery,
  type ThresholdEcdsaDerivationRouteAuth,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { ThresholdRuntimePolicyScope } from '../sessionPolicy';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  FinalizeRouterAbEcdsaRecoveryActivationResultV1,
  RouterAbEcdsaActivationRefreshRequestFactsV1,
  RouterAbEcdsaRecoveryRequestFactsV1,
} from '../../workerManager/ecdsaClientWorkerChannels';
import {
  closeRouterAbEcdsaPostRegistrationCeremonyWasm,
  createRouterAbEcdsaPostRegistrationCeremonyWasm,
  finalizeRouterAbEcdsaRecoveryActivationWasm,
  verifyRouterAbEcdsaRecoveryClientProofsWasm,
  verifyRouterAbEcdsaRefreshClientProofsWasm,
} from '../crypto/ecdsaDerivationClientWasm';

const POST_REGISTRATION_ROUTE_AUTH_KINDS = new Set(['app_session', 'wallet_session']);

export type ActivateStrictEcdsaPostRegistrationSessionInput = {
  readonly relayerUrl: string;
  readonly routeAuth: Extract<
    ThresholdEcdsaDerivationRouteAuth,
    { kind: 'app_session' | 'wallet_session' }
  >;
  readonly workerCtx: WorkerOperationContext;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly walletId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type ActivateStrictEcdsaPostRegistrationSessionResult = {
  readonly sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly roleLocalActivation: FinalizeRouterAbEcdsaRecoveryActivationResultV1;
};

function randomDigest32B64u(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function clientProofFinalization(
  response: {
    readonly bundles: RouterAbEcdsaClientProofFinalizationV1['bundles'];
    readonly commitmentRegistry: RouterAbEcdsaClientProofFinalizationV1['commitmentRegistry'];
  },
): RouterAbEcdsaClientProofFinalizationV1 {
  return {
    kind: 'finalize_encrypted_client_proof_bundles_v1',
    verificationTimeMs: Date.now(),
    bundles: response.bundles,
    commitmentRegistry: response.commitmentRegistry,
  };
}

function routeFailureMessage(
  result: { readonly code?: string; readonly message?: string; readonly error?: string },
  fallback: string,
): string {
  return result.error || result.message || result.code || fallback;
}

function validateStrictSessionInput(input: ActivateStrictEcdsaPostRegistrationSessionInput): void {
  if (!POST_REGISTRATION_ROUTE_AUTH_KINDS.has(input.routeAuth.kind)) {
    throw new Error('Strict ECDSA session activation requires app or Wallet Session bearer auth');
  }
  if (!input.walletId || !input.thresholdSessionId || !input.signingGrantId) {
    throw new Error('Strict ECDSA session activation requires exact wallet and session identity');
  }
  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1) {
    throw new Error('Strict ECDSA session activation requires a positive ttlMs');
  }
  if (!Number.isSafeInteger(input.remainingUses) || input.remainingUses < 1) {
    throw new Error('Strict ECDSA session activation requires positive remainingUses');
  }
}

function recoveryRequestFacts(args: {
  input: ActivateStrictEcdsaPostRegistrationSessionInput;
  lifecycleId: string;
  nonce: string;
  authorizationDigestB64u: string;
  expiresAtMs: number;
}): RouterAbEcdsaRecoveryRequestFactsV1 {
  const capability = args.input.publicCapability;
  return {
    context: capability.context,
    lifecycle: {
      lifecycle_id: args.lifecycleId,
      work_kind: 'recovery',
      primitive_request_kind: 'recovery',
      root_share_epoch: capability.activation_epoch,
      account_id: args.input.walletId,
      session_id: args.input.thresholdSessionId,
      signer_set_id: capability.signer_set.signer_set_id,
      selected_server_id: capability.signer_set.selected_server.server_id,
    },
    public_identity: capability.public_identity,
    signer_set: capability.signer_set,
    router_id: capability.router_id,
    client_id: capability.client_id,
    recovery_authorization_digest_b64u: args.authorizationDigestB64u,
    recovery_nonce: args.nonce,
    expires_at_ms: args.expiresAtMs,
    deriver_recipient_keys: capability.deriver_recipient_keys,
  };
}

function refreshRequestFacts(args: {
  input: ActivateStrictEcdsaPostRegistrationSessionInput;
  lifecycleId: string;
  nonce: string;
  authorizationDigestB64u: string;
  nextActivationEpoch: string;
  expiresAtMs: number;
}): RouterAbEcdsaActivationRefreshRequestFactsV1 {
  const capability = args.input.publicCapability;
  return {
    context: capability.context,
    lifecycle: {
      lifecycle_id: args.lifecycleId,
      work_kind: 'server_share_refresh',
      primitive_request_kind: 'refresh',
      root_share_epoch: args.nextActivationEpoch,
      account_id: args.input.walletId,
      session_id: args.input.thresholdSessionId,
      signer_set_id: capability.signer_set.signer_set_id,
      selected_server_id: capability.signer_set.selected_server.server_id,
    },
    public_identity: capability.public_identity,
    signer_set: capability.signer_set,
    router_id: capability.router_id,
    client_id: capability.client_id,
    signing_worker_ephemeral_public_key:
      capability.signer_set.selected_server.recipient_encryption_key,
    refresh_authorization_digest_b64u: args.authorizationDigestB64u,
    refresh_nonce: args.nonce,
    previous_activation_epoch: capability.activation_epoch,
    next_activation_epoch: args.nextActivationEpoch,
    expires_at_ms: args.expiresAtMs,
    deriver_recipient_keys: capability.deriver_recipient_keys,
  };
}

async function closeCeremony(
  workerCtx: WorkerOperationContext,
  ceremonyId: string,
): Promise<void> {
  await closeRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx,
    command: {
      kind: 'close_router_ab_ecdsa_post_registration_ceremony_v1',
      ceremonyId,
    },
  }).catch(() => undefined);
}

export async function activateStrictEcdsaPostRegistrationSession(
  input: ActivateStrictEcdsaPostRegistrationSessionInput,
): Promise<ActivateStrictEcdsaPostRegistrationSessionResult> {
  validateStrictSessionInput(input);
  const expiresAtMs = Date.now() + input.ttlMs;
  const recoveryId = secureRandomId(
    'ecdsa-recovery',
    24,
    'Router A/B ECDSA recovery lifecycle ids',
  );
  const refreshId = secureRandomId(
    'ecdsa-refresh',
    24,
    'Router A/B ECDSA refresh lifecycle ids',
  );
  const nextActivationEpoch = secureRandomId(
    'ecdsa-activation',
    24,
    'Router A/B ECDSA activation epochs',
  );
  const recoveryCreated = await createRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx: input.workerCtx,
    command: {
      kind: 'create_router_ab_ecdsa_recovery_ceremony_v1',
      ceremonyId: recoveryId,
      publicCapability: input.publicCapability,
      request: recoveryRequestFacts({
        input,
        lifecycleId: recoveryId,
        nonce: secureRandomId('ecdsa-recovery-nonce', 24, 'ECDSA recovery nonces'),
        authorizationDigestB64u: randomDigest32B64u(),
        expiresAtMs,
      }),
    },
  });
  if (recoveryCreated.kind !== 'router_ab_ecdsa_recovery_ceremony_created_v1') {
    await closeCeremony(input.workerCtx, recoveryId);
    throw new Error('Strict ECDSA recovery ceremony kind mismatch');
  }

  let recoveryVerified:
    | Awaited<ReturnType<typeof verifyRouterAbEcdsaRecoveryClientProofsWasm>>
    | undefined;
  try {
    const recovery = await routerAbEcdsaRecovery(input.relayerUrl, {
      request: recoveryCreated.request,
      auth: input.routeAuth,
    });
    if (!recovery.ok) {
      throw new Error(routeFailureMessage(recovery, 'Strict ECDSA recovery failed'));
    }
    recoveryVerified = await verifyRouterAbEcdsaRecoveryClientProofsWasm({
      workerCtx: input.workerCtx,
      command: {
        kind: 'verify_router_ab_ecdsa_recovery_client_proofs_v1',
        ceremonyId: recoveryId,
        clientProofFinalization: clientProofFinalization(recovery.value.response),
      },
    });

    const refreshCreated = await createRouterAbEcdsaPostRegistrationCeremonyWasm({
      workerCtx: input.workerCtx,
      command: {
        kind: 'create_router_ab_ecdsa_activation_refresh_ceremony_v1',
        ceremonyId: refreshId,
        publicCapability: input.publicCapability,
        request: refreshRequestFacts({
          input,
          lifecycleId: refreshId,
          nonce: secureRandomId('ecdsa-refresh-nonce', 24, 'ECDSA refresh nonces'),
          authorizationDigestB64u: randomDigest32B64u(),
          nextActivationEpoch,
          expiresAtMs,
        }),
      },
    });
    if (refreshCreated.kind !== 'router_ab_ecdsa_activation_refresh_ceremony_created_v1') {
      await closeCeremony(input.workerCtx, refreshId);
      throw new Error('Strict ECDSA activation refresh ceremony kind mismatch');
    }
    try {
      const refresh = await routerAbEcdsaActivationRefresh(input.relayerUrl, {
        request: refreshCreated.request,
        auth: input.routeAuth,
      });
      if (!refresh.ok) {
        throw new Error(routeFailureMessage(refresh, 'Strict ECDSA activation refresh failed'));
      }
      await verifyRouterAbEcdsaRefreshClientProofsWasm({
        workerCtx: input.workerCtx,
        command: {
          kind: 'verify_router_ab_ecdsa_refresh_client_proofs_v1',
          ceremonyId: refreshId,
          clientProofFinalization: clientProofFinalization(refresh.value.response),
        },
      });

      const activated = await activateRouterAbEcdsaPostRegistrationSession(input.relayerUrl, {
        auth: input.routeAuth,
        request: {
          kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
          recovery_binding: {
            lifecycle_id: recovery.value.response.lifecycle.lifecycle_id,
            request_id: recovery.value.response.replay.request_id,
          },
          refresh_binding: {
            lifecycle_id: refresh.value.response.lifecycle.lifecycle_id,
            request_id: refresh.value.response.replay.request_id,
          },
          public_capability: input.publicCapability,
          verified_client_facts: recoveryVerified.publicFacts,
          session_policy: {
            threshold_session_id: input.thresholdSessionId,
            signing_grant_id: input.signingGrantId,
            ttl_ms: input.ttlMs,
            remaining_uses: input.remainingUses,
            runtime_policy_scope: input.runtimePolicyScope,
          },
        },
      });
      if (!activated.ok) {
        throw new Error(
          routeFailureMessage(activated, 'Strict ECDSA phase-two session activation failed'),
        );
      }
      const receipt = activated.value.signing_worker_activation;
      const roleLocalActivation = await finalizeRouterAbEcdsaRecoveryActivationWasm({
        workerCtx: input.workerCtx,
        command: {
          kind: 'finalize_router_ab_ecdsa_recovery_activation_v1',
          ceremonyId: recoveryId,
          activationReceipt: receipt,
          expectedLifecycleId: receipt.lifecycle_id,
          expectedTranscriptDigestB64u: base64UrlEncode(
            Uint8Array.from(receipt.transcript_digest.bytes),
          ),
          expectedActivationEpoch: nextActivationEpoch,
          expiresAtMs: activated.value.session.expires_at_ms,
        },
      });
      return {
        sessionActivation: activated.value,
        roleLocalActivation,
      };
    } catch (error: unknown) {
      await closeCeremony(input.workerCtx, refreshId);
      throw error;
    }
  } catch (error: unknown) {
    await closeCeremony(input.workerCtx, recoveryId);
    throw error;
  }
}
