import type {
  AgentPrincipalId,
  LinkedDeviceId,
  MandatePolicyId,
} from './ids';

export type ChainScope = {
  kind: 'chain_scope_v1';
  chainIds: readonly string[];
};

export type AssetScope = {
  kind: 'asset_scope_v1';
  assetIds: readonly string[];
};

export type CounterpartyScope = {
  kind: 'counterparty_scope_v1';
  counterpartyIds: readonly string[];
};

export type AtomicValueLimit = {
  kind: 'atomic_value_limit_v1';
  amountAtomic: string;
  assetId: string;
};

export type DelegatedReplayPolicy = {
  kind: 'delegated_replay_policy_v1';
  nonceScope: 'wallet_key_lane' | 'mandate_policy';
};

export type DelegatedFeePolicy = {
  kind: 'delegated_fee_policy_v1';
  maxFeeAtomic: string;
  feeAssetId: string;
  sponsorship: 'allowed' | 'required' | 'forbidden';
};

export type DelegatedIntentKind = 'specific_purchase_payment_v1' | 'allowance_grant_v1';

export type DelegatedMandatePolicy = {
  kind: 'delegated_mandate_policy_v1';
  policyId: MandatePolicyId;
  policyVersion: string;
  allowedIntents: readonly DelegatedIntentKind[];
  chainScope: ChainScope;
  assetScope: AssetScope;
  counterpartyScope: CounterpartyScope;
  perOperationLimit: AtomicValueLimit;
  aggregateBudget: AtomicValueLimit;
  expiresAtMs: number;
  requiredIntentDigest: 'exact_payment_intent_v1';
  replayPolicy: DelegatedReplayPolicy;
  feePolicy: DelegatedFeePolicy;
  outOfPolicyAction: 'deny' | 'require_owner_approval';
};

export type LinkedDeviceAdministrationScope =
  | 'signing_only'
  | 'device_management'
  | 'delegation_management'
  | 'full_owner_admin';

export type LinkedDevicePermissionPolicy =
  | {
      kind: 'owner_equivalent_device_permission_v1';
      requiresLocalUserPresence: true;
      signingScope: 'full_wallet_signing';
      administrationScope: LinkedDeviceAdministrationScope;
      mandatePolicy?: never;
    }
  | {
      kind: 'scoped_device_permission_v1';
      requiresLocalUserPresence: boolean;
      administrationScope: 'no_account_admin';
      mandatePolicy: DelegatedMandatePolicy;
    };

export type AgentCustodyRuntime = 'managed_service' | 'tee' | 'hsm' | 'customer_runtime';

export type AgentCustodyBindingRecord = {
  kind: 'agent_custody_binding_v1';
  agentId: AgentPrincipalId;
  custodyKeyId: string;
  custodyRuntime: AgentCustodyRuntime;
  encryptionPublicKeyB64u: string;
  attestationDigestB64u: string;
  attestationKind:
    | 'managed_service_policy'
    | 'tee_attestation'
    | 'hsm_attestation'
    | 'customer_runtime_registration';
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};

export type LinkedDeviceBindingRecord = {
  kind: 'linked_device_binding_v1';
  deviceId: LinkedDeviceId;
  linkPublicKeyB64u: string;
  devicePublicKeyB64u: string;
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};

export function buildOwnerEquivalentLinkedDevicePermissionPolicy(args: {
  administrationScope: LinkedDeviceAdministrationScope;
}): LinkedDevicePermissionPolicy {
  return {
    kind: 'owner_equivalent_device_permission_v1',
    requiresLocalUserPresence: true,
    signingScope: 'full_wallet_signing',
    administrationScope: args.administrationScope,
  };
}

export function buildScopedLinkedDevicePermissionPolicy(args: {
  requiresLocalUserPresence: boolean;
  mandatePolicy: DelegatedMandatePolicy;
}): LinkedDevicePermissionPolicy {
  return {
    kind: 'scoped_device_permission_v1',
    requiresLocalUserPresence: args.requiresLocalUserPresence,
    administrationScope: 'no_account_admin',
    mandatePolicy: args.mandatePolicy,
  };
}
