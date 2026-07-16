import { expect, test } from '@playwright/test';
import {
  MPC_CAPABILITY_HYDRATION_OBSERVATION_VERSION,
  parseMpcCapabilityHydrationObservation,
  type MpcCapabilityHydrationEntryPoint,
  type MpcCapabilityHydrationPlan,
} from '../../packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration';

const LIVE_RUNTIME_STATE = {
  kind: 'use_live_runtime',
  capability: 'capability:wallet-1:near',
  materialOwner: 'material-owner:wallet-1:near-key-1',
  authority: 'authority:wallet-1:passkey-1',
  runtime: 'runtime:yao-client-1',
  activeMaterialSession: 'material-session:grant-1',
};

const PUBLIC_REAUTH_STATE = {
  kind: 'reauthorize_public_anchor',
  retirement: 'exhausted',
  publicReauthAnchor: {
    kind: 'mpc_capability_public_reauth_anchor_v1',
    capability: 'capability:wallet-1:evm',
    materialOwner: 'material-owner:wallet-1:evm-key-1',
    authority: 'authority:wallet-1:email-otp-1',
    keyBinding: 'key-binding:evm-key-1',
    lifecycleBinding: 'lifecycle-binding:registration-1',
    policyBinding: 'policy-binding:wallet-policy-1',
    registeredPublicKeyBinding: 'public-key-binding:evm-key-1',
  },
};

const SEALED_ACTIVE_STATE = {
  kind: 'rehydrate_active_session',
  capability: 'capability:wallet-1:near',
  materialOwner: 'material-owner:wallet-1:near-key-1',
  authority: 'authority:wallet-1:passkey-1',
  activeMaterialSession: 'material-session:grant-1',
  sealedMaterial: 'sealed-material:grant-1',
};

function observation(entryPoint: MpcCapabilityHydrationEntryPoint, state: unknown): unknown {
  return {
    version: MPC_CAPABILITY_HYDRATION_OBSERVATION_VERSION,
    entryPoint,
    state,
  };
}

function requireParsedPlan(value: unknown): MpcCapabilityHydrationPlan {
  const parsed = parseMpcCapabilityHydrationObservation(value);
  if (!parsed.ok) {
    throw new Error(`${parsed.path}: ${parsed.message}`);
  }
  return parsed.value.plan;
}

test('entry-point provenance cannot change the canonical hydration plan', () => {
  const registrationPlan = requireParsedPlan(observation('post_registration', LIVE_RUNTIME_STATE));
  const unlockPlan = requireParsedPlan(observation('post_wallet_unlock', LIVE_RUNTIME_STATE));
  const refreshPlan = requireParsedPlan(observation('post_page_refresh', LIVE_RUNTIME_STATE));

  expect(unlockPlan).toEqual(registrationPlan);
  expect(refreshPlan).toEqual(registrationPlan);
  expect(refreshPlan.kind).toBe('use_live_runtime');
});

test('public reauthorization derives exact identity from its public anchor', () => {
  const plan = requireParsedPlan(observation('post_page_refresh', PUBLIC_REAUTH_STATE));
  expect(plan.kind).toBe('reauthorize_public_anchor');
  if (plan.kind !== 'reauthorize_public_anchor') return;

  expect(plan.capability).toBe(plan.publicReauthAnchor.capability);
  expect(plan.materialOwner).toBe(plan.publicReauthAnchor.materialOwner);
  expect(plan.authority).toBe(plan.publicReauthAnchor.authority);
  expect(plan.retirement).toBe('exhausted');
});

test('closed lifecycle parser resolves sealed, retired, and blocked observations', () => {
  const sealedPlan = requireParsedPlan(observation('post_page_refresh', SEALED_ACTIVE_STATE));
  const expiredPlan = requireParsedPlan(
    observation('post_page_refresh', {
      ...PUBLIC_REAUTH_STATE,
      retirement: 'expired',
    }),
  );
  const exhaustedPlan = requireParsedPlan(observation('post_page_refresh', PUBLIC_REAUTH_STATE));
  const blockedPlan = requireParsedPlan(
    observation('post_page_refresh', {
      kind: 'blocked',
      capability: null,
      reason: 'missing_capability',
    }),
  );

  expect(sealedPlan.kind).toBe('rehydrate_active_session');
  expect(expiredPlan.kind).toBe('reauthorize_public_anchor');
  expect(exhaustedPlan.kind).toBe('reauthorize_public_anchor');
  expect(blockedPlan.kind).toBe('blocked');
});

test('boundary parser rejects lifecycle fields from another branch', () => {
  const invalidState = {
    ...LIVE_RUNTIME_STATE,
    sealedMaterial: 'sealed-material:1',
  };
  const parsed = parseMpcCapabilityHydrationObservation(
    observation('post_page_refresh', invalidState),
  );

  expect(parsed.ok).toBeFalsy();
  if (parsed.ok) return;
  expect(parsed.path).toBe('observation.state.sealedMaterial');
});

test('public reauthorization anchor rejects secret-bearing fields', () => {
  const invalidState = {
    ...PUBLIC_REAUTH_STATE,
    publicReauthAnchor: {
      ...PUBLIC_REAUTH_STATE.publicReauthAnchor,
      bearerSessionCredential: 'jwt-secret',
    },
  };
  const parsed = parseMpcCapabilityHydrationObservation(
    observation('post_wallet_unlock', invalidState),
  );

  expect(parsed.ok).toBeFalsy();
  if (parsed.ok) return;
  expect(parsed.path).toBe('observation.state.publicReauthAnchor.bearerSessionCredential');
});
