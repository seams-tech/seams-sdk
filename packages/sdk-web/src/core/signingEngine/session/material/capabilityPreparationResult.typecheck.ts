import type { CapabilityPreparationResult } from './capabilityPreparationResult';

type Result = CapabilityPreparationResult<
  { material: 'ready' },
  { recoveryId: string },
  { factor: 'passkey' },
  { activationId: string },
  { reason: string }
>;

const ready: Result = { kind: 'ready', value: { material: 'ready' } };
const pending: Result = { kind: 'pending', resume: { recoveryId: 'recovery' } };
const authorizationRequired: Result = {
  kind: 'authorization_required',
  requirement: { factor: 'passkey' },
};
const superseded: Result = {
  kind: 'superseded',
  replacement: { activationId: 'replacement' },
};
const failed: Result = { kind: 'failed', failure: { reason: 'corrupt' } };

void [ready, pending, authorizationRequired, superseded, failed];

const invalidReady: Result = {
  kind: 'ready',
  value: { material: 'ready' },
  // @ts-expect-error A ready result cannot also carry authorization requirements.
  requirement: { factor: 'passkey' },
};

// @ts-expect-error Pending requires an actual resumable value.
const invalidPending: Result = { kind: 'pending' };

void [invalidReady, invalidPending];
