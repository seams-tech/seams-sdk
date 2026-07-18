import { expect, test } from '@playwright/test';
import {
  createRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';

test('Ed25519 Yao product state survives the Durable Object structured-clone boundary', () => {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  state.registration.lifecycleSessions.set('lifecycle-1', 'session-1');
  state.export.authorizationNonces.add('nonce-1');

  const parsed = parseRouterAbEd25519YaoProductRegistrationStateV1(
    structuredClone(state),
  );

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.message);
  expect(parsed.value.registration.lifecycleSessions.get('lifecycle-1')).toBe('session-1');
  expect(parsed.value.export.authorizationNonces.has('nonce-1')).toBe(true);
});

test('Ed25519 Yao product state rejects JSON-shaped lifecycle collections', () => {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const jsonShapedState = JSON.parse(JSON.stringify(state));

  expect(parseRouterAbEd25519YaoProductRegistrationStateV1(jsonShapedState)).toEqual({
    ok: false,
    message: 'persisted Ed25519 Yao product state has invalid lifecycle collections',
  });
});
