/**
 * Refactor 94C. Compile-time fixture for the registration configuration
 * surface.
 *
 * `/wallets/register/setup` authenticates with a publishable key alone, so the
 * credential must reach the browser. The backend-proxied mode could not supply
 * one and its `bootstrapUrl` pointed at the deleted intent route; both are
 * gone. This pins that they cannot come back as an accepted input shape —
 * a runtime check alone would let a caller keep writing the retired config and
 * only learn at build time.
 */

import type { SeamsRegistrationConfig, SeamsRegistrationConfigInput } from '../types/seams';

/* The supported shape. */
const managedInput: SeamsRegistrationConfigInput = {
  mode: 'managed',
  projectEnvironmentId: 'env_prod',
  publishableKey: 'pk_publishable',
};
void managedInput;

/* `mode` may be omitted — managed is the only value it can take. */
const managedInputWithoutMode: SeamsRegistrationConfigInput = {
  projectEnvironmentId: 'env_prod',
  publishableKey: 'pk_publishable',
};
void managedInputWithoutMode;

/* The retired mode. The target is a single object type rather than a union, so
   the mismatch is reported on the offending property, not the declaration. */
const backendProxyInput: SeamsRegistrationConfigInput = {
  // @ts-expect-error backend_proxy is not a registration mode.
  mode: 'backend_proxy',
  projectEnvironmentId: 'env_prod',
  publishableKey: 'pk_publishable',
};
void backendProxyInput;

/* Its URL field is gone even when the mode is spelled correctly. */
const bootstrapUrlInput: SeamsRegistrationConfigInput = {
  mode: 'managed',
  projectEnvironmentId: 'env_prod',
  publishableKey: 'pk_publishable',
  // @ts-expect-error registrationBootstrapUrl is not a registration input field.
  registrationBootstrapUrl: 'https://app.example/api/registration/bootstrap',
};
void bootstrapUrlInput;

/* Credentials are required on the input: a managed block that cannot
   authenticate is not a representable state. */
// @ts-expect-error managed registration requires publishableKey.
const missingPublishableKey: SeamsRegistrationConfigInput = {
  mode: 'managed',
  projectEnvironmentId: 'env_prod',
};
void missingPublishableKey;

/* The resolved config has no second arm to narrow against. */
const resolved: SeamsRegistrationConfig = {
  mode: 'managed',
  projectEnvironmentId: 'env_prod',
  publishableKey: 'pk_publishable',
  paymentMode: 'disabled',
  nearAccountProvisioning: { kind: 'implicit_account' },
};
void resolved;

/* `mode` is a single literal, so this comparison is statically impossible —
   the check that would have selected the deleted branch cannot be written. */
// @ts-expect-error resolved registration config has no backend_proxy arm.
const retiredArm: boolean = resolved.mode === 'backend_proxy';
void retiredArm;
