import { expect, test } from '@playwright/test';
import {
  ecdsaSigningAuthorizationSupersession,
  ecdsaSigningCapabilitySupersession,
  ecdsaSigningMaterialSupersession,
} from '@/core/signingEngine/flows/signEvmFamily/signingFlowRuntime';
import {
  EvmFamilyEcdsaMaterialSupersededError,
  isEvmFamilyEcdsaMaterialSupersededError,
} from '@/core/signingEngine/flows/signEvmFamily/signingFlow';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaCapabilityActivationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';

// R90-INV-010. A preparation binds one material activation; the wallet's active
// manifest names the one that may be used now. When those differ the
// preparation is superseded -- the caller discards it and resolves current
// state again. Collapsing this into a generic material failure would surface a
// routine capability replacement to the user as a signing error.

const WALLET_ID = 'supersession-fixture-wallet';
const PREPARED = buildMpcMaterialActivationRefFixture('prepared-activation', WALLET_ID);
const CURRENT = buildMpcMaterialActivationRefFixture('current-activation', WALLET_ID);

test.describe('ECDSA material supersession', () => {
  test('is not raised while the manifest still names the prepared activation', () => {
    expect(
      ecdsaSigningMaterialSupersession({
        preparedMaterialActivation: PREPARED,
        currentMaterialActivation: PREPARED,
      }),
    ).toBeNull();
  });

  test('names both sides so the caller can re-resolve against the current one', () => {
    const superseded = ecdsaSigningMaterialSupersession({
      preparedMaterialActivation: PREPARED,
      currentMaterialActivation: CURRENT,
    });

    expect(superseded).toEqual({
      kind: 'superseded',
      supersessionKind: 'material_activation_replaced',
      preparedMaterialActivation: PREPARED,
      currentMaterialActivation: CURRENT,
    });
  });

  test('treats capability-authority replacement as superseded with the same activation', async () => {
    const prepared = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const current = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');

    expect(
      ecdsaSigningCapabilitySupersession({
        preparedCapability: prepared.capability,
        currentManifest: current.manifest,
      }),
    ).toEqual({
      kind: 'superseded',
      supersessionKind: 'capability_authority_replaced',
      preparedMaterialActivation: prepared.manifest.activation.materialActivation,
      currentMaterialActivation: current.manifest.activation.materialActivation,
    });
  });

  test('treats a new manifest revision as superseded with the same activation and authority', async () => {
    const prepared = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const current = ecdsaCapabilityActivationLookupFixture({
      authority: prepared.manifest.signer.authority,
      manifestRevision: 2,
    });

    expect(
      ecdsaSigningCapabilitySupersession({
        preparedCapability: prepared.capability,
        currentManifest: current.manifest,
      }),
    ).toMatchObject({
      kind: 'superseded',
      supersessionKind: 'capability_authority_replaced',
      preparedMaterialActivation: prepared.manifest.activation.materialActivation,
      currentMaterialActivation: current.manifest.activation.materialActivation,
    });
  });

  test('treats reusable authorization replacement during confirmation as superseded', async () => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const preparedAuthorization = activeEvmFamilyWalletSessionAuthorizationFixture({
      manifest: fixture.manifest,
      walletSessionId: 'prepared-wallet-session',
    });
    const currentAuthorization = activeEvmFamilyWalletSessionAuthorizationFixture({
      manifest: fixture.manifest,
      walletSessionId: 'replacement-wallet-session',
    });

    expect(
      ecdsaSigningAuthorizationSupersession({
        preparedAuthorization,
        currentAuthorization,
        materialActivation: fixture.manifest.activation.materialActivation,
      }),
    ).toEqual({
      kind: 'superseded',
      supersessionKind: 'reusable_authorization_replaced',
      preparedMaterialActivation: fixture.manifest.activation.materialActivation,
      currentMaterialActivation: fixture.manifest.activation.materialActivation,
    });
  });

  test('treats reusable quota replacement during confirmation as superseded', async () => {
    const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
    const preparedAuthorization = activeEvmFamilyWalletSessionAuthorizationFixture({
      manifest: fixture.manifest,
      quotaId: 'prepared-quota',
    });
    const currentAuthorization = activeEvmFamilyWalletSessionAuthorizationFixture({
      manifest: fixture.manifest,
      quotaId: 'replacement-quota',
    });

    expect(
      ecdsaSigningAuthorizationSupersession({
        preparedAuthorization,
        currentAuthorization,
        materialActivation: fixture.manifest.activation.materialActivation,
      }),
    ).toMatchObject({
      kind: 'superseded',
      supersessionKind: 'reusable_authorization_replaced',
    });
  });

  test('is a distinct outcome from unavailable material', () => {
    const superseded = ecdsaSigningMaterialSupersession({
      preparedMaterialActivation: PREPARED,
      currentMaterialActivation: CURRENT,
    });
    if (!superseded) throw new Error('expected a superseded outcome');

    // `reason` is the discriminator the unavailable arms carry. A superseded
    // plan must never be mistaken for one, or the signing flow would throw
    // instead of re-resolving.
    expect(superseded.reason).toBeUndefined();
    expect(superseded.material).toBeUndefined();
  });

  test('unwinds to the retry boundary as a recognizable typed error', () => {
    const superseded = ecdsaSigningMaterialSupersession({
      preparedMaterialActivation: PREPARED,
      currentMaterialActivation: CURRENT,
    });
    if (!superseded) throw new Error('expected a superseded outcome');
    const error = new EvmFamilyEcdsaMaterialSupersededError(superseded);

    // The guard is what routes the retry; without it the error falls through to
    // the fresh-auth ladder and prompts the user for an auth they do not need.
    expect(isEvmFamilyEcdsaMaterialSupersededError(error)).toBe(true);
    expect(isEvmFamilyEcdsaMaterialSupersededError(new Error(error.message))).toBe(false);
    expect(error.superseded).toEqual(superseded);
    expect(error.message).toContain(String(PREPARED.activationId));
    expect(error.message).toContain(String(CURRENT.activationId));
  });
});
