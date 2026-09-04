import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { signTenantRootCreationGrantV1 } from '../../packages/wallet-console-server-ts/src/tenantRootCreation/grantSigner';

const RUST_GRANT_B64U =
  'AAAAHXRlbmFudF9yb290X2NyZWF0aW9uX2dyYW50X3YxAAAAH3RlbmFudF9yb290X2F1dGhvcml6ZV9jcmVhdGVfdjEAAABUc2VhbXMvdGVuYW50LXJvb3QtaWRlbnRpdHkvdjEAAAAFb3JnLTEAAAAJcHJvamVjdC0yAAAACnByb2R1Y3Rpb24AAAAJcm9vdC1tYWluAAAAAnYzAAAAECIiIiIiIiIiIiIiIiIiIiIAAAAgMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMAAAAIAAAAAAAPQkAAAAAIAAAAAAAPt3AAAAAZcHJvdmlzaW9uaW5nLWF1dGhvcml0eS12MQAAAECr7rtvCTj4DFZ7RyPi4bonihsdKpEgRV1GaG7ivN_gCCRgDKpDrnx1pu6CIu2ub6JhIt2Gh04v22qcJqda0hIH';

test('Console grant signing matches the Rust canonical grant vector', async () => {
  const signed = await signTenantRootCreationGrantV1({
    identity: {
      orgId: 'org-1',
      projectId: 'project-2',
      envId: 'production',
      signingRootId: 'root-main',
      signingRootVersion: 'v3',
    },
    custodyLineage: new Uint8Array(16).fill(0x22),
    grantNonce: new Uint8Array(32).fill(0x33),
    issuedAtMs: 1_000_000,
    expiresAtMs: 1_030_000,
    grantKeyId: 'provisioning-authority-v1',
    signingSeedB64u: base64UrlEncode(new Uint8Array(32).fill(0x61)),
  });

  expect(signed.grantB64u).toBe(RUST_GRANT_B64U);
  expect(signed.identityDigestB64u).toBe('nF1YOuRpN5POO1FZDHiGUboN9MIzmyW4RnZmX85Eqos');
  expect(signed.grantDigestB64u).toBe('JmWCA9InOK7WPTN5P1gAUQWkK_66Z-fB6cbl9KzVw8I');
});
