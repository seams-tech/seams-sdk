import { expect, test } from '@playwright/test';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { parseThresholdEd25519SessionRouteRequest } from '../../packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation';

function validWebAuthnAuthentication(): Record<string, unknown> {
  return {
    id: 'credential-route-validation',
    rawId: 'credential-route-validation',
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function validThresholdEd25519SessionPolicy(): Record<string, unknown> {
  return {
    version: 'threshold_session_v1',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-route-validation',
    authority: buildPasskeyWalletAuthAuthority({
      walletId: 'frost-vermillion-k7p9m2',
      rpId: 'localhost',
      credentialIdB64u: 'credential-route-validation',
    }),
    relayerKeyId: 'ed25519:relayer',
    thresholdSessionId: 'tsess-route-validation',
    signingGrantId: 'grant-route-validation',
    runtimePolicyScope: {
      orgId: 'org-route-validation',
      projectId: 'project-route-validation',
      envId: 'env-route-validation',
      signingRootVersion: 'root-version-route-validation',
    },
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'ed25519:relayer',
    },
    participantIds: [1, 2],
    ttlMs: 300_000,
    remainingUses: 1,
  };
}

function validThresholdEd25519SessionBody(): Record<string, unknown> {
  return {
    relayerKeyId: 'ed25519:relayer',
    sessionKind: 'jwt',
    sessionPolicy: validThresholdEd25519SessionPolicy(),
    webauthn_authentication: validWebAuthnAuthentication(),
  };
}

function expectInvalidBody(parsed: ReturnType<typeof parseThresholdEd25519SessionRouteRequest>, message: string): void {
  expect(parsed.ok).toBe(false);
  if (parsed.ok) throw new Error('expected invalid threshold-ed25519 route body');
  expect(parsed.body.message).toContain(message);
}

function acceptsExactYaoBudgetRefreshBody(): void {
  const parsed = parseThresholdEd25519SessionRouteRequest(
    validThresholdEd25519SessionBody(),
  );

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request).toMatchObject({
    relayerKeyId: 'ed25519:relayer',
    sessionKind: 'jwt',
    routeAuth: { kind: 'passkey' },
    sessionPolicy: {
      thresholdSessionId: 'tsess-route-validation',
      signingGrantId: 'grant-route-validation',
      participantIds: [1, 2],
    },
  });
}

function rejectsMissingWebAuthnProof(): void {
  const body = validThresholdEd25519SessionBody();
  delete body.webauthn_authentication;
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'webauthn_authentication is required',
  );
}

function rejectsMissingJwtSessionKind(): void {
  const body = validThresholdEd25519SessionBody();
  delete body.sessionKind;
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'requires sessionKind=jwt',
  );
}

function rejectsIncompleteYaoPolicy(): void {
  const body = validThresholdEd25519SessionBody();
  const policy = validThresholdEd25519SessionPolicy();
  delete policy.runtimePolicyScope;
  body.sessionPolicy = policy;
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'sessionPolicy.runtimePolicyScope is required',
  );
}

function rejectsInvalidParticipantTuple(): void {
  const body = validThresholdEd25519SessionBody();
  const policy = validThresholdEd25519SessionPolicy();
  policy.participantIds = [1, 1];
  body.sessionPolicy = policy;
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'exactly two distinct participants',
  );
}

function rejectsRelayerIdentityMismatch(): void {
  const body = validThresholdEd25519SessionBody();
  body.relayerKeyId = 'ed25519:substituted-relayer';
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'relayerKeyId must match sessionPolicy.relayerKeyId',
  );
}

function rejectsBodyOwnedAppSessionClaims(): void {
  const body = validThresholdEd25519SessionBody();
  body.appSessionClaims = {
    kind: 'app_session_v1',
    sub: 'frost-vermillion-k7p9m2',
    appSessionVersion: '1',
  };
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'appSessionClaims',
  );
}

function rejectsBodyOwnedExpectedOrigin(): void {
  const body = validThresholdEd25519SessionBody();
  body.expected_origin = 'http://localhost';
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'expected_origin',
  );
}

function rejectsBodyOwnedEcdsaSessionClaims(): void {
  const body = validThresholdEd25519SessionBody();
  body.ecdsaSessionClaims = {
    kind: 'router_ab_ecdsa_derivation_wallet_session_v1',
    walletId: 'frost-vermillion-k7p9m2',
  };
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'ecdsaSessionClaims',
  );
}

test('threshold-ed25519 session route accepts the exact passkey Yao refresh body', acceptsExactYaoBudgetRefreshBody);
test('threshold-ed25519 session route requires a WebAuthn proof', rejectsMissingWebAuthnProof);
test('threshold-ed25519 session route requires jwt session kind', rejectsMissingJwtSessionKind);
test('threshold-ed25519 session route requires complete Yao policy identity', rejectsIncompleteYaoPolicy);
test('threshold-ed25519 session route requires exactly two participants', rejectsInvalidParticipantTuple);
test('threshold-ed25519 session route rejects relayer identity substitution', rejectsRelayerIdentityMismatch);
test('threshold-ed25519 session route rejects body-owned app session claims', rejectsBodyOwnedAppSessionClaims);
test('threshold-ed25519 session route rejects body-owned expected origin', rejectsBodyOwnedExpectedOrigin);
test('threshold-ed25519 session route rejects body-owned ECDSA session claims', rejectsBodyOwnedEcdsaSessionClaims);
