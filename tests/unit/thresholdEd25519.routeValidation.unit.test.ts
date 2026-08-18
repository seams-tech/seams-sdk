import { expect, test } from '@playwright/test';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  parseThresholdEd25519OperationStepUpGrantRequest,
  parseThresholdEd25519SessionRouteRequest,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/session/thresholdEd25519RequestValidation';

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
    sessionKind: 'opaque',
    sessionPolicy: validThresholdEd25519SessionPolicy(),
    webauthn_authentication: validWebAuthnAuthentication(),
  };
}

function validOperationStepUpBody(
  proof: Record<string, unknown>,
  materialRecovery: Record<string, unknown> = { kind: 'not_requested' },
): Record<string, unknown> {
  return {
    kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
    normalSigningRequest: {
      scope: { kind: 'router_ab_ed25519_normal_signing_scope_v2' },
      intent: { kind: 'near_transaction_v1' },
    },
    displayDigest: 'display-digest',
    proof,
    materialRecovery,
  };
}

function expectInvalidBody(
  parsed: ReturnType<typeof parseThresholdEd25519SessionRouteRequest>,
  message: string,
): void {
  expect(parsed.ok).toBe(false);
  if (parsed.ok) throw new Error('expected invalid threshold-ed25519 route body');
  expect(parsed.body.message).toContain(message);
}

function expectInvalidOperationStepUpBody(
  parsed: ReturnType<typeof parseThresholdEd25519OperationStepUpGrantRequest>,
  message: string,
): void {
  expect(parsed.ok).toBe(false);
  if (parsed.ok) throw new Error('expected invalid operation step-up body');
  expect(parsed.body.message).toContain(message);
}

function acceptsExactPasskeyOperationStepUpProof(): void {
  const authority = validThresholdEd25519SessionPolicy().authority;
  const parsed = parseThresholdEd25519OperationStepUpGrantRequest(
    validOperationStepUpBody({
      kind: 'passkey',
      authority,
      webauthn_authentication: validWebAuthnAuthentication(),
    }),
  );

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request.proof).toMatchObject({
    kind: 'passkey',
    authority,
  });
}

async function acceptsExactEmailOtpOperationStepUpProof(): Promise<void> {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'frost-vermillion-k7p9m2',
    provider: 'email',
    providerUserId: 'email-user-route-validation',
    emailHashHex: 'email-hash-route-validation',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const parsed = parseThresholdEd25519OperationStepUpGrantRequest(
    validOperationStepUpBody(
      {
        kind: 'email_otp',
        authority_ref: authorityRef,
        provider_subject_id: 'email-user-route-validation',
        challenge_id: 'challenge-route-validation',
        otp_code: '123456',
      },
      {
        kind: 'not_requested',
      },
    ),
  );

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request.proof).toEqual({
    kind: 'email_otp',
    authorityRef,
    providerSubjectId: 'email-user-route-validation',
    challengeId: 'challenge-route-validation',
    otpCode: '123456',
  });
  expect(parsed.request.materialRecovery).toEqual({
    kind: 'not_requested',
  });
}

async function acceptsEmailOtpOperationStepUpWithoutMaterialRecovery(): Promise<void> {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'frost-vermillion-k7p9m2',
    provider: 'email',
    providerUserId: 'email-user-route-validation',
    emailHashHex: 'email-hash-route-validation',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const parsed = parseThresholdEd25519OperationStepUpGrantRequest(
    validOperationStepUpBody({
      kind: 'email_otp',
      authority_ref: authorityRef,
      provider_subject_id: 'email-user-route-validation',
      challenge_id: 'challenge-route-validation',
      otp_code: '123456',
    }),
  );
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request.materialRecovery).toEqual({ kind: 'not_requested' });
}

async function acceptsEmailOtpOperationStepUpWithFactorReleaseMaterialRecovery(): Promise<void> {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'frost-vermillion-k7p9m2',
    provider: 'email',
    providerUserId: 'email-user-route-validation',
    emailHashHex: 'email-hash-route-validation',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const parsed = parseThresholdEd25519OperationStepUpGrantRequest(
    validOperationStepUpBody(
      {
        kind: 'email_otp',
        authority_ref: authorityRef,
        provider_subject_id: 'email-user-route-validation',
        challenge_id: 'challenge-route-validation',
        otp_code: '123456',
      },
      {
        kind: 'email_otp_factor_release_v1',
        worker_ephemeral_public_key_65_b64u: 'worker-ephemeral-public-key',
      },
    ),
  );
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request.materialRecovery).toEqual({
    kind: 'email_otp_factor_release_v1',
    workerEphemeralPublicKey65B64u: 'worker-ephemeral-public-key',
  });
}

async function rejectsMixedOperationStepUpProofFields(): Promise<void> {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'frost-vermillion-k7p9m2',
    provider: 'email',
    providerUserId: 'email-user-route-validation',
    emailHashHex: 'email-hash-route-validation',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  expectInvalidOperationStepUpBody(
    parseThresholdEd25519OperationStepUpGrantRequest(
      validOperationStepUpBody({
        kind: 'email_otp',
        authority_ref: authorityRef,
        provider_subject_id: 'email-user-route-validation',
        challenge_id: 'challenge-route-validation',
        otp_code: '123456',
        webauthn_authentication: validWebAuthnAuthentication(),
      }),
    ),
    'Unsupported Email OTP operation step-up proof field: webauthn_authentication',
  );
}

function rejectsLegacyFlatOperationStepUpProof(): void {
  const body = validOperationStepUpBody({
    kind: 'passkey',
    authority: validThresholdEd25519SessionPolicy().authority,
    webauthn_authentication: validWebAuthnAuthentication(),
  });
  const proof = body.proof as Record<string, unknown>;
  delete body.proof;
  body.authority = proof.authority;
  body.webauthn_authentication = proof.webauthn_authentication;
  expectInvalidOperationStepUpBody(
    parseThresholdEd25519OperationStepUpGrantRequest(body),
    'Unsupported operation step-up grant field: authority',
  );
}

function rejectsPasskeyMaterialRecovery(): void {
  expectInvalidOperationStepUpBody(
    parseThresholdEd25519OperationStepUpGrantRequest(
      validOperationStepUpBody(
        {
          kind: 'passkey',
          authority: validThresholdEd25519SessionPolicy().authority,
          webauthn_authentication: validWebAuthnAuthentication(),
        },
        {
          kind: 'email_otp_local_material_v1',
          wrappedCiphertext: 'wrapped-ciphertext',
          enrollmentSealKeyVersion: 'enrollment-seal-v1',
        },
      ),
    ),
    'Unsupported Passkey operation step-up material recovery field: wrappedCiphertext',
  );
}

async function rejectsRetiredEmailOtpMaterialRecovery(): Promise<void> {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: 'frost-vermillion-k7p9m2',
    provider: 'email',
    providerUserId: 'email-user-route-validation',
    emailHashHex: 'email-hash-route-validation',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  expectInvalidOperationStepUpBody(
    parseThresholdEd25519OperationStepUpGrantRequest(
      validOperationStepUpBody(
        {
          kind: 'email_otp',
          authority_ref: authorityRef,
          provider_subject_id: 'email-user-route-validation',
          challenge_id: 'challenge-route-validation',
          otp_code: '123456',
        },
        {
          kind: 'email_otp_local_material_v1',
        },
      ),
    ),
    'Email OTP operation step-up materialRecovery.kind is invalid',
  );
}

function acceptsExactYaoBudgetRefreshBody(): void {
  const parsed = parseThresholdEd25519SessionRouteRequest(validThresholdEd25519SessionBody());

  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request).toMatchObject({
    relayerKeyId: 'ed25519:relayer',
    sessionKind: 'opaque',
    routeAuth: { kind: 'passkey' },
    sessionPolicy: {
      thresholdSessionId: 'tsess-route-validation',
      participantIds: [1, 2],
    },
  });
}

function rejectsMalformedWebAuthnProof(): void {
  const body = validThresholdEd25519SessionBody();
  body.webauthn_authentication = { id: 'incomplete' };
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'webauthn_authentication is invalid',
  );
}

function rejectsNonOpaqueSessionKind(): void {
  const body = validThresholdEd25519SessionBody();
  body.sessionKind = 'jwt';
  expectInvalidBody(
    parseThresholdEd25519SessionRouteRequest(body),
    'requires sessionKind=opaque',
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

function normalizesThresholdSessionIdentityAtRouteBoundary(): void {
  const body = validThresholdEd25519SessionBody();
  const policy = validThresholdEd25519SessionPolicy();
  policy.thresholdSessionId = '  tsess-route-validation  ';
  body.sessionPolicy = policy;
  const parsed = parseThresholdEd25519SessionRouteRequest(body);
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error(parsed.body.message);
  expect(parsed.request.sessionPolicy.thresholdSessionId).toBe('tsess-route-validation');
}

function rejectsBodyOwnedAppSessionClaims(): void {
  const body = validThresholdEd25519SessionBody();
  body.appSessionClaims = {
    kind: 'app_session_v1',
    sub: 'frost-vermillion-k7p9m2',
    appSessionVersion: '1',
  };
  expectInvalidBody(parseThresholdEd25519SessionRouteRequest(body), 'appSessionClaims');
}

function rejectsBodyOwnedExpectedOrigin(): void {
  const body = validThresholdEd25519SessionBody();
  body.expected_origin = 'http://localhost';
  expectInvalidBody(parseThresholdEd25519SessionRouteRequest(body), 'expected_origin');
}

function rejectsBodyOwnedEcdsaSessionClaims(): void {
  const body = validThresholdEd25519SessionBody();
  body.ecdsaSessionClaims = {
    kind: 'router_ab_ecdsa_derivation_wallet_session_v1',
    walletId: 'frost-vermillion-k7p9m2',
  };
  expectInvalidBody(parseThresholdEd25519SessionRouteRequest(body), 'ecdsaSessionClaims');
}

test(
  'threshold-ed25519 session route accepts the exact passkey Yao refresh body',
  acceptsExactYaoBudgetRefreshBody,
);
test(
  'threshold-ed25519 session route rejects a malformed WebAuthn proof',
  rejectsMalformedWebAuthnProof,
);
test(
  'threshold-ed25519 session route normalizes threshold-session identity once',
  normalizesThresholdSessionIdentityAtRouteBoundary,
);
test('threshold-ed25519 session route requires opaque session kind', rejectsNonOpaqueSessionKind);
test(
  'threshold-ed25519 session route requires complete Yao policy identity',
  rejectsIncompleteYaoPolicy,
);
test(
  'threshold-ed25519 session route requires exactly two participants',
  rejectsInvalidParticipantTuple,
);
test(
  'threshold-ed25519 session route rejects relayer identity substitution',
  rejectsRelayerIdentityMismatch,
);
test(
  'threshold-ed25519 session route rejects body-owned app session claims',
  rejectsBodyOwnedAppSessionClaims,
);
test(
  'threshold-ed25519 session route rejects body-owned expected origin',
  rejectsBodyOwnedExpectedOrigin,
);
test(
  'threshold-ed25519 session route rejects body-owned ECDSA session claims',
  rejectsBodyOwnedEcdsaSessionClaims,
);
test(
  'threshold-ed25519 operation step-up accepts the exact Passkey proof branch',
  acceptsExactPasskeyOperationStepUpProof,
);
test(
  'threshold-ed25519 operation step-up accepts the exact Email OTP proof branch',
  acceptsExactEmailOtpOperationStepUpProof,
);
test(
  'threshold-ed25519 operation step-up permits an active Email OTP client without material recovery',
  acceptsEmailOtpOperationStepUpWithoutMaterialRecovery,
);
test(
  'threshold-ed25519 operation step-up accepts Email OTP factor-release material recovery',
  acceptsEmailOtpOperationStepUpWithFactorReleaseMaterialRecovery,
);
test(
  'threshold-ed25519 operation step-up rejects mixed factor proof fields',
  rejectsMixedOperationStepUpProofFields,
);
test(
  'threshold-ed25519 operation step-up rejects the retired flat proof shape',
  rejectsLegacyFlatOperationStepUpProof,
);
test(
  'threshold-ed25519 operation step-up rejects Passkey material recovery',
  rejectsPasskeyMaterialRecovery,
);
test(
  'threshold-ed25519 operation step-up rejects retired Email OTP material recovery',
  rejectsRetiredEmailOtpMaterialRecovery,
);
