import type {
  ClientSecretSource,
  PlatformResult,
  PlatformRuntime,
  PrepareEcdsaClientBootstrapInput,
} from './types';

declare const runtime: PlatformRuntime;
declare const result: PlatformResult<{ value: string }, 'failed'>;
declare const secretSource: ClientSecretSource;

runtime.signerCompute.prepareEcdsaClientBootstrap({
  secretSource: {
    kind: 'webauthn_prf_first',
    prfFirstB64u: 'first',
    rpId: 'wallet.example',
    credentialIdB64u: 'credential',
  },
  walletId: 'wallet_subject_alice',
  rpId: 'wallet.example',
  participantIds: [0, 1, 2],
} satisfies PrepareEcdsaClientBootstrapInput);

if (result.ok) {
  result.value.value;
  // @ts-expect-error failure fields cannot be assigned from successful platform results
  const code: 'failed' = result.code;
  void code;
} else {
  result.code;
  // @ts-expect-error success values cannot be assigned from failed platform results
  const value: { value: string } = result.value;
  void value;
}

switch (secretSource.kind) {
  case 'webauthn_prf_first':
    secretSource.credentialIdB64u;
    break;
  case 'secure_enclave_wrapped_secret':
    secretSource.accessGroup;
    break;
  case 'fido2_hmac_secret':
    secretSource.rpId;
    break;
  case 'email_otp_worker_session':
    secretSource.sessionId;
    break;
}

runtime.signerCompute.prepareEcdsaClientBootstrap({
  secretSource: {
    // @ts-expect-error secure enclave sources are unsupported by the MVP ECDSA bootstrap command
    kind: 'secure_enclave_wrapped_secret',
    keyId: 'key',
    accessGroup: 'group',
  },
  walletId: 'wallet_subject_alice',
  rpId: 'wallet.example',
  participantIds: [0, 1, 2],
});

runtime.signerCompute.prepareEcdsaClientBootstrap({
  secretSource: {
    // @ts-expect-error FIDO2 HMAC secret sources are unsupported by the MVP ECDSA bootstrap command
    kind: 'fido2_hmac_secret',
    credentialIdB64u: 'credential',
    rpId: 'wallet.example',
  },
  walletId: 'wallet_subject_alice',
  rpId: 'wallet.example',
  participantIds: [0, 1, 2],
});
