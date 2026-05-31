import { thresholdEcdsaChainTargetFromChainFamily, toWalletId } from '../signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '../signingEngine/session/identity/emailOtpHssIdentity';
import {
  buildEmailOtpWorkerIssuedSessionHandle,
  buildEmailOtpWorkerSessionSecretSource,
  buildFido2HmacSecretSource,
  buildSecureEnclaveWrappedSecretSource,
  buildWebAuthnPrfFirstSecretSource,
} from './types';
import type {
  AuthenticatorResult,
  ClientSecretSource,
  EcdsaRoleLocalPendingStateBlob,
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
  EcdsaRoleLocalSessionRecordState,
  EmailOtpWorkerIssuedSessionHandle,
  PlatformResult,
  PlatformRuntime,
  PrepareEcdsaClientBootstrapInput,
  RequiredPrfAuthenticatorSuccess,
  SignerCryptoResult,
} from './types';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types/webauthn';

declare const runtime: PlatformRuntime;
declare const platformResult: PlatformResult<{ value: string }, 'failed'>;
declare const signerResult: SignerCryptoResult<{ value: string }, 'invalid_context'>;
declare const secretSource: ClientSecretSource;
declare const registrationCredential: WebAuthnRegistrationCredential;
declare const authenticationCredential: WebAuthnAuthenticationCredential;
declare const hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
declare const relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
declare const pendingBlob: EcdsaRoleLocalPendingStateBlob;
declare const readyBlob: EcdsaRoleLocalReadyStateBlob;
declare const readyRecord: EcdsaRoleLocalReadyRecord;
declare const requiredPrfAuthenticatorSuccess: RequiredPrfAuthenticatorSuccess;

const emailOtpWorkerIssuedSessionHandleFromBuilder = buildEmailOtpWorkerIssuedSessionHandle({
  sessionId: 'otp-session',
  walletId: toWalletId('wallet_alice'),
  rpId: toRpId('wallet.example'),
  authSubjectId: toEmailOtpAuthSubjectId('google:alice'),
  action: 'threshold_ecdsa_bootstrap',
  operation: 'sign',
  chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'tempo', chainId: 42431 }),
});

const prepareInput = {
  kind: 'prepare_ecdsa_client_bootstrap_v1',
  algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
  context: {
    walletId: toWalletId('wallet_alice'),
    rpId: toRpId('wallet.example'),
    chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'evm', chainId: 5042002 }),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-key'),
    signingRootId: toEcdsaHssSigningRootId('root'),
    signingRootVersion: toEcdsaHssSigningRootVersion('v1'),
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
  },
  participants: {
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
  },
  secretSource: buildWebAuthnPrfFirstSecretSource(requiredPrfAuthenticatorSuccess),
} satisfies PrepareEcdsaClientBootstrapInput;

runtime.signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
runtime.signerCrypto.finalizeEcdsaClientBootstrap({
  kind: 'finalize_ecdsa_client_bootstrap_v1',
  pendingStateBlob: pendingBlob,
  relayerPublicIdentity: {
    relayerKeyId: 'relayer',
    relayerPublicKey33B64u,
    groupPublicKey33B64u: 'group',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
  },
});

if (platformResult.ok) {
  platformResult.value.value;
  // @ts-expect-error failure fields cannot be assigned from successful platform results
  const code: 'failed' = platformResult.code;
  void code;
} else {
  platformResult.code;
  // @ts-expect-error success values cannot be assigned from failed platform results
  const value: { value: string } = platformResult.value;
  void value;
}

if (signerResult.ok) {
  signerResult.value.value;
  // @ts-expect-error signer-crypto success branches do not carry failure kind
  const failure: 'command' = signerResult.failure;
  void failure;
} else if (signerResult.failure === 'command') {
  signerResult.code satisfies 'invalid_context';
} else {
  signerResult.code satisfies 'unavailable' | 'worker_transport_failure' | 'native_binding_failure' | 'timeout';
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
    secretSource.handle.sessionId;
    break;
}

runtime.signerCrypto.prepareEcdsaClientBootstrap({
  ...prepareInput,
  secretSource: buildSecureEnclaveWrappedSecretSource({
    keyId: 'key',
    accessGroup: 'group',
  }),
});

runtime.signerCrypto.prepareEcdsaClientBootstrap({
  ...prepareInput,
  secretSource: buildFido2HmacSecretSource({
    credentialIdB64u: 'credential',
    rpId: toRpId('wallet.example'),
  }),
});

runtime.signerCrypto.prepareEcdsaClientBootstrap({
  ...prepareInput,
  // @ts-expect-error ECDSA bootstrap participants are fixed to client=1, relayer=2.
  participants: { clientParticipantId: 0, relayerParticipantId: 2, participantIds: [0, 2] },
});

runtime.signerCrypto.finalizeEcdsaClientBootstrap({
  kind: 'finalize_ecdsa_client_bootstrap_v1',
  // @ts-expect-error finalize requires a pending state blob, not a ready state blob
  pendingStateBlob: readyBlob,
  relayerPublicIdentity: {
    relayerKeyId: 'relayer',
    relayerPublicKey33B64u,
    groupPublicKey33B64u: 'group',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
  },
});

const requiredPrfCreate = {
  ok: true,
  operation: 'create_passkey',
  requirePrfFirst: true,
  credential: registrationCredential,
  credentialIdB64u: 'credential',
  rawIdB64u: 'raw',
  rpId: toRpId('wallet.example'),
  prf: {
    kind: 'required',
    prfFirstB64u: 'first',
  },
} satisfies RequiredPrfAuthenticatorSuccess;
void requiredPrfCreate;

const requiredPrfGet = {
  ok: true,
  operation: 'get_passkey',
  requirePrfFirst: true,
  credential: authenticationCredential,
  credentialIdB64u: 'credential',
  rawIdB64u: 'raw',
  rpId: toRpId('wallet.example'),
  prf: {
    kind: 'required',
    prfFirstB64u: 'first',
  },
} satisfies RequiredPrfAuthenticatorSuccess;
void requiredPrfGet;

const missingRequiredPrf = {
  ok: true,
  operation: 'get_passkey',
  requirePrfFirst: true,
  credential: authenticationCredential,
  credentialIdB64u: 'credential',
  rawIdB64u: 'raw',
  rpId: toRpId('wallet.example'),
  prf: {
    // @ts-expect-error required PRF authenticator success must include prfFirstB64u
    kind: 'not_requested_or_unavailable',
  },
} satisfies AuthenticatorResult;
void missingRequiredPrf;

const mixedSecretSource = {
  kind: 'email_otp_worker_session',
  handle: emailOtpWorkerIssuedSessionHandleFromBuilder,
  credentialIdB64u: 'credential',
};
// @ts-expect-error Email OTP worker-session sources cannot include passkey fields or bypass builders
mixedSecretSource satisfies ClientSecretSource;
void mixedSecretSource;

const missingSecretSourceIdentity = {
  kind: 'webauthn_prf_first',
  prfFirstB64u: 'first',
  credentialIdB64u: 'credential',
};
// @ts-expect-error WebAuthn PRF secret sources require rpId
missingSecretSourceIdentity satisfies ClientSecretSource;
void missingSecretSourceIdentity;

const directWebAuthnSecretSource = {
  kind: 'webauthn_prf_first',
  prfFirstB64u: 'first',
  rpId: toRpId('wallet.example'),
  credentialIdB64u: 'credential',
};
// @ts-expect-error ClientSecretSource branches are builder-only and carry a private brand
directWebAuthnSecretSource satisfies ClientSecretSource;

const broadSpreadSecretSource = {
  ...directWebAuthnSecretSource,
};
// @ts-expect-error broad object spreads cannot forge builder-only secret-source branches
broadSpreadSecretSource satisfies ClientSecretSource;

const emailOtpWorkerSecretSource = buildEmailOtpWorkerSessionSecretSource(
  emailOtpWorkerIssuedSessionHandleFromBuilder,
);
void emailOtpWorkerSecretSource;

const directEmailOtpWorkerSessionHandle = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'otp-session',
  walletId: toWalletId('wallet_alice'),
  rpId: toRpId('wallet.example'),
  authSubjectId: toEmailOtpAuthSubjectId('google:alice'),
  action: 'threshold_ecdsa_bootstrap',
  operation: 'sign',
  chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'tempo', chainId: 42431 }),
};
// @ts-expect-error Worker-issued handle branches are builder-only and carry a private brand
directEmailOtpWorkerSessionHandle satisfies EmailOtpWorkerIssuedSessionHandle;

const broadSpreadEmailOtpWorkerSessionHandle = {
  ...directEmailOtpWorkerSessionHandle,
};
// @ts-expect-error broad object spreads cannot forge worker-issued handle branches
broadSpreadEmailOtpWorkerSessionHandle satisfies EmailOtpWorkerIssuedSessionHandle;

// @ts-expect-error Email OTP worker-session handle requires authSubjectId.
buildEmailOtpWorkerIssuedSessionHandle({
  sessionId: 'otp-session',
  walletId: toWalletId('wallet_alice'),
  rpId: toRpId('wallet.example'),
  action: 'threshold_ecdsa_bootstrap',
  operation: 'sign',
  chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'tempo', chainId: 42431 }),
});

// @ts-expect-error ECDSA worker-session handles require chainTarget.
buildEmailOtpWorkerIssuedSessionHandle({
  sessionId: 'otp-session',
  walletId: toWalletId('wallet_alice'),
  rpId: toRpId('wallet.example'),
  authSubjectId: toEmailOtpAuthSubjectId('google:alice'),
  action: 'threshold_ecdsa_bootstrap',
  operation: 'sign',
});

// @ts-expect-error Ed25519 worker-session handles must not include chainTarget.
buildEmailOtpWorkerIssuedSessionHandle({
  sessionId: 'otp-session',
  walletId: toWalletId('wallet_alice'),
  rpId: toRpId('wallet.example'),
  authSubjectId: toEmailOtpAuthSubjectId('google:alice'),
  action: 'threshold_ed25519_session',
  operation: 'wallet_unlock',
  chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'tempo', chainId: 42431 }),
});

declare function useReadyBlob(blob: EcdsaRoleLocalReadyStateBlob): void;
// @ts-expect-error pending ECDSA blobs cannot be used as ready signing/export material
useReadyBlob(pendingBlob);
useReadyBlob(readyBlob);

const passkeyReadyRoleLocalState = {
  kind: 'ready_passkey_role_local_material_v1',
  authMethod: 'passkey',
  readyRecord,
  inlineSigningMaterial: {
    kind: 'inline_client_share',
    clientAdditiveShare32B64u: 'share',
  },
} satisfies EcdsaRoleLocalSessionRecordState;
void passkeyReadyRoleLocalState;

const passkeyWorkerRoleLocalState = {
  kind: 'ready_passkey_role_local_material_v1',
  authMethod: 'passkey',
  readyRecord,
  inlineSigningMaterial: {
    kind: 'email_otp_worker_share',
    workerSessionId: 'otp-session',
  },
};
// @ts-expect-error passkey-ready role-local state cannot carry Email OTP worker material
passkeyWorkerRoleLocalState satisfies EcdsaRoleLocalSessionRecordState;

const reauthWithInlineRoleLocalState = {
  kind: 'reauth_required_role_local_material_v1',
  authMethod: 'email_otp',
  readyRecord,
  reason: 'expired',
  inlineSigningMaterial: {
    kind: 'inline_client_share',
    clientAdditiveShare32B64u: 'share',
  },
};
// @ts-expect-error reauth-required role-local state cannot carry ready signing material
reauthWithInlineRoleLocalState satisfies EcdsaRoleLocalSessionRecordState;

const incompletePlatformRuntime = {
  kind: 'browser',
  storage: runtime.storage,
  signerCrypto: runtime.signerCrypto,
};
// @ts-expect-error platform runtime construction requires every port
incompletePlatformRuntime satisfies PlatformRuntime;

void hssClientSharePublicKey33B64u;
