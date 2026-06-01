import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
  buildEmailOtpWorkerIssuedSessionHandle,
  buildRelayerKeyId,
  type AuthenticatorResult,
  type BootstrapEcdsaSessionRouteInput,
  type BootstrapEcdsaSessionRouteOutput,
  type DurableRecordStore,
  type EcdsaRelayerClient,
  type EcdsaRoleLocalReadyRecord,
  type FinalizeEcdsaClientBootstrapOutput,
  type PrepareEcdsaClientBootstrapOutput,
  type SignerCryptoPort,
  type EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import {
  createProvisionEcdsaUseCase,
  type ProvisionEcdsaDeps,
  type ProvisionEcdsaInput,
} from '@/core/signingEngine/useCases/provisionEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

function b64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function compressedSecp256k1PublicKeyB64u(fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = fill % 2 === 0 ? 2 : 3;
  return base64UrlEncode(bytes);
}

const walletId = toWalletId('wallet_alice');
const rpId = toRpId('wallet.example');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
});
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ecdsa-threshold-key');
const signingRootId = toEcdsaHssSigningRootId('root');
const signingRootVersion = toEcdsaHssSigningRootVersion('v1');
const passkeyAuthMethod = buildEcdsaRoleLocalPasskeyAuthMethod({
  credentialIdB64u: 'credential-passkey',
  rpId,
});
const emailOtpHandle = buildEmailOtpWorkerIssuedSessionHandle({
  sessionId: 'email-session',
  walletId,
  rpId,
  authSubjectId: toEmailOtpAuthSubjectId(walletId),
  action: 'threshold_ecdsa_bootstrap',
  operation: 'wallet_unlock',
  chainTarget,
});
const relayerKeyId = buildRelayerKeyId('relayer-key');

function requireEcdsaEmailOtpHandle(
  handle: EmailOtpWorkerIssuedSessionHandle,
): Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }> {
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('expected ECDSA Email OTP worker handle');
  }
  return handle;
}

const credential: WebAuthnAuthenticationCredential = {
  id: passkeyAuthMethod.credentialIdB64u,
  rawId: passkeyAuthMethod.credentialIdB64u,
  type: 'public-key',
  authenticatorAttachment: undefined,
  response: {
    clientDataJSON: b64u(8, 1),
    authenticatorData: b64u(8, 2),
    signature: b64u(64, 3),
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: b64u(32, 4),
        second: undefined,
      },
    },
  },
};

function baseInput(): ProvisionEcdsaInput {
  return {
    walletId,
    rpId,
    chainTarget,
    keyHandle: 'ecdsa-key-handle',
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: passkeyAuthMethod.credentialIdB64u,
      challengeB64u: b64u(32, 5),
    },
    route: {
      relayerKeyId,
      requestId: 'request',
      sessionId: 'threshold-session',
      walletSigningSessionId: 'wallet-signing-session',
      ttlMs: 60_000,
      remainingUses: 8,
      sessionKind: 'jwt',
      auth: { kind: 'publishable_key', token: 'pk_test' },
    },
  };
}

function preparedOutput(): PrepareEcdsaClientBootstrapOutput {
  const facts = publicFacts(baseInput());
  return {
    pendingStateBlob: {
      kind: 'ecdsa_role_local_pending_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: b64u(48, 6),
    },
    clientBootstrap: {
      contextBinding32B64u: b64u(32, 7),
      hssClientSharePublicKey33B64u: facts.hssClientSharePublicKey33B64u,
      clientShareRetryCounter: 0,
      participantId: 1,
    },
    publicFacts: {
      hssClientSharePublicKey33B64u: facts.hssClientSharePublicKey33B64u,
      clientVerifyingShareB64u: compressedSecp256k1PublicKeyB64u(9),
    },
  };
}

function relayerOutput(input: ProvisionEcdsaInput): BootstrapEcdsaSessionRouteOutput {
  const facts = publicFacts(input);
  return {
    kind: 'bootstrap_ecdsa_session_route_output_v1',
    walletId: input.walletId,
    rpId: input.rpId,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    keyHandle: input.keyHandle,
    relayerPublicIdentity: {
      relayerKeyId: input.route.relayerKeyId,
      relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
      groupPublicKey33B64u: facts.groupPublicKey33B64u,
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    participantIds: [1, 2],
    sessionId: input.route.sessionId,
    walletSigningSessionId: input.route.walletSigningSessionId,
    expiresAtMs: 1_900_000_000_000,
    remainingUses: input.route.remainingUses,
    thresholdSessionAuthToken: 'jwt',
  };
}

function publicFacts(input: ProvisionEcdsaInput) {
  return buildEcdsaRoleLocalPublicFacts({
    walletId: input.walletId,
    rpId: input.rpId,
    chainTarget: input.chainTarget,
    keyHandle: input.keyHandle,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: input.participantIds,
    hssClientSharePublicKey33B64u: compressedSecp256k1PublicKeyB64u(8),
    relayerPublicKey33B64u: compressedSecp256k1PublicKeyB64u(10),
    groupPublicKey33B64u: compressedSecp256k1PublicKeyB64u(11),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    contextBinding32B64u: b64u(32, 7),
  });
}

function finalizedOutput(): FinalizeEcdsaClientBootstrapOutput {
  const facts = publicFacts(baseInput());
  return {
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: b64u(64, 12),
    },
    publicFacts: {
      hssClientSharePublicKey33B64u: facts.hssClientSharePublicKey33B64u,
      clientVerifyingShareB64u: compressedSecp256k1PublicKeyB64u(9),
      relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
      groupPublicKey33B64u: compressedSecp256k1PublicKeyB64u(11),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
      contextBinding32B64u: facts.contextBinding32B64u,
    },
  };
}

function readyRecord(input: ProvisionEcdsaInput): EcdsaRoleLocalReadyRecord {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: finalizedOutput().stateBlob,
    publicFacts: publicFacts(input),
    authMethod:
      input.authMethod.kind === 'email_otp'
        ? buildEcdsaRoleLocalEmailOtpAuthMethod({
            authSubjectId: input.authMethod.handle.authSubjectId,
          })
        : buildEcdsaRoleLocalPasskeyAuthMethod({
            credentialIdB64u: input.authMethod.credentialIdB64u,
            rpId: input.rpId,
          }),
  });
}

type Captures = {
  authenticatorRuns: unknown[];
  prepareInputs: unknown[];
  relayerInputs: BootstrapEcdsaSessionRouteInput[];
  finalizeInputs: unknown[];
  persistInputs: unknown[];
};

function createDeps(args: {
  loadValue?: Awaited<ReturnType<DurableRecordStore['loadEcdsaRoleLocalReadyRecord']>>;
  authenticatorResult?: AuthenticatorResult;
  prepareResult?: Awaited<ReturnType<SignerCryptoPort['prepareEcdsaClientBootstrap']>>;
  relayerResult?: Awaited<ReturnType<EcdsaRelayerClient['bootstrapEcdsaSession']>>;
  finalizeResult?: Awaited<ReturnType<SignerCryptoPort['finalizeEcdsaClientBootstrap']>>;
} = {}): { deps: ProvisionEcdsaDeps; captures: Captures } {
  const captures: Captures = {
    authenticatorRuns: [],
    prepareInputs: [],
    relayerInputs: [],
    finalizeInputs: [],
    persistInputs: [],
  };
  const input = baseInput();
  const deps: ProvisionEcdsaDeps = {
    authenticator: {
      async run(operation) {
        captures.authenticatorRuns.push(operation);
        return (
          args.authenticatorResult || {
            ok: true,
            operation: 'get_passkey',
            requirePrfFirst: true,
            credential,
            credentialIdB64u: passkeyAuthMethod.credentialIdB64u,
            rawIdB64u: passkeyAuthMethod.credentialIdB64u,
            rpId,
            prf: { kind: 'required', prfFirstB64u: b64u(32, 4) },
          }
        );
      },
    },
    signerCrypto: {
      async prepareEcdsaClientBootstrap(prepareInput) {
        captures.prepareInputs.push(prepareInput);
        return args.prepareResult || { ok: true, value: preparedOutput() };
      },
      async finalizeEcdsaClientBootstrap(finalizeInput) {
        captures.finalizeInputs.push(finalizeInput);
        return args.finalizeResult || { ok: true, value: finalizedOutput() };
      },
    },
    storage: {
      async loadEcdsaRoleLocalReadyRecord() {
        return args.loadValue || { ok: true, value: { kind: 'not_found' } };
      },
      async persistEcdsaRoleLocalReadyRecord(persistInput) {
        captures.persistInputs.push(persistInput);
        return { ok: true, value: { kind: 'persisted' } };
      },
    },
    relayer: {
      async bootstrapEcdsaSession(routeInput) {
        captures.relayerInputs.push(routeInput);
        return args.relayerResult || { ok: true, value: relayerOutput(input) };
      },
    },
    clock: {
      nowMs: () => 1_800_000_000_000,
    },
  };
  return { deps, captures };
}

test('returns existing durable ready record before prompting or bootstrapping', async () => {
  const input = baseInput();
  const existingRecord = readyRecord(input);
  const { deps, captures } = createDeps({
    loadValue: { ok: true, value: { kind: 'found', record: existingRecord } },
  });
  const result = await createProvisionEcdsaUseCase(deps).provision(input);

  expect(result).toEqual({ ok: true, record: existingRecord });
  expect(captures.authenticatorRuns).toEqual([]);
  expect(captures.prepareInputs).toEqual([]);
  expect(captures.relayerInputs).toEqual([]);
  expect(captures.finalizeInputs).toEqual([]);
  expect(captures.persistInputs).toEqual([]);
});

test('provisions passkey ECDSA material through signer, relayer, finalize, and persist', async () => {
  const input = baseInput();
  const { deps, captures } = createDeps();
  const result = await createProvisionEcdsaUseCase(deps).provision(input);

  expect(result.ok).toBe(true);
  expect(captures.authenticatorRuns).toHaveLength(1);
  expect(captures.prepareInputs).toHaveLength(1);
  expect(captures.relayerInputs).toHaveLength(1);
  expect(captures.finalizeInputs).toHaveLength(1);
  expect(captures.persistInputs).toHaveLength(1);
  expect(captures.relayerInputs[0]).toMatchObject({
    kind: 'bootstrap_ecdsa_session_route_v1',
    walletId,
    rpId,
    keyScope: 'evm-family',
    clientBootstrap: preparedOutput().clientBootstrap,
  });
  expect(captures.persistInputs[0]).toMatchObject({
    storageKeyFacts: {
      walletId,
      rpId,
      keyHandle: input.keyHandle,
      authMethod: {
        kind: 'passkey',
        credentialIdB64u: passkeyAuthMethod.credentialIdB64u,
        rpId,
      },
    },
  });
});

test('maps signer command and invocation failures to distinct use-case codes', async () => {
  const command = createDeps({
    prepareResult: {
      ok: false,
      failure: 'command',
      code: 'crypto_failure',
      message: 'bad command',
    },
  });
  await expect(createProvisionEcdsaUseCase(command.deps).provision(baseInput())).resolves.toMatchObject({
    ok: false,
    code: 'signer_crypto_command_failed',
    source: 'signer_crypto',
    retryable: false,
  });

  const invocation = createDeps({
    prepareResult: {
      ok: false,
      failure: 'invocation',
      code: 'worker_transport_failure',
      message: 'worker down',
    },
  });
  await expect(createProvisionEcdsaUseCase(invocation.deps).provision(baseInput())).resolves.toMatchObject({
    ok: false,
    code: 'signer_crypto_invocation_failed',
    source: 'signer_crypto',
    retryable: true,
  });
});

test('maps relayer failures without finalizing client state', async () => {
  const { deps, captures } = createDeps({
    relayerResult: {
      ok: false,
      code: 'unavailable',
      message: 'relayer unavailable',
      retryable: true,
    },
  });
  const result = await createProvisionEcdsaUseCase(deps).provision(baseInput());

  expect(result).toMatchObject({
    ok: false,
    code: 'relayer_failed',
    source: 'relayer',
    retryable: true,
  });
  expect(captures.finalizeInputs).toEqual([]);
});

test('provisions Email OTP material from a worker-issued ECDSA handle', async () => {
  const input: ProvisionEcdsaInput = {
    ...baseInput(),
    authMethod: {
      kind: 'email_otp',
      handle: requireEcdsaEmailOtpHandle(emailOtpHandle),
    },
  };
  const { deps, captures } = createDeps();
  const result = await createProvisionEcdsaUseCase(deps).provision(input);

  expect(result.ok).toBe(true);
  expect(captures.authenticatorRuns).toEqual([]);
  expect(captures.prepareInputs).toHaveLength(1);
  expect(captures.prepareInputs[0]).toMatchObject({
    secretSource: {
      kind: 'email_otp_worker_session',
      handle: emailOtpHandle,
    },
  });
  expect(captures.persistInputs[0]).toMatchObject({
    storageKeyFacts: {
      authMethod: {
        kind: 'email_otp',
        authSubjectId: emailOtpHandle.authSubjectId,
      },
    },
  });
});
