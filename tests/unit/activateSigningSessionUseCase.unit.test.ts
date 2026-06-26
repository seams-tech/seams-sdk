import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseSigningGrantId,
  parseWalletKeyId,
} from '@shared/utils/domainIds';
import {
  buildEmailOtpWorkerIssuedSessionHandle,
  buildRelayerKeyId,
  type EcdsaRoleLocalAuthMethod,
  type EcdsaRoleLocalReadyRecord,
  type EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import {
  createActivateSigningSessionUseCase,
  type ActivateSigningSessionDeps,
  type ActivateSigningSessionSealPolicyResult,
  type ActivateSigningSessionSealWriteResult,
} from '@/core/signingEngine/useCases/activateSigningSession';
import {
  useCaseFailure,
  type ActivateSigningSessionInput,
  type ActivateSigningSessionLifecycleState,
  type Ed25519RelayerKeyId,
  type SigningSessionActivationEmailOtpEcdsaAuth,
  type SigningSessionActivationEmailOtpEd25519Auth,
  type SigningSessionActivationMaterial,
  type SigningSessionActivationPasskeyAuth,
  type SigningSessionSealWriteInput,
  type UnixTimeMs,
  type WarmSessionRemainingUses,
} from '@/core/signingEngine/useCases/lifecycle';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function b64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function compressedSecp256k1PublicKeyB64u(fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = fill % 2 === 0 ? 2 : 3;
  return base64UrlEncode(bytes);
}

function parsedDomain<T>(
  result: { ok: true; value: T } | { ok: false; error: { message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function ed25519Handle(
  handle: EmailOtpWorkerIssuedSessionHandle,
): Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ed25519_session' }> {
  if (handle.action !== 'threshold_ed25519_session') {
    throw new Error('expected Ed25519 worker handle');
  }
  return handle;
}

function ecdsaHandle(
  handle: EmailOtpWorkerIssuedSessionHandle,
): Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }> {
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('expected ECDSA worker handle');
  }
  return handle;
}

const walletId = toWalletId('wallet_alice');
const walletKeyId = parsedDomain(parseWalletKeyId('wallet-key-activation'));
const rpId = toRpId('wallet.example');
const authSubjectId = toEmailOtpAuthSubjectId('google:alice');
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
});
const otherChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42432,
});
const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId('ecdsa-threshold-key');
const signingRootId = toEcdsaHssSigningRootId('root');
const signingRootVersion = toEcdsaHssSigningRootVersion('v1');
const signingGrantId = parsedDomain(parseSigningGrantId('signing-grant'));
const ed25519ThresholdSessionId = parsedDomain(
  parseThresholdEd25519SessionId('threshold-ed25519-session'),
);
const ecdsaThresholdSessionId = parsedDomain(
  parseThresholdEcdsaSessionId('threshold-ecdsa-session'),
);
const ed25519RelayerKeyId = buildRelayerKeyId('ed25519-relayer') as Ed25519RelayerKeyId;
const expiresAtMs = 1_900_000_000_000 as UnixTimeMs;
const remainingUses = 8 as WarmSessionRemainingUses;

const passkeyAuthMethod = buildEcdsaRoleLocalPasskeyAuthMethod({
  credentialIdB64u: 'credential-passkey',
  rpId,
});
const emailOtpAuthMethod = buildEcdsaRoleLocalEmailOtpAuthMethod({
  authSubjectId,
});

const passkeyAuth = {
  kind: 'passkey',
  walletId,
  rpId,
  credentialIdB64u: passkeyAuthMethod.credentialIdB64u,
} satisfies SigningSessionActivationPasskeyAuth;

const emailOtpEd25519Auth = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId,
  workerHandle: ed25519Handle(
    buildEmailOtpWorkerIssuedSessionHandle({
      sessionId: 'email-ed25519-session',
      walletId,
      rpId,
      authSubjectId,
      action: 'threshold_ed25519_session',
      operation: 'wallet_unlock',
    }),
  ),
} satisfies SigningSessionActivationEmailOtpEd25519Auth;

function emailOtpEcdsaAuthFor(
  target: ThresholdEcdsaChainTarget,
): SigningSessionActivationEmailOtpEcdsaAuth {
  return {
    kind: 'email_otp',
    walletId,
    walletKeyId,
    authSubjectId,
    workerHandle: ecdsaHandle(
      buildEmailOtpWorkerIssuedSessionHandle({
        sessionId: 'email-ecdsa-session',
        walletId,
        walletKeyId,
        authSubjectId,
        action: 'threshold_ecdsa_bootstrap',
        operation: 'wallet_unlock',
        chainTarget: target,
      }),
    ),
  };
}

function publicFacts(target: ThresholdEcdsaChainTarget) {
  return buildEcdsaRoleLocalPublicFacts({
    walletId,
      walletKeyId,
    chainTarget: target,
    keyHandle: 'ecdsa-key-handle',
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    hssClientSharePublicKey33B64u: compressedSecp256k1PublicKeyB64u(8),
    relayerPublicKey33B64u: compressedSecp256k1PublicKeyB64u(10),
    groupPublicKey33B64u: compressedSecp256k1PublicKeyB64u(11),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    contextBinding32B64u: b64u(32, 7),
  });
}

function readyRecord(args: {
  authMethod: EcdsaRoleLocalAuthMethod;
  target?: ThresholdEcdsaChainTarget;
}): EcdsaRoleLocalReadyRecord {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: b64u(64, 12),
    },
    publicFacts: publicFacts(args.target || chainTarget),
    authMethod: args.authMethod,
  });
}

const ed25519Material = {
  kind: 'ed25519_session',
  thresholdSessionId: ed25519ThresholdSessionId,
  signingGrantId,
  relayerKeyId: ed25519RelayerKeyId,
} satisfies SigningSessionActivationMaterial;

function ecdsaMaterial(record: EcdsaRoleLocalReadyRecord): SigningSessionActivationMaterial {
  return {
    kind: 'ecdsa_session',
    thresholdSessionId: ecdsaThresholdSessionId,
    signingGrantId,
    record,
  };
}

type Captures = {
  policyInputs: unknown[];
  writes: SigningSessionSealWriteInput[];
  transitions: ActivateSigningSessionLifecycleState[];
};

function createDeps(
  args: {
    policyResult?: ActivateSigningSessionSealPolicyResult;
    writeResult?: ActivateSigningSessionSealWriteResult;
  } = {},
): { deps: ActivateSigningSessionDeps; captures: Captures } {
  const captures: Captures = {
    policyInputs: [],
    writes: [],
    transitions: [],
  };
  return {
    captures,
    deps: {
      clock: {
        nowMs: () => 1_800_000_000_000,
      },
      sealPolicy: {
        resolve(input) {
          captures.policyInputs.push(input);
          return (
            args.policyResult || {
              ok: true,
              expiresAtMs,
              remainingUses,
            }
          );
        },
      },
      sealWriter: {
        write(input) {
          captures.writes.push(input);
          return args.writeResult || { ok: true };
        },
      },
      lifecycle: {
        transition(state) {
          captures.transitions.push(state);
        },
      },
    },
  };
}

async function activate(
  input: ActivateSigningSessionInput,
  args: Parameters<typeof createDeps>[0] = {},
) {
  const { deps, captures } = createDeps(args);
  const result = await createActivateSigningSessionUseCase(deps).activate(input);
  return { result, captures };
}

test.describe('ActivateSigningSessionUseCase', () => {
  test('writes branch-specific passkey seals for Ed25519 and ECDSA materials', async () => {
    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: passkeyAuth,
      material: [ed25519Material, ecdsaMaterial(readyRecord({ authMethod: passkeyAuthMethod }))],
    });

    expect(result.ok).toBe(true);
    expect(captures.writes.map((write) => write.kind)).toEqual([
      'passkey_ed25519_seal_write_v1',
      'passkey_ecdsa_seal_write_v1',
    ]);
    expect(captures.writes[0]?.material.kind).toBe('ed25519_session');
    expect(captures.writes[1]?.material.kind).toBe('ecdsa_session');
    expect(captures.transitions.map((state) => state.kind)).toEqual([
      'received_input',
      'validating_material',
      'writing_seals',
      'activated',
    ]);
  });

  test('writes Email OTP Ed25519 seals only from Ed25519 worker handles', async () => {
    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: emailOtpEd25519Auth,
      material: [ed25519Material],
    });

    expect(result.ok).toBe(true);
    expect(captures.writes).toHaveLength(1);
    expect(captures.writes[0]?.kind).toBe('email_otp_ed25519_seal_write_v1');
    const write = captures.writes[0];
    if (write?.kind !== 'email_otp_ed25519_seal_write_v1') {
      throw new Error('expected Email OTP Ed25519 seal write');
    }
    expect(write.auth.workerHandle.action).toBe('threshold_ed25519_session');
    expect('chainTarget' in write.auth.workerHandle).toBe(false);
  });

  test('writes Email OTP ECDSA seals only from matching ECDSA worker handles and ready records', async () => {
    const emailOtpEcdsaAuth = emailOtpEcdsaAuthFor(chainTarget);
    const material = ecdsaMaterial(readyRecord({ authMethod: emailOtpAuthMethod }));

    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: emailOtpEcdsaAuth,
      material: [material],
    });

    expect(result.ok).toBe(true);
    expect(captures.writes).toHaveLength(1);
    expect(captures.writes[0]?.kind).toBe('email_otp_ecdsa_seal_write_v1');
    const write = captures.writes[0];
    if (write?.kind !== 'email_otp_ecdsa_seal_write_v1') {
      throw new Error('expected Email OTP ECDSA seal write');
    }
    expect(write.auth.workerHandle.chainTarget).toEqual(chainTarget);
    expect(write.material.record.kind).toBe('ecdsa_role_local_ready_email_otp_v1');
  });

  test('rejects Email OTP Ed25519 activation carrying an ECDSA worker handle', async () => {
    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: emailOtpEcdsaAuthFor(chainTarget),
      material: [ed25519Material],
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'auth_branch_mismatch',
      retryable: false,
    });
    expect(captures.writes).toEqual([]);
  });

  test('rejects Email OTP ECDSA activation carrying an Ed25519 worker handle', async () => {
    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: emailOtpEd25519Auth,
      material: [ecdsaMaterial(readyRecord({ authMethod: emailOtpAuthMethod }))],
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'auth_branch_mismatch',
      retryable: false,
    });
    expect(captures.writes).toEqual([]);
  });

  test('rejects Email OTP ECDSA handles whose chain target differs from the ready record', async () => {
    const { result, captures } = await activate({
      walletId,
      walletKeyId,
      rpId,
      auth: emailOtpEcdsaAuthFor(otherChainTarget),
      material: [ecdsaMaterial(readyRecord({ authMethod: emailOtpAuthMethod }))],
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'auth_branch_mismatch',
      retryable: false,
    });
    expect(captures.writes).toEqual([]);
  });

  test('rejects expired or exhausted seal policy before persistence writes', async () => {
    const { result, captures } = await activate(
      {
        walletId,
      walletKeyId,
        rpId,
        auth: passkeyAuth,
        material: [ed25519Material],
      },
      {
        policyResult: {
          ok: true,
          expiresAtMs: 1_700_000_000_000 as UnixTimeMs,
          remainingUses,
        },
      },
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'session_expired',
    });
    expect(captures.writes).toEqual([]);
  });

  test('returns seal writer failures without activating the lifecycle', async () => {
    const { result, captures } = await activate(
      {
        walletId,
      walletKeyId,
        rpId,
        auth: passkeyAuth,
        material: [ed25519Material],
      },
      {
        writeResult: useCaseFailure({
          code: 'storage_failed' as const,
          source: 'storage',
          message: 'IndexedDB unavailable',
          retryable: true,
        }),
      },
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'storage_failed',
      retryable: true,
    });
    expect(captures.transitions.map((state) => state.kind)).toEqual([
      'received_input',
      'validating_material',
      'writing_seals',
      'failed',
    ]);
  });
});
