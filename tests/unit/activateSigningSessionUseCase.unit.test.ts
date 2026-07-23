import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEmailOtpAuthSubjectId,
} from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
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
  type SigningSessionActivationEmailOtpEcdsaAuth,
  type SigningSessionSealWriteInput,
  type UnixTimeMs,
  type WarmSessionRemainingUses,
} from '@/core/signingEngine/useCases/lifecycle';
import {
  seedActivationEcdsaRoleLocalReadyRecord,
  seedEcdsaSigningSessionActivationMaterial,
  seedEd25519SigningSessionActivationMaterial,
  seedSigningSessionActivationEmailOtpEcdsaAuth,
  seedSigningSessionActivationEmailOtpEd25519Auth,
  seedSigningSessionActivationPasskeyAuth,
} from './helpers/signingSessionActivation.fixtures';

const walletId = toWalletId('wallet_alice');
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
const signingRootId = toEcdsaDerivationSigningRootId('root');
const signingRootVersion = toEcdsaDerivationSigningRootVersion('v1');
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId,
  signingRootVersion,
});
const passkeyCredentialIdB64u = 'credential-passkey';
const expiresAtMs = 1_900_000_000_000 as UnixTimeMs;
const remainingUses = 8 as WarmSessionRemainingUses;

const passkeyAuth = seedSigningSessionActivationPasskeyAuth({
  walletId,
  rpId,
  credentialIdB64u: passkeyCredentialIdB64u,
});

const emailOtpEd25519Auth = seedSigningSessionActivationEmailOtpEd25519Auth({
  walletId,
  rpId,
  authSubjectId,
});

function emailOtpEcdsaAuthFor(
  target: ThresholdEcdsaChainTarget,
): SigningSessionActivationEmailOtpEcdsaAuth {
  return seedSigningSessionActivationEmailOtpEcdsaAuth({
    walletId,
    evmFamilySigningKeySlotId,
    authSubjectId,
    chainTarget: target,
  });
}

function readyRecord(args: { authMethod: 'passkey' | 'email_otp' }): EcdsaRoleLocalReadyRecord {
  return seedActivationEcdsaRoleLocalReadyRecord({
    walletId,
    signingRootId,
    signingRootVersion,
    authMethod: args.authMethod,
    credentialIdB64u: passkeyCredentialIdB64u,
    rpId,
    authSubjectId,
  });
}

const ed25519Material = seedEd25519SigningSessionActivationMaterial();

function ecdsaMaterial(record: EcdsaRoleLocalReadyRecord) {
  return seedEcdsaSigningSessionActivationMaterial({ record });
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
      evmFamilySigningKeySlotId,
      rpId,
      auth: passkeyAuth,
      material: [ed25519Material, ecdsaMaterial(readyRecord({ authMethod: 'passkey' }))],
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
      evmFamilySigningKeySlotId,
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
    const material = ecdsaMaterial(readyRecord({ authMethod: 'email_otp' }));

    const { result, captures } = await activate({
      walletId,
      evmFamilySigningKeySlotId,
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
      evmFamilySigningKeySlotId,
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
      evmFamilySigningKeySlotId,
      rpId,
      auth: emailOtpEd25519Auth,
      material: [ecdsaMaterial(readyRecord({ authMethod: 'email_otp' }))],
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
      evmFamilySigningKeySlotId,
      rpId,
      auth: emailOtpEcdsaAuthFor(otherChainTarget),
      material: [ecdsaMaterial(readyRecord({ authMethod: 'email_otp' }))],
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
        evmFamilySigningKeySlotId,
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
        evmFamilySigningKeySlotId,
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
