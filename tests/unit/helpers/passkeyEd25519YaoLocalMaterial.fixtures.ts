import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

function bytes32(byte: number): string {
  return Buffer.from(new Uint8Array(32).fill(byte)).toString('base64url');
}

export function buildPasskeyEd25519YaoLocalMaterialBindingFixture(args?: {
  readonly materialActivation?: MpcMaterialActivationRef;
}): Record<string, unknown> {
  const walletId = 'wallet-passkey-yao-local-material';
  const signingWorkerId = 'signing-worker-passkey-yao-local-material';
  return {
    kind: 'router_ab_ed25519_yao_active_client_v1',
    walletId,
    nearAccountId: 'wallet-passkey-yao-local-material.testnet',
    nearEd25519SigningKeyId: 'near-signing-key-passkey-yao-local-material',
    signerSlot: 1,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-passkey-yao-local-material',
    lifecycleId: 'lifecycle-passkey-yao-local-material',
    thresholdSessionId: 'threshold-session-passkey-yao-local-material',
    materialActivation:
      args?.materialActivation ??
      buildMpcMaterialActivationRefFixture(
        'passkey-yao-local-material',
        walletId,
        signingWorkerId,
      ),
    signingRootId: 'project-passkey-yao:test',
    signingRootVersion: 'root-passkey-yao-v1',
    signerSetId: 'signer-set-passkey-yao-local-material',
    signingWorkerId,
    participantIds: [1, 2],
    registeredPublicKeyB64u: bytes32(7),
    signingWorkerVerifyingShareB64u: bytes32(8),
    stateEpoch: '1',
    activationTranscriptB64u: bytes32(9),
    activationCapabilityBindingB64u: bytes32(10),
  };
}
