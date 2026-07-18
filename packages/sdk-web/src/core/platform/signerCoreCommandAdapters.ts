import { base64UrlDecode } from '@shared/utils/base64';
import type {
  DerivationClientSharePublicKey33B64u,
  EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand as RawBuildEcdsaRoleLocalExportArtifactCommand,
  BuildEcdsaRoleLocalExportArtifactOutput as RawBuildEcdsaRoleLocalExportArtifactOutput,
  FinalizeEcdsaClientBootstrapCommand as RawFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapOutput as RawFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as RawPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapOutput as RawPrepareEcdsaClientBootstrapOutput,
} from './generated/signerCoreCommands';
import type {
  BuildEcdsaRoleLocalExportArtifactInput,
  BuildEcdsaRoleLocalExportArtifactOutput,
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalPendingStateBlob,
  EcdsaRoleLocalReadyStateBlob,
  FinalizeEcdsaClientBootstrapInput,
  FinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapInput,
  PrepareEcdsaClientBootstrapOutput,
} from './types';

export type GeneratedPrepareEcdsaClientBootstrapCommand = RawPrepareEcdsaClientBootstrapCommand;
export type GeneratedPrepareEcdsaClientBootstrapOutput = RawPrepareEcdsaClientBootstrapOutput;
export type GeneratedFinalizeEcdsaClientBootstrapCommand = RawFinalizeEcdsaClientBootstrapCommand;
export type GeneratedFinalizeEcdsaClientBootstrapOutput = RawFinalizeEcdsaClientBootstrapOutput;
export type GeneratedBuildEcdsaRoleLocalExportArtifactCommand =
  RawBuildEcdsaRoleLocalExportArtifactCommand;
export type GeneratedBuildEcdsaRoleLocalExportArtifactOutput =
  RawBuildEcdsaRoleLocalExportArtifactOutput;

function requireBase64UrlBytes(value: string, field: string, byteLength: number): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[signer-core-command] ${field} is required`);
  }
  if (base64UrlDecode(normalized).length !== byteLength) {
    throw new Error(`[signer-core-command] ${field} must decode to ${byteLength} bytes`);
  }
  return normalized;
}

function parseDerivationClientSharePublicKey33B64u(value: string): DerivationClientSharePublicKey33B64u {
  return requireBase64UrlBytes(
    value,
    'derivationClientSharePublicKey33B64u',
    33,
  ) as DerivationClientSharePublicKey33B64u;
}

function parseRelayerEcdsaDerivationPublicKey33B64u(value: string): EcdsaDerivationRelayerPublicKey33B64u {
  return requireBase64UrlBytes(
    value,
    'relayerPublicKey33B64u',
    33,
  ) as EcdsaDerivationRelayerPublicKey33B64u;
}

function parsePublicKey33B64u(value: string, field: string): string {
  return requireBase64UrlBytes(value, field, 33);
}

function parseEthereumAddress(value: string): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) {
    throw new Error('[signer-core-command] ethereumAddress must be 0x-prefixed 20-byte hex');
  }
  return normalized as `0x${string}`;
}

function parseHexBytes(value: string, field: string, byteLength: number): `0x${string}` {
  const normalized = String(value || '').trim();
  const hexChars = byteLength * 2;
  if (!new RegExp(`^0x[0-9a-fA-F]{${hexChars}}$`).test(normalized)) {
    throw new Error(`[signer-core-command] ${field} must be 0x-prefixed ${byteLength}-byte hex`);
  }
  return normalized as `0x${string}`;
}

function parsePendingStateBlob(
  input: RawPrepareEcdsaClientBootstrapOutput['pendingStateBlob'],
): EcdsaRoleLocalPendingStateBlob {
  if (
    input.kind !== 'ecdsa_role_local_pending_state_blob_v1' ||
    input.curve !== 'secp256k1' ||
    input.encoding !== 'base64url' ||
    input.producer !== 'signer_core'
  ) {
    throw new Error('[signer-core-command] invalid ECDSA pending state blob envelope');
  }
  return input;
}

function parseReadyStateBlob(
  input:
    | RawFinalizeEcdsaClientBootstrapOutput['stateBlob']
    | RawBuildEcdsaRoleLocalExportArtifactCommand['stateBlob'],
): EcdsaRoleLocalReadyStateBlob {
  if (
    input.kind !== 'ecdsa_role_local_state_blob_v1' ||
    input.curve !== 'secp256k1' ||
    input.encoding !== 'base64url' ||
    input.producer !== 'signer_core'
  ) {
    throw new Error('[signer-core-command] invalid ECDSA ready state blob envelope');
  }
  return input;
}

export function toGeneratedPrepareEcdsaClientBootstrapCommand(
  input: PrepareEcdsaClientBootstrapInput,
): GeneratedPrepareEcdsaClientBootstrapCommand {
  return {
    kind: input.kind,
    algorithm: input.algorithm,
    context: {
      applicationBindingDigestB64u: input.context.applicationBindingDigestB64u,
    },
    participants: {
      clientParticipantId: input.participants.clientParticipantId,
      relayerParticipantId: input.participants.relayerParticipantId,
      participantIds: [...input.participants.participantIds],
    },
    secretSource: {
      kind: 'threshold_prf_x_client_base',
      xClientBaseB64u: requireBase64UrlBytes(
        input.secretSource.xClientBaseB64u,
        'secretSource.xClientBaseB64u',
        32,
      ),
    },
  };
}

export function parseGeneratedPrepareEcdsaClientBootstrapOutput(
  input: GeneratedPrepareEcdsaClientBootstrapOutput,
): PrepareEcdsaClientBootstrapOutput {
  if (input.clientBootstrap.participantId !== 1) {
    throw new Error('[signer-core-command] ECDSA client bootstrap participantId must be 1');
  }
  const derivationClientSharePublicKey33B64u = parseDerivationClientSharePublicKey33B64u(
    input.clientBootstrap.derivationClientSharePublicKey33B64u,
  );
  return {
    pendingStateBlob: parsePendingStateBlob(input.pendingStateBlob),
    clientBootstrap: {
      contextBinding32B64u: requireBase64UrlBytes(
        input.clientBootstrap.contextBinding32B64u,
        'contextBinding32B64u',
        32,
      ),
      derivationClientSharePublicKey33B64u,
      clientShareRetryCounter: input.clientBootstrap.clientShareRetryCounter,
      participantId: 1,
    },
    publicFacts: {
      derivationClientSharePublicKey33B64u: parseDerivationClientSharePublicKey33B64u(
        input.publicFacts.derivationClientSharePublicKey33B64u,
      ),
      clientVerifyingShareB64u: parsePublicKey33B64u(
        input.publicFacts.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
    },
  };
}

export function toGeneratedFinalizeEcdsaClientBootstrapCommand(
  input: FinalizeEcdsaClientBootstrapInput,
): GeneratedFinalizeEcdsaClientBootstrapCommand {
  return {
    kind: input.kind,
    pendingStateBlob: input.pendingStateBlob,
    relayerPublicIdentity: {
      relayerKeyId: input.relayerPublicIdentity.relayerKeyId,
      relayerPublicKey33B64u: input.relayerPublicIdentity.relayerPublicKey33B64u,
      groupPublicKey33B64u: input.relayerPublicIdentity.groupPublicKey33B64u,
      ethereumAddress: input.relayerPublicIdentity.ethereumAddress,
      relayerShareRetryCounter: input.relayerPublicIdentity.relayerShareRetryCounter,
    },
  };
}

export function parseGeneratedFinalizeEcdsaClientBootstrapOutput(
  input: GeneratedFinalizeEcdsaClientBootstrapOutput,
): FinalizeEcdsaClientBootstrapOutput {
  return {
    stateBlob: parseReadyStateBlob(input.stateBlob),
    publicFacts: {
      contextBinding32B64u: requireBase64UrlBytes(
        input.publicFacts.contextBinding32B64u,
        'contextBinding32B64u',
        32,
      ),
      derivationClientSharePublicKey33B64u: parseDerivationClientSharePublicKey33B64u(
        input.publicFacts.derivationClientSharePublicKey33B64u,
      ),
      clientVerifyingShareB64u: parsePublicKey33B64u(
        input.publicFacts.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      relayerPublicKey33B64u: parseRelayerEcdsaDerivationPublicKey33B64u(
        input.publicFacts.relayerPublicKey33B64u,
      ),
      groupPublicKey33B64u: parsePublicKey33B64u(
        input.publicFacts.groupPublicKey33B64u,
        'groupPublicKey33B64u',
      ),
      ethereumAddress: parseEthereumAddress(input.publicFacts.ethereumAddress),
    },
  };
}

function generatedExportPublicFacts(
  publicFacts: EcdsaRoleLocalPublicFacts,
): RawBuildEcdsaRoleLocalExportArtifactCommand['publicFacts'] {
  return {
    applicationBindingDigestB64u: requireBase64UrlBytes(
      publicFacts.applicationBindingDigestB64u,
      'publicFacts.applicationBindingDigestB64u',
      32,
    ),
    clientParticipantId: publicFacts.clientParticipantId,
    relayerParticipantId: publicFacts.relayerParticipantId,
    participantIds: [...publicFacts.participantIds],
    contextBinding32B64u: requireBase64UrlBytes(
      publicFacts.contextBinding32B64u,
      'publicFacts.contextBinding32B64u',
      32,
    ),
    derivationClientSharePublicKey33B64u: parseDerivationClientSharePublicKey33B64u(
      publicFacts.derivationClientSharePublicKey33B64u,
    ),
    relayerPublicKey33B64u: parseRelayerEcdsaDerivationPublicKey33B64u(
      publicFacts.relayerPublicKey33B64u,
    ),
    groupPublicKey33B64u: parsePublicKey33B64u(
      publicFacts.groupPublicKey33B64u,
      'publicFacts.groupPublicKey33B64u',
    ),
    ethereumAddress: parseEthereumAddress(publicFacts.ethereumAddress),
  };
}

export function toGeneratedBuildEcdsaRoleLocalExportArtifactCommand(
  input: BuildEcdsaRoleLocalExportArtifactInput,
): GeneratedBuildEcdsaRoleLocalExportArtifactCommand {
  return {
    kind: input.kind,
    algorithm: input.algorithm,
    stateBlob: parseReadyStateBlob(input.stateBlob),
    publicFacts: generatedExportPublicFacts(input.publicFacts),
    serverExportShare32B64u: requireBase64UrlBytes(
      input.serverExportShare32B64u,
      'serverExportShare32B64u',
      32,
    ),
  };
}

export function parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput(
  input: GeneratedBuildEcdsaRoleLocalExportArtifactOutput,
): BuildEcdsaRoleLocalExportArtifactOutput {
  return {
    publicKeyHex: parseHexBytes(input.publicKeyHex, 'publicKeyHex', 33),
    privateKeyHex: parseHexBytes(input.privateKeyHex, 'privateKeyHex', 32),
    ethereumAddress: parseEthereumAddress(input.ethereumAddress),
  };
}
