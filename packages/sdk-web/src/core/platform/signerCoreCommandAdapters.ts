import { base64UrlDecode } from '@shared/utils/base64';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
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

function parseHssClientSharePublicKey33B64u(value: string): EcdsaHssClientSharePublicKey33B64u {
  return requireBase64UrlBytes(
    value,
    'hssClientSharePublicKey33B64u',
    33,
  ) as EcdsaHssClientSharePublicKey33B64u;
}

function parseRelayerHssPublicKey33B64u(value: string): EcdsaRelayerHssPublicKey33B64u {
  return requireBase64UrlBytes(
    value,
    'relayerPublicKey33B64u',
    33,
  ) as EcdsaRelayerHssPublicKey33B64u;
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
  const base = {
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
  };

  switch (input.secretSource.kind) {
    case 'webauthn_prf_first':
      return {
        ...base,
        secretSource: {
          kind: 'webauthn_prf_first',
          prfFirstB64u: input.secretSource.prfFirstB64u,
          rpId: input.secretSource.rpId,
          credentialIdB64u: input.secretSource.credentialIdB64u,
        },
      };
    case 'email_otp_worker_session':
    case 'secure_enclave_wrapped_secret':
    case 'fido2_hmac_secret':
      throw new Error(
        `[signer-core-command] unsupported ECDSA bootstrap secret source: ${input.secretSource.kind}`,
      );
    default:
      return assertNeverSignerCoreCommand(input.secretSource);
  }
}

export function parseGeneratedPrepareEcdsaClientBootstrapOutput(
  input: GeneratedPrepareEcdsaClientBootstrapOutput,
): PrepareEcdsaClientBootstrapOutput {
  if (input.clientBootstrap.participantId !== 1) {
    throw new Error('[signer-core-command] ECDSA client bootstrap participantId must be 1');
  }
  const hssClientSharePublicKey33B64u = parseHssClientSharePublicKey33B64u(
    input.clientBootstrap.hssClientSharePublicKey33B64u,
  );
  return {
    pendingStateBlob: parsePendingStateBlob(input.pendingStateBlob),
    clientBootstrap: {
      contextBinding32B64u: requireBase64UrlBytes(
        input.clientBootstrap.contextBinding32B64u,
        'contextBinding32B64u',
        32,
      ),
      hssClientSharePublicKey33B64u,
      clientShareRetryCounter: input.clientBootstrap.clientShareRetryCounter,
      participantId: 1,
    },
    publicFacts: {
      hssClientSharePublicKey33B64u: parseHssClientSharePublicKey33B64u(
        input.publicFacts.hssClientSharePublicKey33B64u,
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
      hssClientSharePublicKey33B64u: parseHssClientSharePublicKey33B64u(
        input.publicFacts.hssClientSharePublicKey33B64u,
      ),
      clientVerifyingShareB64u: parsePublicKey33B64u(
        input.publicFacts.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      relayerPublicKey33B64u: parseRelayerHssPublicKey33B64u(
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
    hssClientSharePublicKey33B64u: parseHssClientSharePublicKey33B64u(
      publicFacts.hssClientSharePublicKey33B64u,
    ),
    relayerPublicKey33B64u: parseRelayerHssPublicKey33B64u(
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

function assertNeverSignerCoreCommand(value: never): never {
  throw new Error(`[signer-core-command] unhandled branch: ${String(value)}`);
}
