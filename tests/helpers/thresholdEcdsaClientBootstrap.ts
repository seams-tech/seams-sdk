import type { PrepareEcdsaClientBootstrapOutput } from '../../packages/sdk-web/src/core/platform/generated/signerCoreCommands';
import { createHash } from 'node:crypto';
import {
  prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
  prepare_ecdsa_client_bootstrap_v1,
} from '../../wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.js';

export type TestEcdsaClientBootstrapContext = {
  walletId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
};

export type TestPasskeyEcdsaClientBootstrapContext = TestEcdsaClientBootstrapContext & {
  rpId: string;
};

export type TestPreparedEcdsaClientBootstrap = {
  pendingStateBlobB64u: string;
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: string;
  clientVerifyingShareB64u: string;
  clientShareRetryCounter: number;
  participantId: number;
  raw: PrepareEcdsaClientBootstrapOutput;
};

export function prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest(args: {
  context: TestEcdsaClientBootstrapContext;
  clientRootShare32B64u: string;
}): TestPreparedEcdsaClientBootstrap {
  return flattenPreparedBootstrap(
    JSON.parse(
      prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
        JSON.stringify({
          kind: 'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
          algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
          context: contextPayload(args.context),
          participants: {
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
          },
          resolvedEmailOtpRootShare32B64u: args.clientRootShare32B64u,
        }),
      ),
    ) as PrepareEcdsaClientBootstrapOutput,
  );
}

export function preparePasskeyPrfEcdsaClientBootstrapForTest(args: {
  context: TestPasskeyEcdsaClientBootstrapContext;
  passkeyPrfFirstB64u: string;
  credentialIdB64u?: string;
}): TestPreparedEcdsaClientBootstrap {
  return flattenPreparedBootstrap(
    JSON.parse(
      prepare_ecdsa_client_bootstrap_v1(
        JSON.stringify({
          kind: 'prepare_ecdsa_client_bootstrap_v1',
          algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
          context: contextPayload(args.context),
          participants: {
            clientParticipantId: 1,
            relayerParticipantId: 2,
            participantIds: [1, 2],
          },
          secretSource: {
            kind: 'webauthn_prf_first',
            prfFirstB64u: args.passkeyPrfFirstB64u,
            rpId: args.context.rpId,
            credentialIdB64u: args.credentialIdB64u || Buffer.from([1]).toString('base64url'),
          },
        }),
      ),
    ) as PrepareEcdsaClientBootstrapOutput,
  );
}

function contextPayload(context: TestEcdsaClientBootstrapContext) {
  const applicationBindingDigestB64u = sdkEcdsaDerivationApplicationBindingDigestB64u({
    walletId: context.walletId,
    ecdsaThresholdKeyId: context.ecdsaThresholdKeyId,
    signingRootId: context.signingRootId,
    signingRootVersion: context.signingRootVersion,
  });
  return {
    applicationBindingDigestB64u,
  };
}

function pushU32(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushLengthDelimitedField(out: number[], label: string, value: string): void {
  const labelBytes = Buffer.from(label, 'utf8');
  const valueBytes = Buffer.from(String(value || '').trim(), 'utf8');
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

export function sdkEcdsaDerivationApplicationBindingDigestB64u(input: {
  walletId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
}): string {
  const out: number[] = [];
  const domain = Buffer.from('seams-sdk:ecdsa-derivation:application-binding:v1', 'utf8');
  pushU32(out, domain.length);
  out.push(...domain);
  pushLengthDelimitedField(out, 'walletId', input.walletId);
  pushLengthDelimitedField(out, 'ecdsaThresholdKeyId', input.ecdsaThresholdKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return createHash('sha256').update(Buffer.from(out)).digest('base64url');
}

function flattenPreparedBootstrap(
  output: PrepareEcdsaClientBootstrapOutput,
): TestPreparedEcdsaClientBootstrap {
  return {
    pendingStateBlobB64u: output.pendingStateBlob.stateBlobB64u,
    contextBinding32B64u: output.clientBootstrap.contextBinding32B64u,
    derivationClientSharePublicKey33B64u:
      output.clientBootstrap.derivationClientSharePublicKey33B64u,
    clientVerifyingShareB64u: output.publicFacts.clientVerifyingShareB64u,
    clientShareRetryCounter: output.clientBootstrap.clientShareRetryCounter,
    participantId: output.clientBootstrap.participantId,
    raw: output,
  };
}
