import type {
  PrepareEcdsaClientBootstrapOutput,
  ThresholdEcdsaChainTarget,
} from '../../client/src/core/platform/generated/signerCoreCommands';
import {
  prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
  prepare_ecdsa_client_bootstrap_v1,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';

const DEFAULT_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

export type TestEcdsaClientBootstrapContext = {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  chainTarget?: ThresholdEcdsaChainTarget;
};

export type TestPreparedEcdsaClientBootstrap = {
  pendingStateBlobB64u: string;
  contextBinding32B64u: string;
  hssClientSharePublicKey33B64u: string;
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
          algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
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
  context: TestEcdsaClientBootstrapContext;
  passkeyPrfFirstB64u: string;
  credentialIdB64u?: string;
}): TestPreparedEcdsaClientBootstrap {
  return flattenPreparedBootstrap(
    JSON.parse(
      prepare_ecdsa_client_bootstrap_v1(
        JSON.stringify({
          kind: 'prepare_ecdsa_client_bootstrap_v1',
          algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
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
  return {
    walletId: context.walletId,
    rpId: context.rpId,
    chainTarget: context.chainTarget || DEFAULT_CHAIN_TARGET,
    ecdsaThresholdKeyId: context.ecdsaThresholdKeyId,
    signingRootId: context.signingRootId,
    signingRootVersion: context.signingRootVersion,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
  };
}

function flattenPreparedBootstrap(
  output: PrepareEcdsaClientBootstrapOutput,
): TestPreparedEcdsaClientBootstrap {
  return {
    pendingStateBlobB64u: output.pendingStateBlob.stateBlobB64u,
    contextBinding32B64u: output.clientBootstrap.contextBinding32B64u,
    hssClientSharePublicKey33B64u: output.clientBootstrap.hssClientSharePublicKey33B64u,
    clientVerifyingShareB64u: output.publicFacts.clientVerifyingShareB64u,
    clientShareRetryCounter: output.clientBootstrap.clientShareRetryCounter,
    participantId: output.clientBootstrap.participantId,
    raw: output,
  };
}
