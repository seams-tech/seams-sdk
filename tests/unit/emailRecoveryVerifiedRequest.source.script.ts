import {
  buildEncryptedEmailRecoveryActions,
  buildVerifiedEmailRecoveryRequest,
} from '../../packages/sdk-server-ts/src/email-recovery/rpcCalls.ts';

const recoveryPayload = {
  version: 'recovery_email_payload_v1' as const,
  nearAccountId: 'alice.testnet',
  recoverySessionId: 'ABC123',
  newNearPublicKey: 'ed25519:recovery-key',
  newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
  deadlineEpochSeconds: 1_893_456_000,
  scope: 'all-linked-evm-accounts',
};

const verifiedRecoveryRequest = buildVerifiedEmailRecoveryRequest({
  accountId: 'alice.testnet',
  recoveryPayload,
});

const { actions } = await buildEncryptedEmailRecoveryActions(
  {
    relayerAccount: 'w3a-relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    networkId: 'testnet',
    emailDkimVerifierContract: 'email-dkim-verifier.testnet',
    nearClient: {} as never,
    ensureSignerAndRelayerAccount: async () => {},
    queueTransaction: async <T>(fn: () => Promise<T>) => fn(),
    fetchTxContext: async () => ({ nextNonce: '1', blockHash: 'block-hash' }),
    signWithPrivateKey: async () => ({}) as never,
    getRelayerPublicKey: () => 'relayer-public-key',
  },
  {
    accountId: 'alice.testnet',
    emailBlob: [
      'From: Alice <alice@example.com>',
      'Subject: recover-v1 alice.testnet ABC123',
      '',
      'body',
    ].join('\n'),
    recoveryPayload,
    recipientPk: new Uint8Array(32).fill(7),
    encrypt: async () => ({
      envelope: {
        version: 1,
        ephemeral_pub: 'ephemeral',
        nonce: 'nonce',
        ciphertext: 'ciphertext',
      },
    }),
  },
);

const functionCallAction = actions[0] as Extract<
  (typeof actions)[number],
  { action_type: 'FunctionCall' }
>;
const parsedArgs = JSON.parse(String(functionCallAction.args || '{}'));

console.log(
  'RESULT:' +
    JSON.stringify({
      verifiedRecoveryRequest,
      verifiedRecoveryRequestKeys: Object.keys(verifiedRecoveryRequest).sort(),
      parsedArgs: {
        expected_new_public_key: parsedArgs.expected_new_public_key,
        request_id: parsedArgs.request_id,
      },
    }),
);
