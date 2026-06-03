import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { showThresholdEcdsaExportViewer } from '../../client/src/core/signingEngine/flows/recovery/keyExportConfirmation';
import type { ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
};

test.describe('threshold ECDSA export viewer payload', () => {
  test('includes EVM address in the loading viewer payload', async () => {
    let capturedRequestType = '';
    let capturedPayload: any = null;

    await showThresholdEcdsaExportViewer(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            capturedRequestType = String(request.type);
            capturedPayload = request.payload;
            return { requestId: request.requestId, confirmed: true };
          },
        },
        theme: 'light',
      },
      {
        state: 'loading',
        nearAccountId: toAccountId('alice.testnet'),
        chainTarget: EVM_TARGET,
        publicKeyHex: '0x02abcdef',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
        variant: 'drawer',
        theme: 'light',
        viewerSessionId: 'export-viewer-session-1',
        flowId: 'key-export-flow-1',
      },
    );

    if (!capturedPayload) throw new Error('expected export viewer request to be captured');

    expect(capturedRequestType).toBe('showSecurePrivateKeyUi');
    expect(capturedPayload.loading).toBe(true);
    expect(capturedPayload.keys).toEqual([
      {
        scheme: 'secp256k1',
        label: 'EVM private key',
        publicKey: '0x02abcdef',
        privateKey: '',
        address: '0x1111111111111111111111111111111111111111',
      },
    ]);
  });
});
