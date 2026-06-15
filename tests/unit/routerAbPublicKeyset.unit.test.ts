import { expect, test } from '@playwright/test';
import {
  parseRouterAbPublicKeysetV1,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V1,
} from '@shared/utils/routerAbPublicKeyset';
import { fetchRouterAbPublicKeysetV1 } from '@/core/rpcClients/relayer/routerAbPublicKeyset';

const keyset = {
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V1,
  route_profile: 'strict_proof_bundle',
  signer_envelope_hpke: {
    deriver_a: {
      role: 'signer_a',
      key_epoch: 'epoch-a',
      public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
    },
    deriver_b: {
      role: 'signer_b',
      key_epoch: 'epoch-b',
      public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
};

test.describe('Router A/B public keyset boundary', () => {
  test('parses the public Cloudflare Router keyset shape', () => {
    expect(parseRouterAbPublicKeysetV1(keyset)).toEqual(keyset);
  });

  test('rejects swapped signer roles', () => {
    expect(() =>
      parseRouterAbPublicKeysetV1({
        ...keyset,
        signer_envelope_hpke: {
          ...keyset.signer_envelope_hpke,
          deriver_a: {
            ...keyset.signer_envelope_hpke.deriver_a,
            role: 'signer_b',
          },
        },
      }),
    ).toThrow('signer_envelope_hpke.deriver_a.role must be signer_a');
  });

  test('rejects non-canonical public key encodings', () => {
    expect(() =>
      parseRouterAbPublicKeysetV1({
        ...keyset,
        signing_worker_server_output_hpke: {
          ...keyset.signing_worker_server_output_hpke,
          public_key: 'x25519:ABC',
        },
      }),
    ).toThrow('signing_worker_server_output_hpke.public_key must use x25519');
  });

  test('fetches and parses the versioned keyset endpoint', async () => {
    const originalFetch = globalThis.fetch;
    const requests: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      requests.push(String(input));
      return new Response(JSON.stringify(keyset), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    try {
      await expect(
        fetchRouterAbPublicKeysetV1({ relayerUrl: 'https://relay.example/' }),
      ).resolves.toEqual(keyset);
      expect(requests).toEqual(['https://relay.example/v1/router-ab/keyset']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
