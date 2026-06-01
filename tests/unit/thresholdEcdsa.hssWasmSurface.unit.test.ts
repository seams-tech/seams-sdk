import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import * as EthSignerWasm from '../../wasm/eth_signer/pkg/eth_signer.js';
import * as HssClientSignerWasm from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';

const ETH_SIGNER_WASM_URL = new URL(
  '../../wasm/eth_signer/pkg/eth_signer_bg.wasm',
  import.meta.url,
);
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const FIXTURE_URL = new URL('../../crates/ecdsa-hss/fixtures/role_local_v2.json', import.meta.url);

let ethSignerWasmInitialized = false;
let hssClientSignerWasmInitialized = false;

function ensureEthSignerWasm(): void {
  if (ethSignerWasmInitialized) return;
  EthSignerWasm.initSync({ module: readFileSync(ETH_SIGNER_WASM_URL) });
  ethSignerWasmInitialized = true;
}

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  HssClientSignerWasm.initSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function bytesHex(bytes: Uint8Array | number[]): string {
  return Buffer.from(bytes).toString('hex');
}

function readRoleLocalFixture() {
  return JSON.parse(readFileSync(FIXTURE_URL, 'utf8')) as {
    context: {
      walletId: string;
      rpId: string;
      ecdsaThresholdKeyId: string;
      signingRootId: string;
      signingRootVersion: string;
      keyPurpose: string;
      keyVersion: string;
    };
    inputs: {
      relayer_key_id: string;
      y_client32_le_hex: string;
      y_relayer32_le_hex: string;
    };
    identity: {
      client_public_key33_hex: string;
      relayer_public_key33_hex: string;
      threshold_public_key33_hex: string;
      threshold_ethereum_address20_hex: string;
      client_share_retry_counter: number;
    };
  };
}

function contextPayload(fixture: ReturnType<typeof readRoleLocalFixture>) {
  return {
    walletId: fixture.context.walletId,
    rpId: fixture.context.rpId,
    ecdsaThresholdKeyId: fixture.context.ecdsaThresholdKeyId,
    signingRootId: fixture.context.signingRootId,
    signingRootVersion: fixture.context.signingRootVersion,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
  };
}

test.describe('threshold ECDSA HSS WASM surface', () => {
  test('server bundle exposes only role-local relayer HSS helper', () => {
    const ethExports = EthSignerWasm as Record<string, unknown>;
    expect(typeof ethExports.threshold_ecdsa_hss_role_local_relayer_bootstrap).toBe('function');

    for (const forbidden of [
      'ecdsa_hss_derive_canonical_secret',
      'ecdsa_hss_derive_additive_shares',
      'ecdsa_hss_bootstrap_non_export_sign',
      'ecdsa_hss_bootstrap_non_export_sign_full',
      'ecdsa_hss_sign_non_export',
      'ecdsa_hss_sign_non_export_profiled',
      'ecdsa_hss_explicit_export',
    ]) {
      expect(forbidden in ethExports, forbidden).toBe(false);
    }
  });

  test('client bundle does not expose relayer or joined-root HSS helpers', () => {
    const clientExports = HssClientSignerWasm as Record<string, unknown>;
    expect('threshold_ecdsa_hss_role_local_client_bootstrap' in clientExports).toBe(false);
    expect('threshold_ecdsa_hss_role_local_prepare_client_bootstrap' in clientExports).toBe(
      false,
    );
    expect(
      typeof clientExports.prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
    ).toBe(
      'function',
    );
    expect(typeof clientExports.open_ecdsa_role_local_signing_share_v1).toBe('function');
    expect(typeof clientExports.build_ecdsa_role_local_export_artifact_v1).toBe('function');

    for (const forbidden of [
      'threshold_ecdsa_hss_role_local_export_artifact',
      'threshold_ecdsa_hss_role_local_relayer_bootstrap',
      'ecdsa_hss_derive_canonical_secret',
      'ecdsa_hss_derive_additive_shares',
      'ecdsa_hss_explicit_export',
    ]) {
      expect(forbidden in clientExports, forbidden).toBe(false);
    }
  });

  test('relayer bootstrap FFI accepts fixture little-endian scalars and compressed SEC1 public keys', () => {
    ensureEthSignerWasm();
    ensureHssClientSignerWasm();
    const fixture = readRoleLocalFixture();
    const context = contextPayload(fixture);
    const clientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
      context,
      clientRootShare32B64u: bytesB64u(hexToBytes(fixture.inputs.y_client32_le_hex)),
    });

    const relayerBootstrap = EthSignerWasm.threshold_ecdsa_hss_role_local_relayer_bootstrap({
      ...context,
      relayerKeyId: fixture.inputs.relayer_key_id,
      yRelayer32Le: Array.from(hexToBytes(fixture.inputs.y_relayer32_le_hex)),
      clientPublicKey33: Array.from(
        Buffer.from(clientBootstrap.hssClientSharePublicKey33B64u, 'base64url'),
      ),
      clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    }) as {
      contextBinding32: number[];
      relayerPublicKey33: number[];
      groupPublicKey33: number[];
      ethereumAddress20: number[];
    };

    expect(bytesHex(Buffer.from(clientBootstrap.contextBinding32B64u, 'base64url'))).toBe(
      bytesHex(relayerBootstrap.contextBinding32),
    );
    expect(Buffer.from(clientBootstrap.contextBinding32B64u, 'base64url')).toHaveLength(32);
    expect(Buffer.from(clientBootstrap.hssClientSharePublicKey33B64u, 'base64url')).toHaveLength(
      33,
    );
    expect(relayerBootstrap.relayerPublicKey33).toHaveLength(33);
    expect(relayerBootstrap.groupPublicKey33).toHaveLength(33);
    expect(relayerBootstrap.ethereumAddress20).toHaveLength(20);
  });

  test('relayer bootstrap FFI rejects wrong scalar and public-key widths', () => {
    ensureEthSignerWasm();
    const fixture = readRoleLocalFixture();
    const context = contextPayload(fixture);
    const validClientPublicKey33 = Array.from(hexToBytes(fixture.identity.client_public_key33_hex));
    const validRelayerRoot = Array.from(hexToBytes(fixture.inputs.y_relayer32_le_hex));
    const basePayload = {
      ...context,
      relayerKeyId: fixture.inputs.relayer_key_id,
      yRelayer32Le: validRelayerRoot,
      clientPublicKey33: validClientPublicKey33,
      clientShareRetryCounter: fixture.identity.client_share_retry_counter,
    };

    expect(() =>
      EthSignerWasm.threshold_ecdsa_hss_role_local_relayer_bootstrap({
        ...basePayload,
        yRelayer32Le: validRelayerRoot.slice(0, 31),
      }),
    ).toThrow(/yRelayer32Le must be 32 bytes/);
    expect(() =>
      EthSignerWasm.threshold_ecdsa_hss_role_local_relayer_bootstrap({
        ...basePayload,
        clientPublicKey33: validClientPublicKey33.slice(0, 32),
      }),
    ).toThrow(/clientPublicKey33 must be 33 bytes/);
  });
});
