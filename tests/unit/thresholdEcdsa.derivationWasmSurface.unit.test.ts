import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import * as RouterAbEcdsaSigningWorkerWasm from '../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js';
import * as EcdsaDerivationClientWasm from '../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';

const ROUTER_AB_ECDSA_SIGNING_WORKER_WASM_URL = new URL(
  '../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  import.meta.url,
);
const ECDSA_DERIVATION_CLIENT_WASM_URL = new URL(
  '../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client_bg.wasm',
  import.meta.url,
);
const FIXTURE_URL = new URL(
  '../../crates/router-ab-ecdsa-derivation/fixtures/role_local_v1.json',
  import.meta.url,
);

let routerAbEcdsaSigningWorkerWasmInitialized = false;
let ecdsaDerivationClientWasmInitialized = false;

function ensureRouterAbEcdsaSigningWorkerWasm(): void {
  if (routerAbEcdsaSigningWorkerWasmInitialized) return;
  RouterAbEcdsaSigningWorkerWasm.initSync({
    module: readFileSync(ROUTER_AB_ECDSA_SIGNING_WORKER_WASM_URL),
  });
  routerAbEcdsaSigningWorkerWasmInitialized = true;
}

function ensureEcdsaDerivationClientWasm(): void {
  if (ecdsaDerivationClientWasmInitialized) return;
  EcdsaDerivationClientWasm.initSync({ module: readFileSync(ECDSA_DERIVATION_CLIENT_WASM_URL) });
  ecdsaDerivationClientWasmInitialized = true;
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
      application_binding_digest_hex: string;
      binding32_hex: string;
    };
    inputs: {
      client_root32_le_hex: string;
      relayer_root32_le_hex: string;
    };
    identity: {
      derivation_client_share_public_key33_hex: string;
      relayer_public_key33_hex: string;
      threshold_public_key33_hex: string;
      threshold_ethereum_address20_hex: string;
      client_share_retry_counter: number;
    };
  };
}

function contextPayload(fixture: ReturnType<typeof readRoleLocalFixture>) {
  return {
    applicationBindingDigest: Array.from(
      hexToBytes(fixture.context.application_binding_digest_hex),
    ),
  };
}

function prepareFixtureClientBootstrap(fixture: ReturnType<typeof readRoleLocalFixture>): {
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: string;
  clientShareRetryCounter: number;
} {
  const output = JSON.parse(
    EcdsaDerivationClientWasm.prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
      JSON.stringify({
        kind: 'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
        algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
        context: {
          applicationBindingDigestB64u: bytesB64u(
            hexToBytes(fixture.context.application_binding_digest_hex),
          ),
        },
        participants: {
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
        },
        resolvedEmailOtpRootShare32B64u: bytesB64u(hexToBytes(fixture.inputs.client_root32_le_hex)),
      }),
    ),
  ) as {
    clientBootstrap: {
      contextBinding32B64u: string;
      derivationClientSharePublicKey33B64u: string;
      clientShareRetryCounter: number;
    };
  };
  return output.clientBootstrap;
}

test.describe('threshold ECDSA derivation WASM surface', () => {
  test('server signing worker exposes the role-local relayer derivation helper', () => {
    const serverExports = RouterAbEcdsaSigningWorkerWasm as Record<string, unknown>;
    expect(typeof serverExports.router_ab_ecdsa_derivation_relayer_bootstrap).toBe('function');

    for (const forbidden of [
      'ecdsa_derivation_derive_canonical_secret',
      'ecdsa_derivation_derive_additive_shares',
      'ecdsa_derivation_bootstrap_non_export_sign',
      'ecdsa_derivation_bootstrap_non_export_sign_full',
      'ecdsa_derivation_sign_non_export',
      'ecdsa_derivation_sign_non_export_profiled',
      'ecdsa_derivation_explicit_export',
    ]) {
      expect(forbidden in serverExports, forbidden).toBe(false);
    }
  });

  test('client bundle does not expose relayer or joined-root derivation helpers', () => {
    const clientExports = EcdsaDerivationClientWasm as Record<string, unknown>;
    expect('threshold_ecdsa_derivation_role_local_client_bootstrap' in clientExports).toBe(false);
    expect('threshold_ecdsa_derivation_role_local_prepare_client_bootstrap' in clientExports).toBe(
      false,
    );
    expect(
      typeof clientExports.prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
    ).toBe('function');
    expect(typeof clientExports.open_ecdsa_role_local_signing_share_v1).toBe('function');
    expect(typeof clientExports.build_ecdsa_role_local_export_artifact_v1).toBe('function');

    for (const forbidden of [
      'threshold_ecdsa_derivation_role_local_export_artifact',
      'threshold_ecdsa_derivation_role_local_relayer_bootstrap',
      'ecdsa_derivation_derive_canonical_secret',
      'ecdsa_derivation_derive_additive_shares',
      'ecdsa_derivation_explicit_export',
    ]) {
      expect(forbidden in clientExports, forbidden).toBe(false);
    }
  });

  test('relayer bootstrap FFI accepts fixture little-endian scalars and compressed SEC1 public keys', () => {
    ensureRouterAbEcdsaSigningWorkerWasm();
    ensureEcdsaDerivationClientWasm();
    const fixture = readRoleLocalFixture();
    const relayerContext = contextPayload(fixture);
    const clientBootstrap = prepareFixtureClientBootstrap(fixture);

    const relayerBootstrap =
      RouterAbEcdsaSigningWorkerWasm.router_ab_ecdsa_derivation_relayer_bootstrap({
        ...relayerContext,
        relayerKeyId: 'fixture-relayer',
        yRelayer32Le: Array.from(hexToBytes(fixture.inputs.relayer_root32_le_hex)),
        clientPublicKey33: Array.from(
          Buffer.from(clientBootstrap.derivationClientSharePublicKey33B64u, 'base64url'),
        ),
        clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
      }) as {
        contextBinding32: number[];
        relayerPublicKey33: number[];
        groupPublicKey33: number[];
        ethereumAddress20: number[];
      };

    expect(bytesHex(Buffer.from(clientBootstrap.contextBinding32B64u, 'base64url'))).toBe(
      fixture.context.binding32_hex,
    );
    expect(bytesHex(relayerBootstrap.contextBinding32)).toBe(fixture.context.binding32_hex);
    expect(
      bytesHex(Buffer.from(clientBootstrap.derivationClientSharePublicKey33B64u, 'base64url')),
    ).toBe(fixture.identity.derivation_client_share_public_key33_hex);
    expect(bytesHex(relayerBootstrap.relayerPublicKey33)).toBe(
      fixture.identity.relayer_public_key33_hex,
    );
    expect(bytesHex(relayerBootstrap.groupPublicKey33)).toBe(
      fixture.identity.threshold_public_key33_hex,
    );
    expect(bytesHex(relayerBootstrap.ethereumAddress20)).toBe(
      fixture.identity.threshold_ethereum_address20_hex,
    );
    expect(Buffer.from(clientBootstrap.contextBinding32B64u, 'base64url')).toHaveLength(32);
    expect(
      Buffer.from(clientBootstrap.derivationClientSharePublicKey33B64u, 'base64url'),
    ).toHaveLength(33);
    expect(relayerBootstrap.relayerPublicKey33).toHaveLength(33);
    expect(relayerBootstrap.groupPublicKey33).toHaveLength(33);
    expect(relayerBootstrap.ethereumAddress20).toHaveLength(20);
  });

  test('relayer bootstrap FFI rejects wrong scalar and public-key widths', () => {
    ensureRouterAbEcdsaSigningWorkerWasm();
    const fixture = readRoleLocalFixture();
    const relayerContext = contextPayload(fixture);
    ensureEcdsaDerivationClientWasm();
    const clientBootstrap = prepareFixtureClientBootstrap(fixture);
    const validClientPublicKey33 = Array.from(
      Buffer.from(clientBootstrap.derivationClientSharePublicKey33B64u, 'base64url'),
    );
    const validRelayerRoot = Array.from(hexToBytes(fixture.inputs.relayer_root32_le_hex));
    const basePayload = {
      ...relayerContext,
      relayerKeyId: 'fixture-relayer',
      yRelayer32Le: validRelayerRoot,
      clientPublicKey33: validClientPublicKey33,
      clientShareRetryCounter: fixture.identity.client_share_retry_counter,
    };

    expect(() =>
      RouterAbEcdsaSigningWorkerWasm.router_ab_ecdsa_derivation_relayer_bootstrap({
        ...basePayload,
        yRelayer32Le: validRelayerRoot.slice(0, 31),
      }),
    ).toThrow(/yRelayer32Le must be 32 bytes/);
    expect(() =>
      RouterAbEcdsaSigningWorkerWasm.router_ab_ecdsa_derivation_relayer_bootstrap({
        ...basePayload,
        clientPublicKey33: validClientPublicKey33.slice(0, 32),
      }),
    ).toThrow(/clientPublicKey33 must be 33 bytes/);
  });
});
