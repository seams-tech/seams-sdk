import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('wallet auth proof WebAuthn boundary guard', () => {
  test('generic transaction signing APIs resolve wallet auth instead of requiring WebAuthn directly', () => {
    for (const relativePath of [
      'client/src/core/signingEngine/api/nearSigning.ts',
      'client/src/core/signingEngine/api/evmSigning.ts',
    ]) {
      const content = readRepoFile(relativePath);

      expect(content, relativePath).toContain('createWalletAuthModeResolver');
      expect(content, relativePath).toContain('WalletAuthPlan');
      expect(content, relativePath).not.toContain('webauthn_authentication');
      expect(content, relativePath).not.toContain('webauthnAuthentication is required');
    }
  });

  test('touch-confirm orchestration resolves signing auth plans, not mode-only helpers', () => {
    const helperContent = readRepoFile(
      'client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts',
    );
    const evmContent = readRepoFile(
      'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
    );
    const tempoContent = readRepoFile(
      'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
    );

    expect(helperContent).toContain('resolveTouchConfirmSigningAuth');
    expect(helperContent).toContain('signingAuthPlanFromWalletAuthPlan');
    expect(helperContent).not.toContain('resolveSigningAuthMode');
    expect(evmContent).toContain('resolveTouchConfirmSigningAuth');
    expect(evmContent).toContain('touchConfirmAuthPayload');
    expect(evmContent).not.toContain('resolveSigningAuthMode');
    expect(tempoContent).toContain('resolveTouchConfirmSigningAuth');
    expect(tempoContent).toContain('touchConfirmAuthPayload');
    expect(tempoContent).not.toContain('resolveSigningAuthMode');
  });

  test('export authorization goes through the resolver before WebAuthn UI', () => {
    const content = readRepoFile('client/src/core/signingEngine/SigningEngine.ts');
    const helperStart = content.indexOf('private async requestPasskeyExportAuthorization');
    const nearStart = content.indexOf('private async requestNearEd25519ExportAuthorization');
    const ecdsaStart = content.indexOf('private async requestThresholdEcdsaExportAuthorization');

    expect(helperStart).toBeGreaterThan(0);
    expect(nearStart).toBeGreaterThan(0);
    expect(ecdsaStart).toBeGreaterThan(0);
    expect(content.slice(helperStart, helperStart + 2400)).toContain(
      'createWalletAuthModeResolver',
    );
    expect(content.slice(nearStart, nearStart + 700)).toContain(
      'this.requestPasskeyExportAuthorization',
    );
    expect(content.slice(ecdsaStart, ecdsaStart + 800)).toContain(
      'this.requestPasskeyExportAuthorization',
    );
  });

  test('Ed25519 session mint normalizes auth proof before passkey verification', () => {
    const content = readRepoFile(
      'server/src/core/ThresholdService/ThresholdSigningService.ts',
    );
    const resolverStart = content.indexOf('function resolveThresholdEd25519SessionWalletAuthProof');
    const sessionStart = content.indexOf('private async ed25519Session');
    const verificationStart = content.indexOf('this.verifyWebAuthnAuthenticationLite!', sessionStart);

    expect(resolverStart).toBeGreaterThan(0);
    expect(sessionStart).toBeGreaterThan(0);
    expect(verificationStart).toBeGreaterThan(sessionStart);
    expect(content.slice(sessionStart, verificationStart)).toContain(
      'resolveThresholdEd25519SessionWalletAuthProof',
    );
    expect(content.slice(verificationStart, verificationStart + 500)).toContain(
      'walletAuthProof.value.webauthnAuthentication',
    );
  });

  test('passkey-only session exchange routes are the only server routes that directly require WebAuthn', () => {
    for (const relativePath of [
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
    ]) {
      const content = readRepoFile(relativePath);
      const directRequirementCount = (
        content.match(/webauthn_authentication is required/g) || []
      ).length;

      expect(content, relativePath).toContain("passkey_assertion");
      expect(directRequirementCount, relativePath).toBe(2);
      expect(content, relativePath).toContain(
        'exchange.webauthn_authentication is required for passkey_assertion',
      );
    }
  });
});
