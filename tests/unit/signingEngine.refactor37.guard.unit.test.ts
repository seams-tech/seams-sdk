import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  deriveEvmFamilyKeyFingerprint,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listTsFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function listRepoFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    if (
      entry.name === 'node_modules' ||
      entry.name === 'target' ||
      entry.name === 'dist' ||
      entry.name === 'coverage' ||
      entry.name === 'playwright-report' ||
      entry.name === 'test-results'
    ) {
      return [];
    }
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listRepoFiles(relativePath);
    return /\.(ts|tsx|js|jsx|mjs|cjs|json|md|sol|toml|yaml|yml)$/.test(entry.name)
      ? [relativePath]
      : [];
  });
}

function findBalancedBlock(source: string, openBraceIndex: number): string | null {
  if (openBraceIndex < 0) return null;
  let depth = 0;
  for (let i = openBraceIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(openBraceIndex, i + 1);
    }
  }
  return null;
}

function findTypeDeclarations(source: string): Array<{ name: string; block: string }> {
  const declarations: Array<{ name: string; block: string }> = [];
  const declarationPattern = /\b(?:export\s+)?(type|interface)\s+(\w+)\b/g;
  let match: RegExpExecArray | null;
  while ((match = declarationPattern.exec(source))) {
    const [, declarationKind, name] = match;
    if (declarationKind === 'interface') {
      const openBraceIndex = source.indexOf('{', match.index);
      const block = findBalancedBlock(source, openBraceIndex);
      if (!block) continue;
      declarations.push({ name, block });
      declarationPattern.lastIndex = openBraceIndex + block.length;
      continue;
    }

    let curlyDepth = 0;
    let parenDepth = 0;
    let bracketDepth = 0;
    for (let i = match.index; i < source.length; i += 1) {
      const char = source[i];
      if (char === '{') curlyDepth += 1;
      if (char === '}') curlyDepth -= 1;
      if (char === '(') parenDepth += 1;
      if (char === ')') parenDepth -= 1;
      if (char === '[') bracketDepth += 1;
      if (char === ']') bracketDepth -= 1;
      if (char === ';' && curlyDepth === 0 && parenDepth === 0 && bracketDepth === 0) {
        declarations.push({ name, block: source.slice(match.index, i + 1) });
        declarationPattern.lastIndex = i + 1;
        break;
      }
    }
  }
  return declarations;
}

function findCallObjectBlocks(source: string, callee: string): string[] {
  const blocks: string[] = [];
  let searchIndex = 0;
  while (searchIndex < source.length) {
    const callIndex = source.indexOf(`${callee}(`, searchIndex);
    if (callIndex < 0) break;
    const openBraceIndex = source.indexOf('{', callIndex);
    const block = findBalancedBlock(source, openBraceIndex);
    if (block) blocks.push(block);
    searchIndex = callIndex + callee.length + 1;
  }
  return blocks;
}

function findTypedObjectLiteralBlocks(source: string, typeName: string): string[] {
  const blocks: string[] = [];
  const declarationPattern = new RegExp(`:\\s*${typeName}\\s*=\\s*\\{`, 'g');
  let match: RegExpExecArray | null;
  while ((match = declarationPattern.exec(source))) {
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (block) {
      blocks.push(block);
      declarationPattern.lastIndex = openBraceIndex + block.length;
    }
  }
  return blocks;
}

function requireTypeDeclarationBlock(source: string, typeName: string): string {
  const declaration = findTypeDeclarations(source).find((candidate) => candidate.name === typeName);
  if (!declaration) throw new Error(`missing type declaration: ${typeName}`);
  return declaration.block;
}

function withoutNeverTripwires(block: string): string {
  return block
    .replace(/\becdsaThresholdKeyId\?:\s*never\b/g, '')
    .replace(/\bthresholdSessionId\?:\s*never\b/g, '')
    .replace(/\bwalletSigningSessionId\?:\s*never\b/g, '')
    .replace(/\bsigningRootId\?:\s*never\b/g, '')
    .replace(/\bsigningRootVersion\?:\s*never\b/g, '')
    .replace(/\bparticipantIds\?:\s*never\b/g, '')
    .replace(/\bthresholdOwnerAddress\?:\s*never\b/g, '');
}

test.describe('signing engine refactor 37 guards', () => {
  test('Phase 10 public ECDSA requests expose wallet-session shape without internal key identity', () => {
    const interfaces = readRepoFile('client/src/core/SeamsPasskey/interfaces.ts');
    const messages = readRepoFile('client/src/core/WalletIframe/shared/messages.ts');
    const publicInputs = readRepoFile('client/src/core/SeamsPasskey/publicInputs.typecheck.ts');
    const bootstrapArgs = requireTypeDeclarationBlock(
      interfaces,
      'BootstrapThresholdEcdsaSessionArgs',
    );
    const signTempoArgs = requireTypeDeclarationBlock(interfaces, 'SignTempoArgs');
    const executeArgs = requireTypeDeclarationBlock(interfaces, 'ExecuteEvmFamilyTransactionArgs');
    const exportInput = requireTypeDeclarationBlock(interfaces, 'ExportKeypairWithUIInput');
    const emailOtpCapabilityArgs = requireTypeDeclarationBlock(
      interfaces,
      'EmailOtpEcdsaCapabilityArgs',
    );
    const signTempoPayload = requireTypeDeclarationBlock(messages, 'PMSignTempoPayload');
    const exportPayload = requireTypeDeclarationBlock(messages, 'PMExportKeypairUiPayload');
    const emailOtpCapabilityPayload = requireTypeDeclarationBlock(
      messages,
      'PMEmailOtpEcdsaCapabilityPayload',
    );

    for (const block of [bootstrapArgs, signTempoArgs, executeArgs, exportInput]) {
      expect(block).toContain('walletSession: WalletSessionRef;');
      expect(block).toContain('subjectId: WalletSubjectId;');
      expect(block).toContain('chainTarget: ThresholdEcdsaChainTarget;');
      expect(block).not.toContain('walletSessionUserId: string');
      expect(block).not.toContain('nearAccountId: string');
    }

    expect(bootstrapArgs).toContain("kind: 'reuse_warm_ecdsa_bootstrap';");
    expect(bootstrapArgs).toContain('ecdsaThresholdKeyId?: never;');
    expect(bootstrapArgs).toContain('participantIds?: never;');
    expect(bootstrapArgs).not.toContain("'passkey_fresh_ecdsa_bootstrap'");
    expect(bootstrapArgs).not.toContain("'passkey_cookie_reconnect_ecdsa_bootstrap'");
    expect(bootstrapArgs).not.toContain("'threshold_session_auth_reconnect_ecdsa_bootstrap'");
    expect(bootstrapArgs).not.toContain("'email_otp_ecdsa_bootstrap'");

    expect(signTempoArgs).toContain('request: MultichainSigningRequest;');
    expect(executeArgs).toContain('request: MultichainSigningRequest;');
    expect(exportInput).not.toContain('walletSessionUserId');
    for (const block of [emailOtpCapabilityArgs, emailOtpCapabilityPayload]) {
      expect(block).toContain('walletSession: WalletSessionRef;');
      expect(block).toContain('subjectId: WalletSubjectId;');
      expect(block).toContain('chainTarget: ThresholdEcdsaChainTarget;');
      expect(block).not.toContain('routeAuth');
      expect(block).not.toContain('ecdsaThresholdKeyId');
      expect(block).not.toContain('participantIds');
      expect(block).not.toContain('sessionKind');
      expect(block).not.toContain('sessionId');
      expect(block).not.toContain('ttlMs');
      expect(block).not.toContain('remainingUses');
      expect(block).not.toContain('runtimePolicyScope');
    }

    expect(messages).toContain(
      'export type PMBootstrapThresholdEcdsaSessionPayload = BootstrapThresholdEcdsaSessionArgs;',
    );
    for (const fixtureMarker of [
      'forbiddenProjectionField',
      'forbiddenProjectionAddressField',
      'forbiddenProjectionSponsorField',
      'forbiddenProjectionRelayField',
      'forbiddenProjectionProtocolField',
    ]) {
      expect(publicInputs).toContain(fixtureMarker);
    }
    for (const block of [signTempoPayload, exportPayload]) {
      expect(block).toContain('walletSession: WalletSessionRef;');
      expect(block).toContain('subjectId: WalletSubjectId;');
      expect(block).toContain('chainTarget: ThresholdEcdsaChainTarget;');
      expect(block).not.toContain('walletSessionUserId: string');
    }
    expect(signTempoPayload).toContain('request: MultichainSigningRequest;');
  });

  test('Phase 11 compile-only fixtures cover invalid ECDSA lifecycle combinations', () => {
    const ecdsaBootstrap = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.typecheck.ts',
    );
    const routePlan = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/routePlan.typecheck.ts',
    );
    const hssTypecheck = readRepoFile(
      'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts',
    );
    const thresholdAdmission = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.typecheck.ts',
    );
    const provisionPlanTypecheck = readRepoFile(
      'client/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts',
    );

    for (const expectedFixture of [
      '@ts-expect-error threshold-session reconnect requires the primed ECDSA client root share',
      '@ts-expect-error passkey fresh bootstrap rejects threshold-session auth reconnect material',
      '@ts-expect-error jwt passkey fresh bootstrap requires route auth or WebAuthn auth',
      '@ts-expect-error Email OTP bootstrap requires Email OTP auth context',
      '@ts-expect-error reuse bootstrap rejects client root share material',
    ]) {
      expect(ecdsaBootstrap).toContain(expectedFixture);
    }

    expect(routePlan).toContain(
      '@ts-expect-error authorizing session ids cannot be used as minted session ids',
    );
    expect(routePlan).toContain(
      '@ts-expect-error auth lanes carry authorizing ids, not minted ids',
    );
    expect(hssTypecheck).toContain(
      '@ts-expect-error stable ECDSA HSS key context rejects volatile wallet session ids',
    );
    expect(hssTypecheck).toContain(
      '@ts-expect-error stable ECDSA HSS key context rejects volatile threshold session ids',
    );
    expect(thresholdAdmission).toContain(
      '@ts-expect-error reauth results must carry canonical ready EVM-family material',
    );
    expect(thresholdAdmission).toContain(
      '@ts-expect-error passkey reconnect must return ready material',
    );
    expect(provisionPlanTypecheck).toContain(
      '@ts-expect-error reconnect material requires a persisted ECDSA record',
    );
    expect(provisionPlanTypecheck).toContain(
      '@ts-expect-error reconnect material requires an ECDSA key ref',
    );
  });

  test('Phase 11 registration and login guards keep one owner for EVM-family targets', () => {
    const registration = readRepoFile('client/src/core/SeamsPasskey/registration.ts');
    const login = readRepoFile('client/src/core/SeamsPasskey/login.ts');
    const syncAccount = readRepoFile('client/src/core/SeamsPasskey/syncAccount.ts');
    const hssBootstrapPolicy = readRepoFile(
      'tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts',
    );
    const identityUnit = readRepoFile('tests/unit/evmFamilyEcdsaIdentity.unit.test.ts');

    expect(registration).toContain(
      'let sharedKeyIdentity: EvmFamilyEcdsaKeyIdentity | null = null;',
    );
    expect(registration).toContain('key: sharedKeyIdentity,');
    expect(registration).toContain(
      "throw new Error('[Registration] threshold ECDSA bootstrap returned divergent shared key identity')",
    );
    expect(registration).toContain('thresholdOwnerAddress: String(args.key.thresholdOwnerAddress)');
    expect(login).toContain('collectConfiguredTargetThresholdEcdsaWarmKeys({');
    expect(login).toContain('deriveEvmFamilyKeyFingerprint(existing.key)');
    expect(login).not.toContain('sharedKey.thresholdOwnerAddress');
    expect(login).not.toContain('metadata.thresholdOwnerAddress ||');
    expect(syncAccount).not.toContain('rawRecord.signerId || metadata.ownerAddress');
    expect(syncAccount).not.toContain('thresholdOwnerAddress: signerId');
    expect(hssBootstrapPolicy).toContain(
      'registration_bootstrap derives the same shared key id and owner across EVM-family targets',
    );
    expect(identityUnit).toContain(
      'derives one shared fingerprint across Tempo and Arc/EVM session lanes',
    );
    expect(identityUnit).toContain(
      'expect(evmKey.thresholdOwnerAddress).toBe(tempoKey.thresholdOwnerAddress);',
    );
  });

  test('Phase 14 base ECDSA warm-up uses threshold ECDSA key identity inventory', () => {
    const login = readRepoFile('client/src/core/SeamsPasskey/login.ts');
    const thresholdEd25519Route = readRepoFile(
      'server/src/router/express/routes/thresholdEd25519.ts',
    );
    const thresholdEcdsaRoute = readRepoFile('server/src/router/express/routes/thresholdEcdsa.ts');
    const authService = readRepoFile('server/src/core/AuthService.ts');
    const bootstrap = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    );
    const warmBootstrap = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts',
    );
    const demoThresholdState = readRepoFile(
      'examples/seams-site/src/flows/demo/hooks/useDemoThresholdAccountState.ts',
    );

    expect(login).toContain('/threshold-ecdsa/key-identities');
    expect(thresholdEcdsaRoute).toContain('/threshold-ecdsa/key-identities');
    expect(thresholdEd25519Route).not.toContain('/threshold-ecdsa/key-identities');
    expect(authService).toContain('listThresholdEcdsaKeyIdentityTargetsForUser');
    expect(authService).toContain('getEcdsaKeyIdentityMetadata');
    expect(bootstrap).toContain('EvmFamilyEcdsaKeyIdentity');
    expect(bootstrap).toContain('EvmFamilyEcdsaSessionLanePolicy');
    expect(warmBootstrap).toContain('tryReuseReadyWarmEcdsaBootstrap');
    expect(demoThresholdState).not.toContain('bootstrapEcdsaSession');
    expect(demoThresholdState).toContain('thresholdEcdsaEthereumAddress');
  });

  test('Phase 14 removed projection-specific routes, fields, and imports repo-wide', () => {
    const forbiddenPatterns = [
      new RegExp(`${'smart'}[-_ ]?${'account'}`, 'i'),
      new RegExp(`${'smart'}[-_ ]?${'wallet'}`, 'i'),
      new RegExp(`${'counter'}${'factual'}`, 'i'),
      new RegExp(`${'erc'}[-_ ]?${'4337'}`, 'i'),
      new RegExp(`${'account'} ${'abstraction'}`, 'i'),
      new RegExp(`${'pay'}${'master'}`, 'i'),
      new RegExp(`${'Account'}${'Signer'}${'Store'}`),
      new RegExp(`${'recovery'}${'Authority'}`),
      new RegExp(
        `${'bundle'}${'r'}(?:Url|URL|Rpc|RPC|Route|Endpoint|Policy|Mode|Config|Field)`,
        'i',
      ),
    ];
    const allowedFiles = new Set(['docs/refactor-37.md']);
    const roots = ['docs', 'client', 'server', 'shared', 'tests', 'examples', 'contracts'];
    const offenders: string[] = [];

    for (const relativePath of roots.flatMap((root) => listRepoFiles(root))) {
      if (allowedFiles.has(relativePath)) continue;
      const source = readRepoFile(relativePath);
      for (const pattern of forbiddenPatterns) {
        if (pattern.test(source)) {
          offenders.push(`${relativePath} :: ${pattern}`);
          break;
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('EVM-family key/session field grouping stays in approved lane and boundary structs', () => {
    const approved = new Set([
      'client/src/core/signingEngine/session/availability/availableSigningLanes.ts::ConcreteAvailableEcdsaSigningLane',
      'client/src/core/signingEngine/session/identity/laneIdentity.ts::SelectedEcdsaLane',
      'client/src/core/signingEngine/session/identity/laneIdentity.ts::SelectedEcdsaLaneInput',
      'client/src/core/signingEngine/session/operationState/lanes.ts::EcdsaPasskeySigningLaneInput',
      'client/src/core/signingEngine/session/operationState/lanes.ts::EcdsaEmailOtpSigningLaneInput',
      'client/src/core/signingEngine/session/operationState/types.ts::EcdsaSigningSessionPlanningLane',
      'client/src/core/signingEngine/session/operationState/types.ts::ResolvedEcdsaSigningSessionIdentity',
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts::EcdsaMaterialSummary',
    ]);
    const roots = [
      'client/src/core/signingEngine/session',
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/flows/recovery',
      'client/src/core/signingEngine/threshold/ecdsa',
    ];
    const offenders: string[] = [];

    for (const relativePath of roots.flatMap((root) => listTsFiles(root))) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(relativePath);
      for (const declaration of findTypeDeclarations(source)) {
        const searchable = withoutNeverTripwires(declaration.block);
        const hasSessionIdentity = /\bthresholdSessionId\b/.test(searchable);
        const hasSharedKeyField = /\becdsaThresholdKeyId\b/.test(searchable);
        if (!hasSessionIdentity || !hasSharedKeyField) continue;
        const key = `${relativePath}::${declaration.name}`;
        if (!approved.has(key)) offenders.push(key);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);

    const exportMaterial = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts',
    );
    const exactExportLaneStart = exportMaterial.indexOf('export type ExactEcdsaExportLane =');
    expect(exactExportLaneStart).toBeGreaterThanOrEqual(0);
    const exactExportLane = findBalancedBlock(
      exportMaterial,
      exportMaterial.indexOf('{', exactExportLaneStart),
    );
    if (!exactExportLane) throw new Error('missing ExactEcdsaExportLane block');
    expect(exactExportLane).toContain('key: EvmFamilyEcdsaKeyIdentity;');
    expect(exactExportLane).toContain('session: {');
    expect(exactExportLane).not.toContain('subjectId:');
    expect(exactExportLane).not.toContain('ecdsaThresholdKeyId: string');
    expect(exactExportLane).not.toContain('walletSigningSessionId: string');
    expect(exactExportLane).not.toContain('thresholdSessionId: string');
  });

  test('EVM-family identity and lane types stay inside builders and type fixtures', () => {
    const allowedFiles = new Set([
      'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
      'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts',
    ]);
    const guardedTypes = [
      'EvmFamilyEcdsaKeyIdentity',
      'EvmFamilyEcdsaSessionLane',
      'ReadyEvmFamilyEcdsaMaterial',
    ] as const;
    const offenders: string[] = [];
    const spreadOffenders: string[] = [];
    const directConstructionPattern = new RegExp(
      `(?:const|let|var)\\s+\\w+\\s*:\\s*(?:${guardedTypes.join(
        '|',
      )})\\s*=\\s*\\{|as\\s+(?:${guardedTypes.join('|')})\\b|satisfies\\s+(?:${guardedTypes.join(
        '|',
      )})\\b`,
    );

    for (const relativePath of [
      ...listTsFiles('client/src/core/signingEngine'),
      ...listTsFiles('tests/unit'),
    ]) {
      if (allowedFiles.has(relativePath)) continue;
      const source = readRepoFile(relativePath);
      if (directConstructionPattern.test(source)) offenders.push(relativePath);
      for (const typeName of [
        'ReadyEvmFamilyEcdsaMaterial',
        'EvmFamilyEcdsaSessionLane',
      ] as const) {
        const typedBlocks = findTypedObjectLiteralBlocks(source, typeName);
        if (typedBlocks.some((block) => /\.\.\./.test(block))) {
          spreadOffenders.push(`${relativePath}::${typeName}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
    expect(spreadOffenders, spreadOffenders.join('\n')).toEqual([]);
  });

  test('exact ECDSA activation keeps stable key identity from the request', () => {
    const source = readRepoFile('client/src/core/signingEngine/threshold/ecdsa/activation.ts');

    expect(source).toContain(
      'exactActivation ? args.key.ecdsaThresholdKeyId : bootstrap.ecdsaThresholdKeyId',
    );
    expect(source).toContain('exactActivation ? args.key.signingRootId : bootstrap.signingRootId');
    expect(source).toContain(
      'exactActivation ? args.key.signingRootVersion : bootstrap.signingRootVersion',
    );
    expect(source).toContain('resolveExactActivationOwnerAddress({');
    expect(source).toContain(
      'threshold-ecdsa exact activation owner address mismatches server bootstrap result',
    );
  });

  test('Phase 3 ECDSA activation requests are constructed through branch builders', () => {
    const sessionProvision = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
    );
    const provisioner = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts',
    );
    const typecheck = readRepoFile(
      'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.typecheck.ts',
    );

    for (const builderName of [
      'buildPasskeyRegistrationEcdsaActivation',
      'buildPasskeyReconnectEcdsaActivation',
      'buildEmailOtpSessionBootstrapEcdsaActivation',
      'buildEmailOtpPerOperationReauthEcdsaActivation',
      'buildThresholdSessionReconnectEcdsaActivation',
      'buildEcdsaExportActivation',
    ]) {
      expect(sessionProvision).toContain(`export function ${builderName}`);
    }

    for (const builderName of [
      'buildPasskeyReconnectEcdsaActivation',
      'buildEmailOtpSessionBootstrapEcdsaActivation',
      'buildEmailOtpPerOperationReauthEcdsaActivation',
      'buildThresholdSessionReconnectEcdsaActivation',
      'buildCookieReconnectEcdsaActivation',
    ]) {
      expect(provisioner).toContain(`${builderName}(`);
    }

    expect(provisioner).not.toMatch(
      /\bThresholdEcdsa(?:PasskeyActivation|EmailOtpActivation|ThresholdSessionAuthReconnect|CookieReconnect)Request\b/,
    );
    expect(provisioner).not.toMatch(
      /\bconst\s+request:\s*ThresholdEcdsa(?:PasskeyActivation|EmailOtpActivation|ThresholdSessionAuthReconnect|CookieReconnect)Request\s*=/,
    );
    expect(sessionProvision).toContain('walletId?: never;');
    expect(sessionProvision).not.toContain('ThresholdEcdsaActivationRequestBoundaryIdentity');
    expect(sessionProvision).not.toContain('activationWalletId(');
    expect(sessionProvision).not.toContain('activationIdentityFields(');
    expect(provisioner).not.toContain('identityPair?:');
    expect(provisioner).toContain('type EcdsaActivationIdentityPair = {');
    expect(provisioner).toContain('identityPair: EcdsaActivationIdentityPair;');
    expect(typecheck).toContain(
      '@ts-expect-error activation builders require canonical key and lane policy',
    );
    expect(typecheck).toContain('@ts-expect-error exact activation derives walletId from key');
  });

  test('Phase 4 Email OTP HSS core types keep wallet and provider identities branded', () => {
    const coreTypeFiles = [
      'client/src/core/signingEngine/threshold/sessionPolicy.ts',
      'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    ];
    const rawWalletSessionFields = coreTypeFiles.filter((relativePath) =>
      /\bwalletSessionUserId:\s*string\b/.test(readRepoFile(relativePath)),
    );

    expect(rawWalletSessionFields, rawWalletSessionFields.join('\n')).toEqual([]);

    const login = readRepoFile('client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts');
    const enrollment = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
    );

    expect(login).toContain('toEmailOtpAuthSubjectId(');
    expect(login).toContain('toWalletSessionUserId(');
    expect(enrollment).toContain('toEmailOtpAuthSubjectId(');
    expect(enrollment).toContain('toWalletSessionUserId(');
  });

  test('Phase 4 ECDSA HSS prepare uses opaque server-planned context', () => {
    const hssClient = readRepoFile(
      'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    );
    const relayer = readRepoFile('client/src/core/rpcClients/relayer/thresholdEcdsa.ts');
    const bootstrapSession = readRepoFile(
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
    );
    const explicitExport = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts',
    );
    const emailOtpWorker = readRepoFile(
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );

    expect(hssClient).toContain('export type ServerPlannedEcdsaHssContext');
    expect(hssClient).toContain('context: ServerPlannedEcdsaHssContext;');
    expect(relayer).toContain('parseServerPlannedEcdsaHssContext(json.hssContext)');
    expect(bootstrapSession).toContain('context: prepare.hssContext');
    expect(explicitExport).toContain('context: prepare.hssContext');
    expect(bootstrapSession).not.toContain(
      'buildThresholdEcdsaHssStableKeyContext(prepare.hssContext)',
    );
    expect(explicitExport).not.toContain(
      'buildThresholdEcdsaHssStableKeyContext(prepare.hssContext)',
    );
    expect(emailOtpWorker).toContain(
      'chainTarget: thresholdEcdsaChainTargetKey(hssContext.chainTarget)',
    );
    expect(emailOtpWorker).not.toMatch(/toEcdsaHss\w+\(hssContext\./);
  });

  test('Phase 4 Email OTP HSS request builders reject broad identity escape hatches', () => {
    const walletScopedFiles = [
      'client/src/core/rpcClients/relayer/thresholdEcdsa.ts',
      'client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
      'client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    ];
    const providerLiteralPattern =
      /\b(?:walletSessionUserId|subjectId):\s*['"`][a-z][a-z0-9+.-]*:/i;
    const providerLiteralOffenders = walletScopedFiles.filter((relativePath) =>
      providerLiteralPattern.test(readRepoFile(relativePath)),
    );

    expect(providerLiteralOffenders, providerLiteralOffenders.join('\n')).toEqual([]);

    const stableContextOffenders = listTsFiles('client/src/core/signingEngine')
      .filter((relativePath) => !relativePath.endsWith('.typecheck.ts'))
      .filter(
        (relativePath) =>
          relativePath !== 'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
      )
      .filter((relativePath) =>
        /\b(?:buildThresholdEcdsaHssStableKeyContext|ThresholdEcdsaHssStableKeyContext)\b/.test(
          readRepoFile(relativePath),
        ),
      );
    expect(stableContextOffenders, stableContextOffenders.join('\n')).toEqual([]);

    const prepareRequestFiles = [
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    ];
    const broadSpreadOffenders = prepareRequestFiles.flatMap((relativePath) =>
      findCallObjectBlocks(readRepoFile(relativePath), 'thresholdEcdsaHssPrepare')
        .filter((block) =>
          /\.\.\.\s*(?:args|input|payload|request|bootstrap|workerBootstrap)\b/.test(block),
        )
        .map(() => relativePath),
    );

    expect(broadSpreadOffenders, broadSpreadOffenders.join('\n')).toEqual([]);
  });

  test('Phase 5 passkey registration and unlock warm-up use shared EVM-family keys', () => {
    const registration = readRepoFile('client/src/core/SeamsPasskey/registration.ts');
    const login = readRepoFile('client/src/core/SeamsPasskey/login.ts');

    expect(registration).toContain('const returnedKeyIdentity = buildEvmFamilyEcdsaKeyIdentity({');
    expect(registration).toContain('sharedEvmFamilyKey');
    expect(registration).toContain('targetMembership');
    expect(registration).toContain('buildEvmFamilyEcdsaSessionLanePolicy({');
    expect(login).toContain("kind: 'complete_shared_key_targets'");
    expect(login).toContain("kind: 'ambiguous_shared_key_targets'");
    expect(login).toContain("kind: 'missing_shared_key'");
    expect(login).toContain('key: targetEcdsaKey.key');
    expect(login).toContain('lanePolicy,');
  });

  test('Phase 6 EVM-family reauth returns canonical ready material', () => {
    const materialState = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
    );
    const thresholdAdmission = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts',
    );
    const thresholdAdmissionTypecheck = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.typecheck.ts',
    );
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const ecdsaSelection = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const signingRuntime = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
    );
    const emailOtpRefresh = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/emailOtpRefresh.ts',
    );
    const signEvmFamily = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const ecdsaLanes = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
    );

    expect(materialState).toContain('resolveReadyEvmFamilyEcdsaMaterial({');
    expect(materialState).toContain('buildEcdsaMaterialStateForResolvedLane');
    expect(materialState).toContain('readyMaterial: readyResolution.material');
    expect(materialState).not.toContain("kind: 'record_only';");
    expect(materialState).not.toContain("kind: 'key_ref_only';");
    expect(materialState).not.toContain('matchesCandidateIdentity');
    expect(materialState).not.toContain("record ? 'record_only'");
    expect(materialState).not.toContain("'key_ref_only'");
    expect(thresholdAdmission).toContain('readyMaterial: ReadyEvmFamilyEcdsaMaterial;');
    expect(ecdsaSelection).toContain('material: ReadyEcdsaMaterial;');
    expect(preparedSigning).toContain('material: EcdsaMaterialState;');
    expect(signingRuntime).toContain('readyMaterial: updated.readyMaterial');
    expect(emailOtpRefresh).toContain('readyMaterial: materialResolution.material');
    expect(ecdsaLanes).toContain('material: ReadyEvmFamilyEcdsaMaterial;');
    expect(ecdsaLanes).not.toContain("material: 'record'");
    expect(ecdsaLanes).not.toContain("material: 'key_ref'");
    expect(ecdsaLanes).not.toContain("material: 'record_and_key_ref'");
    expect(signEvmFamily).toContain('buildEcdsaMaterialStateForResolvedLane({');
    expect(signEvmFamily).not.toContain('buildEcdsaMaterialStateForCandidate');
    expect(signEvmFamily).not.toContain('buildPreparedMaterialForLane');
    expect(thresholdAdmissionTypecheck).toContain(
      '@ts-expect-error reauth results must carry canonical ready EVM-family material',
    );
    expect(thresholdAdmissionTypecheck).toContain(
      '@ts-expect-error passkey reconnect must return ready material',
    );
  });

  test('Phase 13 reconnect plans use paired ECDSA record and keyRef material', () => {
    const provisionPlan = readRepoFile(
      'client/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts',
    );
    const fixture = readRepoFile('tests/unit/helpers/warmSessionStore.fixtures.ts');

    expect(provisionPlan).toContain("kind: 'record_and_key_ref';");
    expect(provisionPlan).toContain('signingKeyContext?: never;');
    expect(provisionPlan).toContain(
      'const signingKeyContext = requireMatchingSigningKeyContext({ record, keyRef });',
    );
    expect(provisionPlan).not.toContain("kind: 'record_only';");
    expect(provisionPlan).not.toContain("kind: 'key_ref_only';");
    expect(fixture).toContain('buildEcdsaReconnectMaterial({');
    expect(fixture).not.toContain("kind: 'record_only' as const");
    expect(fixture).not.toContain("kind: 'key_ref_only' as const");
  });

  test('Phase 6 EVM-family fresh-auth retry stays side-effect gated', () => {
    const policy = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/freshAuthRetryPolicy.ts',
    );
    const signEvmFamily = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const freshEmailOtpRetry = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/freshEmailOtpRetry.ts',
    );
    const signingFlow = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
    );
    const signingRuntime = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
    );
    const trace = readRepoFile('client/src/core/signingEngine/session/operationState/trace.ts');

    expect(policy).toContain('export function classifyEvmFamilyFreshAuthRetry');
    for (const state of [
      'no_auth_side_effect_started',
      'auth_prompt_shown',
      'auth_confirmed',
      'threshold_reconnect_started',
    ]) {
      expect(policy).toContain(state);
    }
    expect(policy).toContain("return blocked('auth_side_effect_started')");
    expect(policy).toContain(
      "if (args.hasStepUpAuthPlan) return blocked('step_up_auth_plan_already_selected');",
    );
    expect(freshEmailOtpRetry).toMatch(/trigger:\s*'email_otp_auth_unavailable'/);
    expect(signEvmFamily).toMatch(/trigger:\s*'wallet_signing_budget_exhausted'/);
    expect(signEvmFamily).toContain('sideEffectState: freshAuthRetrySideEffectState');
    expect(signEvmFamily).toContain('recordFreshAuthRetryDecision(decision, error)');
    expect(signingFlow).toContain("notifyAuthSideEffectStarted('auth_confirmed')");
    expect(signingRuntime).toContain('onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted');
    expect(trace).toContain("'auth_confirmed'");
  });

  test('Phase 8 EVM-family budget failures include operation and lane diagnostics', () => {
    const signEvmFamily = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );

    expect(signEvmFamily).toContain('const buildBudgetFailureDiagnostics =');
    for (const field of [
      'operationId',
      'authMethod',
      'evmFamilyKeyFingerprint',
      'chainTargetKey',
      'ecdsaThresholdKeyId',
      'walletSigningSessionId',
      'thresholdSessionId',
      'budgetProjectionVersion',
      'freshAuthRetrySideEffectState',
    ]) {
      expect(signEvmFamily).toContain(field);
    }
    expect(signEvmFamily).toContain('...buildBudgetFailureDiagnostics(prepared)');
    expect(signEvmFamily).toContain('...buildBudgetFailureDiagnostics(admittedAfterReauth)');
  });

  test('Phase 8 ECDSA export/bootstrap failures include operation and lane diagnostics', () => {
    const exportKeypairOperation = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts',
    );
    const activation = readRepoFile('client/src/core/signingEngine/threshold/ecdsa/activation.ts');

    expect(exportKeypairOperation).toContain(
      "console.warn('[SigningEngine][ecdsa-export][failure]'",
    );
    expect(activation).toContain("console.warn('[threshold-ecdsa][bootstrap][exception]'");
    expect(activation).toContain("console.warn('[threshold-ecdsa][bootstrap][failure]'");

    for (const field of [
      'operationId',
      'authMethod',
      'evmFamilyKeyFingerprint',
      'chainTargetKey',
      'ecdsaThresholdKeyId',
      'walletSigningSessionId',
      'thresholdSessionId',
      'budgetProjectionVersion',
      'freshAuthRetrySideEffectState',
    ]) {
      expect(exportKeypairOperation).toContain(field);
      expect(activation).toContain(field);
    }
  });

  test('Postgres ECDSA key store bootstrap avoids request-time shared-identity unique index creation', () => {
    const keyStore = readRepoFile('server/src/core/ThresholdService/stores/KeyStore.ts');

    expect(keyStore).not.toContain(
      'CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_shared_identity_uidx',
    );
    expect(keyStore).toContain('DROP INDEX IF EXISTS threshold_ecdsa_keys_shared_identity_uidx');
    expect(keyStore).toContain(
      'CREATE INDEX IF NOT EXISTS threshold_ecdsa_keys_shared_identity_idx',
    );
  });

  test('Runtime EVM-family diagnostics thread one key fingerprint through signing/export/bootstrap traces', () => {
    const preparedSigning = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const signEvmFamily = readRepoFile(
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const exportKeypairOperation = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts',
    );
    const bootstrapSession = readRepoFile(
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
    );

    expect(preparedSigning).toContain('evmFamilyKeyFingerprint');
    expect(signEvmFamily).toContain("stage: 'ecdsa_attempt.nonce_operation_prepared'");
    expect(signEvmFamily).toContain("stage: 'ecdsa_attempt.budget_admitted'");
    expect(signEvmFamily).toContain("stage: 'ecdsa_attempt.budget_finalized'");
    expect(signEvmFamily).toContain('evmFamilyKeyFingerprint');
    expect(exportKeypairOperation).toContain('evmFamilyKeyFingerprint');
    expect(bootstrapSession).toContain("console.info('[threshold-ecdsa][hss-prepare][diagnostic]'");
    expect(bootstrapSession).toContain(
      "console.info('[threshold-ecdsa][hss-finalize][diagnostic]'",
    );
    expect(bootstrapSession).toContain('evmFamilyKeyFingerprint');
  });

  test('Phase 6 Email OTP ECDSA minting separates authorizing and minted session ids', () => {
    const authLane = readRepoFile(
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane.ts',
    );
    const routePlan = readRepoFile('client/src/core/signingEngine/session/emailOtp/routePlan.ts');
    const typecheck = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/routePlan.typecheck.ts',
    );
    const login = readRepoFile('client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts');
    const enrollment = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
    );

    expect(authLane).toContain('type AuthorizingWalletSigningSessionId');
    expect(authLane).toContain('type MintedWalletSigningSessionId');
    expect(authLane).toContain('authorizingWalletSigningSessionId');
    expect(authLane).not.toContain('walletSigningSessionId?: string;');
    expect(authLane).not.toContain('walletSigningSessionId: string;');
    expect(routePlan).toContain('buildPerOperationEmailOtpEcdsaMintingSession');
    expect(routePlan).toContain('assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession');
    expect(login).toContain('buildEmailOtpEcdsaMintingSession({');
    expect(enrollment).toContain('buildEmailOtpEcdsaMintingSession({');
    expect(login).not.toContain('routePlan.authLane.walletSigningSessionId');
    expect(enrollment).not.toContain('routePlan.authLane.walletSigningSessionId');
    expect(typecheck).toContain(
      '@ts-expect-error authorizing session ids cannot be used as minted session ids',
    );
    expect(typecheck).toContain(
      '@ts-expect-error auth lanes carry authorizing ids, not minted ids',
    );
  });

  test('one evmFamilyKeyFingerprint threads through the Phase 0 diagnostic fixture', () => {
    const key = buildEvmFamilyEcdsaKeyIdentity({
      walletId: 'alice.refactor37.testnet',
      subjectId: 'alice.refactor37.testnet',
      rpId: 'wallet.example.test',
      ecdsaThresholdKeyId: 'ehss-refactor37-shared-key',
      signingRootId: 'project:refactor37',
      signingRootVersion: 'default',
      participantIds: [2, 1],
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
    });
    const fingerprint = deriveEvmFamilyKeyFingerprint(key);
    const diagnosticFixture = [
      {
        stage: 'hss_prepare',
        evmFamilyKeyFingerprint: fingerprint,
        thresholdOwnerAddress: key.thresholdOwnerAddress,
      },
      {
        stage: 'lane_resolution',
        evmFamilyKeyFingerprint: fingerprint,
        thresholdOwnerAddress: key.thresholdOwnerAddress,
      },
      {
        stage: 'signing',
        evmFamilyKeyFingerprint: fingerprint,
        thresholdOwnerAddress: key.thresholdOwnerAddress,
      },
      {
        stage: 'export',
        evmFamilyKeyFingerprint: fingerprint,
        thresholdOwnerAddress: key.thresholdOwnerAddress,
      },
      {
        stage: 'nonce_resolution',
        evmFamilyKeyFingerprint: fingerprint,
        thresholdOwnerAddress: key.thresholdOwnerAddress,
      },
    ] as const;

    expect(new Set(diagnosticFixture.map((entry) => entry.evmFamilyKeyFingerprint)).size).toBe(1);
    expect(new Set(diagnosticFixture.map((entry) => entry.thresholdOwnerAddress)).size).toBe(1);
    expect(diagnosticFixture.map((entry) => entry.stage)).toEqual([
      'hss_prepare',
      'lane_resolution',
      'signing',
      'export',
      'nonce_resolution',
    ]);
  });
});
