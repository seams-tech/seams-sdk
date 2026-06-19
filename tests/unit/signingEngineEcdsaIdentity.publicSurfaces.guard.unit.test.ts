import { expect, test } from '@playwright/test';
import {
  repoRoot,
  readRepoFile,
  listTsFiles,
  listSourceFiles,
  findCallObjects,
  findLoggerCalls,
  lineNumberForIndex,
  findBalancedBlock,
  findTypeDeclaration,
  findObjectBlockAfter,
  findChainedMethodCallObjects,
  findMethodDeclarationAndBody,
  expectRequiredFields,
  expectDeclaredFields,
  expectAnyDeclaredField,
  expectNoField,
  expectNoNearAccountId
} from './helpers/signingEngineEcdsaIdentityGuard';

test.describe('signing engine ECDSA public surface identity guards', () => {
  test('public SDK ECDSA inputs stay wallet-session shaped', () => {
    const source = readRepoFile('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const namedDeclarations = [
      {
        name: 'SignTempoArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
      {
        name: 'ReportTempoNonceLifecycleBaseArgs',
        required: ['walletSession', 'signedResult'],
        forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
      {
        name: 'ExecuteEvmFamilyTransactionArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
      {
        name: 'BootstrapThresholdEcdsaSessionArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
      {
        name: 'EmailOtpEcdsaCapabilityArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
      {
        name: 'ExportKeypairWithUIInput',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
        allowNeverTripwire: true,
      },
    ];
    const inlineArgBlocks = [
      {
        context: 'AuthCapability.prefillRouterAbEcdsaHssPresignaturePool',
        block: findObjectBlockAfter(source, 'prefillRouterAbEcdsaHssPresignaturePool(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
      {
        context: 'AuthCapability.requestEmailOtpSigningSessionChallenge',
        block: findObjectBlockAfter(source, 'requestEmailOtpSigningSessionChallenge(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
      {
        context: 'AuthCapability.refreshEmailOtpSigningSession',
        block: findObjectBlockAfter(source, 'refreshEmailOtpSigningSession(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
    ];
    const offenders: string[] = [];

    for (const declaration of namedDeclarations) {
      const block = findTypeDeclaration(source, declaration.name);
      offenders.push(
        ...expectRequiredFields(block, declaration.required, declaration.name),
        ...(declaration.forbidden || []).flatMap((field) =>
          expectNoField(block, field, declaration.name),
        ),
        ...expectNoNearAccountId(block, declaration.name, {
          allowNeverTripwire: declaration.allowNeverTripwire,
        }),
      );
    }

    for (const { context, block, required } of inlineArgBlocks) {
      offenders.push(
        ...expectRequiredFields(block, required, context),
        ...expectNoNearAccountId(block, context, { allowNeverTripwire: true }),
      );
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA iframe payloads stay wallet-session shaped', () => {
    const source = readRepoFile('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
    const namedDeclarations = [
      {
        name: 'PMSignTempoPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMTempoNonceLifecyclePayloadBase',
        required: ['walletSession', 'signedResult'],
        forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMExportKeypairUiPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMEmailOtpSigningSessionChallengePayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMEmailOtpEcdsaCapabilityPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMRefreshEmailOtpSigningSessionPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
      {
        name: 'PMPrefillRouterAbEcdsaHssPresignaturePoolPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      },
    ];
    const offenders: string[] = [];

    for (const declaration of namedDeclarations) {
      const block = findTypeDeclaration(source, declaration.name);
      offenders.push(
        ...expectRequiredFields(block, declaration.required, declaration.name),
        ...(declaration.forbidden || []).flatMap((field) =>
          expectNoField(block, field, declaration.name),
        ),
        ...expectNoNearAccountId(block, declaration.name),
      );
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('active SDK ECDSA key refs reject signing-root identity fields', () => {
    const source = readRepoFile('packages/sdk-web/src/core/signingEngine/interfaces/signing.ts');
    const keyRefBlock = findTypeDeclaration(source, 'KeyRef');
    const offenders: string[] = [];

    for (const field of ['signingRootId', 'signingRootVersion']) {
      const neverFieldPattern = new RegExp(`\\b${field}\\?:\\s*never\\b`);
      if (!neverFieldPattern.test(keyRefBlock)) {
        offenders.push(`KeyRef does not reject ${field} with a never field`);
      }
    }

    const searchable = keyRefBlock
      .replace(/\bsigningRootId\?:\s*never\b/g, '')
      .replace(/\bsigningRootVersion\?:\s*never\b/g, '');
    if (/\bsigningRoot(?:Id|Version)\??\s*:/.test(searchable)) {
      offenders.push('KeyRef exposes signing-root identity outside never tripwires');
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA HSS role-local bootstrap types keep lane identity explicit', () => {
    const clientSource = readRepoFile('packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts');
    const clientSessionPolicySource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts',
    );
    const serverSource = readRepoFile('packages/sdk-server-ts/src/core/types.ts');
    const thresholdPrfSource = readRepoFile('packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts');
    const hssClientSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    );
    const offenders: string[] = [];
    const requiredRoleLocalBootstrapFields = [
      'walletId',
      'rpId',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'keyScope',
      'relayerKeyId',
      'hssClientSharePublicKey33B64u',
      'contextBinding32B64u',
      'sessionId',
      'signingGrantId',
      'participantIds',
    ];

    for (const { source, file, typeName } of [
      {
        source: clientSource,
        file: 'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
        typeName: 'ThresholdEcdsaHssRoleLocalBootstrapRequest',
      },
      {
        source: clientSource,
        file: 'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
        typeName: 'ThresholdEcdsaHssRoleLocalBootstrapBody',
      },
      {
        source: serverSource,
        file: 'packages/sdk-server-ts/src/core/types.ts',
        typeName: 'EcdsaHssClientBootstrapRequestBase',
      },
    ]) {
      const block = findTypeDeclaration(source, typeName);
      offenders.push(
        ...expectRequiredFields(block, requiredRoleLocalBootstrapFields, `${file} ${typeName}`),
        ...expectNoField(block, 'chainTarget', `${file} ${typeName}`),
        ...expectNoField(block, 'keyHandle', `${file} ${typeName}`),
        ...expectNoNearAccountId(block, `${file} ${typeName}`, {
          allowNeverTripwire: true,
        }),
      );
    }

    const serverRoleLocalRecordBlock = findTypeDeclaration(
      serverSource,
      'EcdsaHssRoleLocalKeyRecord',
    );
    offenders.push(
      ...expectRequiredFields(
        serverRoleLocalRecordBlock,
        [
          'version',
          'keyHandle',
          'walletId',
          'rpId',
          'ecdsaThresholdKeyId',
          'relayerKeyId',
          'clientPublicKey33B64u',
          'relayerPublicKey33B64u',
          'groupPublicKey33B64u',
          'relayerShare32B64u',
          'relayerCaitSithInput',
        ],
        'packages/sdk-server-ts/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
      ...expectNoField(
        serverRoleLocalRecordBlock,
        'chainTarget',
        'packages/sdk-server-ts/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
      ...expectNoNearAccountId(
        serverRoleLocalRecordBlock,
        'packages/sdk-server-ts/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
    );

    const clientEcdsaPolicyBlock = findTypeDeclaration(
      clientSessionPolicySource,
      'EcdsaHssSessionPolicy',
    );
    offenders.push(
      ...expectRequiredFields(
        clientEcdsaPolicyBlock,
        ['walletId', 'rpId', 'chainTarget', 'sessionId'],
        'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
      ...expectNoField(
        clientEcdsaPolicyBlock,
        'userId',
        'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
      ...expectNoNearAccountId(
        clientEcdsaPolicyBlock,
        'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
    );

    const signingRootContextBlock = findTypeDeclaration(
      thresholdPrfSource,
      'EcdsaHssStableKeyPrfContext',
    );
    offenders.push(
      ...expectRequiredFields(
        signingRootContextBlock,
        ['walletId', 'rpId', 'signingRootId', 'keyPurpose', 'keyVersion'],
        'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ),
      ...expectNoNearAccountId(
        signingRootContextBlock,
        'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ),
    );

    const ecdsaClientContextBlock = findTypeDeclaration(
      hssClientSource,
      'ThresholdEcdsaHssStableKeyContext',
    );
    offenders.push(
      ...expectRequiredFields(
        ecdsaClientContextBlock,
        ['walletId', 'rpId', 'chainTarget', 'keyPurpose', 'keyVersion'],
        'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ),
      ...expectNoNearAccountId(
        ecdsaClientContextBlock,
        'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ),
    );

    for (const [block, context] of [
      [
        signingRootContextBlock,
        'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ],
      [
        ecdsaClientContextBlock,
        'packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ],
    ] as const) {
      for (const field of ['signingGrantId', 'thresholdSessionId']) {
        if (new RegExp(`\\b${field}\\s*:`).test(block)) {
          offenders.push(`${context} carries concrete ${field}`);
        }
        if (!new RegExp(`\\b${field}\\?:\\s*never\\b`).test(block)) {
          offenders.push(`${context} must reject ${field} with never`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA HSS WASM package exports stay role-local', () => {
    const clientDts = readRepoFile('wasm/hss_client_signer/pkg/hss_client_signer.d.ts');
    const serverDts = readRepoFile('wasm/eth_signer/pkg/eth_signer.d.ts');
    const nearWorkerDts = readRepoFile('wasm/near_signer/pkg/wasm_signer_worker.d.ts');
    const offenders: string[] = [];

    for (const symbol of [
      'threshold_ecdsa_hss_prepare_session',
      'threshold_ecdsa_hss_prepare_client_request',
      'threshold_ecdsa_hss_finalize_client_request',
      'threshold_ecdsa_hss_prepare_server_session',
      'threshold_ecdsa_hss_prepare_server_ceremony',
      'threshold_ecdsa_hss_finalize_server_report',
      'threshold_ecdsa_hss_open_server_output',
    ]) {
      if (clientDts.includes(symbol)) offenders.push(`client WASM still exports ${symbol}`);
      if (serverDts.includes(symbol)) offenders.push(`server WASM still exports ${symbol}`);
    }

    for (const symbol of [
      'PrepareThresholdEcdsaHssSession',
      'PrepareThresholdEcdsaHssClientRequest',
      'FinalizeThresholdEcdsaHssClientRequest',
    ]) {
      if (nearWorkerDts.includes(symbol)) offenders.push(`near worker still exposes ${symbol}`);
    }

    if (clientDts.includes('threshold_ecdsa_hss_role_local_prepare_client_bootstrap')) {
      offenders.push('client WASM still exports legacy root-share ECDSA prepare helper');
    }
    if (clientDts.includes('threshold_ecdsa_hss_role_local_export_artifact')) {
      offenders.push('client WASM still exports root-share ECDSA export helper');
    }
    if (clientDts.includes('threshold_ecdsa_hss_role_local_client_bootstrap')) {
      offenders.push('client WASM still exports single-call role-local client bootstrap');
    }

    if (clientDts.includes('threshold_ecdsa_hss_role_local_relayer_bootstrap')) {
      offenders.push('client WASM exposes relayer bootstrap helper');
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
