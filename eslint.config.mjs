import js from '@eslint/js';
import globals from 'globals';
import prettier from 'eslint-config-prettier';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/.svelte-kit/**',
      '**/.vercel/**',
      '**/.wrangler/**',
      '**/.turbo/**',
      '**/.vitepress/cache/**',
      '**/.lake/**',
      '**/.playwright-cli/**',
      '**/.runtime/**',
      '**/coverage/**',
      '**/playwright-report/**',
      '**/test-results/**',
      'crates/ed25519-yao-cloudflare-bench/build/**',
      'crates/**/build/**',
      'crates/**/bundled/**',
      'crates/**/wasm-bench/pkg*/**',
      'crates/**/_build/**',
      'tools/**/target/**',
      'wasm/**/pkg/**',
      'wasm/**/target/**',
      'apps/seams-site/public/**',
    ],
  },

  js.configs.recommended,

  ...tseslint.configs.recommended,

  {
    files: ['**/*.{js,jsx,mjs,cjs,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.es2022,
        ...globals.browser,
        ...globals.node,
        ...globals.worker,
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'max-len': [
        'warn',
        {
          code: 140,
          tabWidth: 2,
          ignoreUrls: true,
          ignoreStrings: true,
          ignoreTemplateLiterals: true,
          ignoreRegExpLiterals: true,
          ignoreComments: true,
        },
      ],
      // TS-aware version should apply only to TS files (see TS override).
      '@typescript-eslint/no-unused-vars': 'off',

      // Common, intentional patterns in this repo (e.g. `catch {}` around optional APIs).
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },

  {
    files: ['**/*.{jsx,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
    },
  },

  {
    files: ['**/*.{ts,tsx}'],
    rules: {
      // TypeScript handles this better than ESLint.
      'no-undef': 'off',

      // Prefer TS-aware version.
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],

      // Too noisy for an existing TS codebase; keep as signal without blocking CI.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-non-null-asserted-optional-chain': 'warn',
      '@typescript-eslint/no-unused-expressions': [
        'error',
        { allowShortCircuit: true, allowTernary: true },
      ],

      // Prefer `@ts-expect-error`, but don't fail the build on existing usage.
      '@typescript-eslint/ban-ts-comment': 'warn',
    },
  },

  {
    files: ['**/*.d.ts'],
    rules: {
      // Declaration files frequently need `any` to model external libs.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },

  {
    files: ['**/*.typecheck.ts', '**/tests/type-fixtures/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unused-expressions': 'off',
    },
  },

  {
    files: ['tests/**/*.{ts,tsx,js,jsx,mjs,cjs}', '**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      'react-hooks/rules-of-hooks': 'off',
      'react-hooks/exhaustive-deps': 'off',
    },
  },

  {
    // Complex domain-state records in tests must come from the shared factories
    // (tests/AGENTS.md "Fixture rules"); inline literals drift when domain types change.
    files: ['tests/unit/**/*.test.ts', 'tests/relayer/**/*.test.ts'],
    ignores: [
      'tests/unit/helpers/**',
      'tests/helpers/**',
      // Grandfathered pre-existing offenders (2026-07-23): migrate onto the shared
      // factories and delete the entry. Do not add new entries.
      'tests/unit/touchConfirm.workerRouter.integration.test.ts',
      'tests/unit/evmClient.waitForReceipt.unit.test.ts',
      'tests/unit/addWalletSigner.orchestration.unit.test.ts',
      'tests/unit/seamsWeb.chainSigners.integration.test.ts',
      'tests/unit/nonceCoordinator.unit.test.ts',
      'tests/unit/d1StagingEvidenceVerify.script.unit.test.ts',
      'tests/unit/cloudflareD1RouterApiServiceSurface.unit.test.ts',
      'tests/unit/warmSessionStore.concurrency.unit.test.ts',
      'tests/unit/warmEd25519SigningSessionAuthorization.unit.test.ts',
      'tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts',
      'tests/unit/vite-wallet-corp.unit.test.ts',
      'tests/unit/pluginRorOrigins.unit.test.ts',
    ],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            'TSSatisfiesExpression > TSTypeReference[typeName.name=/(Record|CapabilityState|AuthorizationState|SessionStatus)$/]',
          message:
            'Inline domain-state record literal. Build it with a shared factory from tests/unit/helpers/ or tests/helpers/ (see tests/AGENTS.md, "Fixture rules").',
        },
        {
          selector:
            'VariableDeclarator[id.typeAnnotation.typeAnnotation.typeName.name=/(Record|CapabilityState|AuthorizationState|SessionStatus)$/] > ObjectExpression',
          message:
            'Inline domain-state record literal. Build it with a shared factory from tests/unit/helpers/ or tests/helpers/ (see tests/AGENTS.md, "Fixture rules").',
        },
      ],
    },
  },

  // Keep ESLint from fighting Prettier.
  prettier,
];
