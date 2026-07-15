// Rolldown config exporting an array of build entries.
import { BUILD_PATHS } from './build-paths.ts';
import * as path from 'path';
import * as fs from 'fs';
import { pathToFileURL } from 'url';

// NOTE: Rolldown's `preserveModulesRoot` is sensitive to relative paths; when it
// can't resolve the root cleanly it will preserve `client/src/...` (or similar)
// into the output. Use absolute roots so dist paths match `sdk/package.json`
// export maps (e.g. `dist/esm/index.js`, `dist/esm/core/...`).
const SDK_ROOT_ABS = process.cwd();
const CLIENT_SRC_ROOT_ABS = path.resolve(SDK_ROOT_ABS, 'src');
const CLIENT_REACT_ROOT_ABS = path.resolve(SDK_ROOT_ABS, 'src/react');
const CLIENT_PLUGINS_ROOT_ABS = path.resolve(SDK_ROOT_ABS, 'src/plugins');
const WALLET_STATIC_ASSETS_ROOT_ABS = path.resolve(SDK_ROOT_ABS, 'src/static/wallet-assets');
const WALLET_STATIC_ASSET_FILES = ['wallet-shims.js', 'wallet-service.css'] as const;
const NEAR_SIGNER_WASM_JS_ABS = path.resolve(
  SDK_ROOT_ABS,
  '../../wasm/near_signer/pkg/wasm_signer_worker.js',
);
const NEAR_SIGNER_WASM_JS_OUT = 'wasm/near_signer/pkg/wasm_signer_worker.js';
const ED25519_YAO_CLIENT_WASM_JS_ABS = path.resolve(
  SDK_ROOT_ABS,
  '../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js',
);
const ED25519_YAO_CLIENT_WASM_JS_OUT =
  'wasm/router_ab_ed25519_yao_client/pkg/router_ab_ed25519_yao_client.js';
const ECDSA_CLIENT_SIGNER_WASM_JS_ABS = path.resolve(
  SDK_ROOT_ABS,
  '../../wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js',
);
const ECDSA_CLIENT_SIGNER_WASM_JS_OUT = 'wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js';
const NEAR_SIGNER_WORKER_ENUM_EXPORTS = [
  'ConfirmationBehavior',
  'ConfirmationUIMode',
  'UserVerificationPolicy',
] as const;

const toPosixPath = (p: string): string => p.split(path.sep).join('/');
const stripExt = (p: string): string => p.replace(/\.[^/.]+$/, '');
const stripLeadingDotDots = (p: string): string => {
  let out = p;
  while (out.startsWith('../')) out = out.slice(3);
  return out;
};
const preservedModuleOut = (opts: { facadeModuleId: string; rootAbs: string; prefix: string }) => {
  const facadeAbs = path.resolve(opts.facadeModuleId);
  if (facadeAbs === NEAR_SIGNER_WASM_JS_ABS) return NEAR_SIGNER_WASM_JS_OUT;
  if (facadeAbs === ED25519_YAO_CLIENT_WASM_JS_ABS) return ED25519_YAO_CLIENT_WASM_JS_OUT;
  if (facadeAbs === ECDSA_CLIENT_SIGNER_WASM_JS_ABS) return ECDSA_CLIENT_SIGNER_WASM_JS_OUT;

  const rel = toPosixPath(path.relative(opts.rootAbs, facadeAbs));
  const relNoExt = stripExt(stripLeadingDotDots(rel));
  return `${opts.prefix}/${relNoExt}.js`;
};

const ensureNearSignerWorkerEnumExports = (code: string): string => {
  const exportLinePattern = /export \{([^}]+)\};/;
  const exportLineMatch = code.match(exportLinePattern);
  if (!exportLineMatch) return code;

  const exportedBindings = exportLineMatch[1]
    .split(',')
    .map((binding) => binding.trim())
    .filter(Boolean);

  const missingBindings = NEAR_SIGNER_WORKER_ENUM_EXPORTS.filter((binding) => {
    if (!code.includes(`const ${binding} = Object.freeze(`)) return false;
    return !exportedBindings.some((exportedBinding) => exportedBinding === binding);
  });
  if (missingBindings.length === 0) return code;

  const mergedBindings = [...exportedBindings, ...missingBindings].join(', ');
  return code.replace(exportLinePattern, `export { ${mergedBindings} };`);
};

const ensureEd25519YaoClientNamedInitExport = (code: string): string => {
  const exportLinePattern = /export \{([^}]+)\};/;
  const exportLineMatch = code.match(exportLinePattern);
  if (!exportLineMatch) return code;
  const exportedBindings = exportLineMatch[1]
    .split(',')
    .map((binding) => binding.trim())
    .filter(Boolean);
  if (!exportedBindings.includes('__wbg_init as default')) return code;
  if (exportedBindings.includes('__wbg_init')) return code;
  return code.replace(
    exportLinePattern,
    `export { ${['__wbg_init', ...exportedBindings].join(', ')} };`,
  );
};

// Lightweight define plugin to replace process.env.NODE_ENV with 'production' for
// browser/embedded bundles so React and others use prod paths and treeshake well.
const defineNodeEnvPlugin = {
  name: 'define-node-env',
  transform(code: string) {
    if (code && code.includes('process.env.NODE_ENV')) {
      return {
        code: code.replace(/process\.env\.NODE_ENV/g, '"production"'),
        map: null as any,
      };
    }
    return null as any;
  },
};

// Toggle production transforms based on environment
const isProd = process.env.NODE_ENV === 'production';
const prodPlugins = isProd ? [defineNodeEnvPlugin] : [];

const external = [
  // React dependencies
  'react',
  'react-dom',
  'react/jsx-runtime',

  // All @near-js packages
  /@near-js\/.*/,

  // Exclude Lit SSR shim (not needed for client-side only)
  '@lit-labs/ssr-dom-shim',
  // Externalize Lit for library builds so host bundler resolves a single copy
  'lit',
  /lit\/directives\/.*/,
  'lit-html',
  /lit-html\/.*/,

  // Node.js native modules used by package tooling helpers
  'fs',
  'path',
  'url',
  'module',
  'crypto',
  'util',
  /^node:.*/,

  // Core dependencies that should be provided by consuming application
  'borsh',
  'bs58',
  'qrcode',
  'jsqr',
  '@noble/hashes',
  /@noble\/hashes\/.*/,
  'idb',
  'near-api-js',

  // Other common packages
  'tslib',
  // UI libs used by React components should be provided by the app bundler

  // WASM modules - externalize so bundlers handle them correctly
  /\.wasm$/,
  /\.css$/,
];

// External dependencies for embedded components.
// IMPORTANT: Externalize Lit so the host app's bundler (e.g., Vite) serves a consistent copy.
// Bundling Lit directly into SDK bundles caused internal node_modules paths and ESM export mismatches.
// Embedded bundles are loaded directly in the browser (no bundler/import maps),
// so do NOT externalize dependencies. Bundle everything needed.
const embeddedExternal: (string | RegExp)[] = [];

const aliasConfig = {
  '@build-paths': path.resolve(SDK_ROOT_ABS, 'build-paths.ts'),
  '@/core/runtime': path.resolve(SDK_ROOT_ABS, 'src/core/runtime'),
  '@/core/runtime/*': path.resolve(SDK_ROOT_ABS, 'src/core/runtime/*'),
  '@/*': path.resolve(SDK_ROOT_ABS, 'src/*'),
  '@shared/*': path.resolve(SDK_ROOT_ABS, '../shared-ts/src/*'),
};

type WalletStaticAssetFile = (typeof WALLET_STATIC_ASSET_FILES)[number];

const walletStaticAssetSourcePath = (fileName: WalletStaticAssetFile): string =>
  path.join(WALLET_STATIC_ASSETS_ROOT_ABS, fileName);

const copyWalletStaticAsset = (sdkDir: string, fileName: WalletStaticAssetFile): void => {
  fs.copyFileSync(walletStaticAssetSourcePath(fileName), path.join(sdkDir, fileName));
};

const copyWalletStaticAssets = (sdkDir: string): void => {
  for (const fileName of WALLET_STATIC_ASSET_FILES) {
    copyWalletStaticAsset(sdkDir, fileName);
  }
};

const W3A_COMPONENT_HOSTS = [
  'w3a-tx-tree',
  'w3a-drawer',
  'w3a-modal-tx-confirmer',
  'w3a-drawer-tx-confirmer',
  'w3a-tx-confirm-content',
  'w3a-halo-border',
  'w3a-passkey-halo-loading',
] as const;

const emitW3AThemeAliases = (vars: any, indent = '  '): string[] => [
  `${indent}--w3a-colors-textPrimary: ${vars.textPrimary};`,
  `${indent}--w3a-colors-textSecondary: ${vars.textSecondary};`,
  `${indent}--w3a-colors-textMuted: ${vars.textMuted};`,
  `${indent}--w3a-colors-textButton: ${vars.textButton};`,
  `${indent}--w3a-colors-colorBackground: ${vars.colorBackground};`,
  `${indent}--w3a-colors-surface: ${vars.surface};`,
  `${indent}--w3a-colors-surface2: ${vars.surface2};`,
  `${indent}--w3a-colors-surface3: ${vars.surface3};`,
  `${indent}--w3a-colors-surface4: ${vars.surface4};`,
  `${indent}--w3a-colors-primary: ${vars.primary};`,
  `${indent}--w3a-colors-primaryHover: ${vars.primaryHover};`,
  `${indent}--w3a-colors-secondary: ${vars.secondary};`,
  `${indent}--w3a-colors-secondaryHover: ${vars.secondaryHover};`,
  `${indent}--w3a-colors-accent: ${vars.accent};`,
  `${indent}--w3a-colors-buttonBackground: ${vars.buttonBackground};`,
  `${indent}--w3a-colors-buttonHoverBackground: ${vars.buttonHoverBackground};`,
  `${indent}--w3a-colors-hover: ${vars.hover};`,
  `${indent}--w3a-colors-active: ${vars.active};`,
  `${indent}--w3a-colors-focus: ${vars.focus};`,
  `${indent}--w3a-colors-success: ${vars.success};`,
  `${indent}--w3a-colors-warning: ${vars.warning};`,
  `${indent}--w3a-colors-error: ${vars.error};`,
  `${indent}--w3a-colors-info: ${vars.info};`,
  `${indent}--w3a-colors-borderPrimary: ${vars.borderPrimary};`,
  `${indent}--w3a-colors-borderSecondary: ${vars.borderSecondary};`,
  `${indent}--w3a-colors-borderHover: ${vars.borderHover};`,
  `${indent}--w3a-colors-gradientPrimary: ${vars.gradientPrimary};`,
  `${indent}--w3a-colors-gradientSecondary: ${vars.gradientSecondary};`,
  `${indent}--w3a-colors-gradientTertiary: ${vars.gradientTertiary};`,
  `${indent}--w3a-colors-highlightReceiverId: ${vars.highlightReceiverId};`,
  `${indent}--w3a-colors-highlightMethodName: ${vars.highlightMethodName};`,
  `${indent}--w3a-colors-highlightAmount: ${vars.highlightAmount};`,
];

const buildW3AComponentsCss = async (sdkRoot: string): Promise<string> => {
  const palettePath = path.join(sdkRoot, 'src/theme/palette.json');
  const paletteRaw = fs.readFileSync(palettePath, 'utf-8');
  const palette = JSON.parse(paletteRaw) as any;

  const baseStylesPath = path.join(sdkRoot, 'src/theme/base-styles.js');
  const base = await import(pathToFileURL(baseStylesPath).href);
  const { createThemeTokens } = base as any;
  const { DARK_THEME: darkVars, LIGHT_THEME: lightVars } = createThemeTokens(palette);

  const hostSelector = W3A_COMPONENT_HOSTS.join(',\n');
  const lines: string[] = [];

  lines.push(
    '/* Generated from src/theme/palette.json + src/theme/base-styles.js. Do not edit by hand. */',
  );
  lines.push(`${hostSelector} {`);
  lines.push(`  --w3a-modal__btn__focus-outline-color: ${darkVars?.focus || '#3b82f6'};`);
  lines.push('  --w3a-tree__file-content__scrollbar-track__background: rgba(255, 255, 255, 0.06);');
  lines.push('  --w3a-tree__file-content__scrollbar-thumb__background: rgba(255, 255, 255, 0.22);');

  const pushScale = (name: string, scale: Record<string, string>) => {
    Object.keys(scale || {}).forEach((k) => {
      lines.push(`  --w3a-${name}${k}: ${scale[k]};`);
    });
  };

  pushScale('grey', palette.grey || {});
  pushScale('slate', palette.slate || {});

  const exclude = new Set(['grey', 'slate', 'gradients', 'tokens', 'themes']);
  Object.keys(palette)
    .filter((k) => !exclude.has(k))
    .forEach((fam) => {
      if (palette[fam] && typeof palette[fam] === 'object') pushScale(fam, palette[fam]);
    });

  Object.keys(palette.gradients || {}).forEach((name) => {
    lines.push(`  --w3a-gradient-${name}: ${palette.gradients[name]};`);
  });

  lines.push('');
  lines.push('  /* Default token aliases (dark) for hosts */');
  lines.push(...emitW3AThemeAliases(darkVars));
  lines.push('}');

  lines.push('');
  lines.push(':root {');
  lines.push(...emitW3AThemeAliases(darkVars, '  '));
  lines.push('}');
  lines.push('');
  lines.push(':root[data-w3a-theme="light"] {');
  lines.push(...emitW3AThemeAliases(lightVars, '  '));
  lines.push('}');

  const themedSelLight = W3A_COMPONENT_HOSTS.map((s) => `:root[data-w3a-theme="light"] ${s}`).join(
    ',\n',
  );

  lines.push('');
  lines.push(`${themedSelLight} {`);
  lines.push(...emitW3AThemeAliases(lightVars, '  '));
  lines.push('}');

  return `${lines.join('\n')}\n`;
};

const emitWalletServiceStaticAssets = async (sdkRoot = process.cwd()): Promise<void> => {
  const sdkDir = path.join(sdkRoot, `${BUILD_PATHS.BUILD.ESM}/sdk`);
  fs.mkdirSync(sdkDir, { recursive: true });

  const copyIfMissing = (src: string, dest: string) => {
    if (fs.existsSync(src) && !fs.existsSync(dest)) fs.copyFileSync(src, dest);
  };

  copyWalletStaticAssets(sdkDir);

  try {
    const w3aComponentsCss = await buildW3AComponentsCss(sdkRoot);
    fs.writeFileSync(path.join(sdkDir, 'w3a-components.css'), w3aComponentsCss, 'utf-8');
  } catch (e) {
    console.warn('⚠️  Failed to generate w3a-components.css from palette:', e);
    const src = path.join(
      sdkRoot,
      'src/core/signingEngine/uiConfirm/ui/lit-components/css/w3a-components.css',
    );
    const dest = path.join(sdkDir, 'w3a-components.css');
    if (fs.existsSync(src)) fs.copyFileSync(src, dest);
  }

  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/tx-tree.css'),
    path.join(sdkDir, 'tx-tree.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/tx-confirmer.css'),
    path.join(sdkDir, 'tx-confirmer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/drawer.css'),
    path.join(sdkDir, 'drawer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/halo-border.css'),
    path.join(sdkDir, 'halo-border.css'),
  );
  copyIfMissing(
    path.join(
      sdkRoot,
      'src/core/signingEngine/uiConfirm/ui/lit-components/css/passkey-halo-loading.css',
    ),
    path.join(sdkDir, 'passkey-halo-loading.css'),
  );
  copyIfMissing(
    path.join(
      sdkRoot,
      'src/core/signingEngine/uiConfirm/ui/lit-components/css/seams-passkey-registration-btn.css',
    ),
    path.join(sdkDir, 'seams-passkey-registration-btn.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/padlock-icon.css'),
    path.join(sdkDir, 'padlock-icon.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/export-viewer.css'),
    path.join(sdkDir, 'export-viewer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/core/signingEngine/uiConfirm/ui/lit-components/css/export-iframe.css'),
    path.join(sdkDir, 'export-iframe.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, 'src/SeamsWeb/walletIframe/client/overlay/overlay.css'),
    path.join(sdkDir, 'overlay.css'),
  );

  console.log('✅ Emitted /sdk wallet-shims.js and wallet-service.css');
};

const emitWalletServiceStaticPlugin = {
  name: 'emit-wallet-service-static',
  async generateBundle() {
    try {
      await emitWalletServiceStaticAssets();
    } catch (err) {
      console.warn('⚠️  Unable to emit wallet static assets:', err);
    }
  },
};

const collectCssFiles = (dir: string, files: string[] = []): string[] => {
  if (!fs.existsSync(dir)) return files;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectCssFiles(fullPath, files);
      continue;
    }
    if (entry.isFile() && fullPath.endsWith('.css')) files.push(fullPath);
  }
  return files;
};

const CSS_IMPORT_LINE_PATTERN = /^\s*@import\s+['"]([^'"]+)['"];\s*$/;

const inlineCssImportLine = (line: string, currentFilePath: string, seen: Set<string>): string => {
  const match = line.match(CSS_IMPORT_LINE_PATTERN);
  if (!match) return line;
  const child = path.resolve(path.dirname(currentFilePath), match[1]);
  return inlineCssImports(child, seen);
};

const inlineCssImports = (filePath: string, seen = new Set<string>()): string => {
  const normalized = path.resolve(filePath);
  if (seen.has(normalized)) return '';
  seen.add(normalized);
  const source = fs.readFileSync(normalized, 'utf-8');
  const lines = source.split(/\r?\n/);
  const inlinedLines: string[] = [];
  for (const line of lines) {
    inlinedLines.push(inlineCssImportLine(line, normalized, seen));
  }
  return inlinedLines.join('\n');
};

const emitReactCssAssets = (sdkRoot = process.cwd()): void => {
  const srcReactRoot = path.join(sdkRoot, 'src/react');
  const destReactRoot = path.join(sdkRoot, `${BUILD_PATHS.BUILD.ESM}/react`);
  const destModuleRoot = path.join(sdkRoot, BUILD_PATHS.BUILD.ESM);
  for (const src of collectCssFiles(srcReactRoot)) {
    const rel = path.relative(srcReactRoot, src);
    for (const root of [destReactRoot, destModuleRoot]) {
      const dest = path.join(root, rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(src, dest);
    }
  }
  const stylesOut = path.join(destReactRoot, 'styles/styles.css');
  fs.mkdirSync(path.dirname(stylesOut), { recursive: true });
  fs.writeFileSync(stylesOut, inlineCssImports(path.join(srcReactRoot, 'styles.css')), 'utf-8');
};

const emitReactCssAssetsPlugin = {
  name: 'emit-react-css-assets',
  generateBundle() {
    emitReactCssAssets();
  },
};

const copyWasmAsset = (source: string, destination: string, label: string): void => {
  if (!fs.existsSync(source)) {
    throw new Error(`Missing WASM source at ${source}`);
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  console.log(label);
};

const configs = [
  // ESM build
  {
    input: [
      'src/index.ts',
      'src/advanced.ts',
      'src/runtime.ts',
      'src/SeamsWeb/index.ts',
      // Stable threshold workflow surface.
      'src/threshold.ts',
      // Treat this as an entry so Rolldown doesn't tree-shake its re-exported WASM enums.
      // Tests (and some internal tools) import `core/types/signer-worker` directly.
      'src/core/types/signer-worker.ts',
      // Keep active IndexedDB repository internals as stable deep-import entries for tests/tools.
      'src/core/indexedDB/index.ts',
      'src/core/accountData/near/keyMaterial.ts',
      'src/core/indexedDB/seamsWalletDB/repositories.ts',
      // Keep Email OTP device-local escrow store as a stable deep import for worker wiring/tests.
      'src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts',
      // Keep sealed signing-session persistence stable for worker wiring/tests.
      'src/core/signingEngine/session/persistence/sealedSessionStore.ts',
      // Keep worker-facing WASM wrapper exports stable for deep imports used by tests/tools.
      'src/core/signingEngine/chains/evm/ethSignerWasm.ts',
    ],
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_SRC_ROOT_ABS,
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
    plugins: [emitReactCssAssetsPlugin],
  },
  // Plugins: headers helper ESM
  {
    input: 'src/plugins/headers.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'plugins/headers.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Plugins: Next helper ESM
  {
    input: 'src/plugins/next.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'plugins/next.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // React ESM build
  {
    input: [
      'src/react/index.ts',
      'src/react/context/SeamsWebProvider.tsx',
      // Ensure public subpath entrypoints exist in dist even when re-exports are flattened.
      'src/react/components/SeamsAuthMenu/public.ts',
      // Public subpath entrypoints (avoid treeshaking away default exports).
      'src/react/components/SeamsAuthMenu/preload.ts',
      'src/react/components/SeamsAuthMenu/shell.tsx',
      'src/react/components/SeamsAuthMenu/skeleton.tsx',
      'src/react/components/SeamsAuthMenu/client.tsx',
    ],
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_REACT_ROOT_ABS,
      entryFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `react/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: CLIENT_REACT_ROOT_ABS,
          prefix: 'react',
        });
      },
      chunkFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `react/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: CLIENT_REACT_ROOT_ABS,
          prefix: 'react',
        });
      },
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Shared utils needed in-browser by some test harnesses (served under `/sdk/esm/*`).
  {
    input: '../shared-ts/src/utils/base64.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'utils/base64.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // WASM Signer Worker build for server usage - includes WASM binary
  {
    input: '../../wasm/near_signer/pkg/wasm_signer_worker.js',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'wasm/near_signer/pkg/wasm_signer_worker.js',
    },
    plugins: [
      {
        name: 'emit-near-signer-wasm',
        generateBundle(_options, bundle) {
          for (const output of Object.values(bundle)) {
            if (output.type !== 'chunk' || output.fileName !== NEAR_SIGNER_WASM_JS_OUT) continue;
            output.code = ensureNearSignerWorkerEnumExports(output.code);
          }
          try {
            const source = fs.readFileSync(
              path.join(SDK_ROOT_ABS, '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm'),
            );
            (this as any).emitFile({
              type: 'asset',
              fileName: 'wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
              source,
            });
            console.log('✅ Emitted dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm');
          } catch (error) {
            console.error('❌ Failed to copy signer WASM asset:', error);
            throw error;
          }
        },
      },
    ],
  },
  {
    input: '../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'wasm/router_ab_ed25519_yao_client/pkg/router_ab_ed25519_yao_client.js',
    },
    plugins: [
      {
        name: 'emit-ed25519-yao-client-wasm',
        generateBundle(_options, bundle) {
          for (const output of Object.values(bundle)) {
            if (output.type !== 'chunk' || output.fileName !== ED25519_YAO_CLIENT_WASM_JS_OUT) {
              continue;
            }
            output.code = ensureEd25519YaoClientNamedInitExport(output.code);
          }
          const source = fs.readFileSync(
            path.join(
              SDK_ROOT_ABS,
              '../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client_bg.wasm',
            ),
          );
          (this as any).emitFile({
            type: 'asset',
            fileName: 'wasm/router_ab_ed25519_yao_client/pkg/router_ab_ed25519_yao_client_bg.wasm',
            source,
          });
          console.log('✅ Emitted Ed25519 Yao Client WASM asset');
        },
      },
    ],
  },
  {
    input: '../../wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js',
    },
    plugins: [
      {
        name: 'emit-hss-client-signer-wasm',
        generateBundle(_options, bundle) {
          for (const output of Object.values(bundle)) {
            if (output.type !== 'chunk' || output.fileName !== ECDSA_CLIENT_SIGNER_WASM_JS_OUT) {
              continue;
            }
          }
          try {
            const source = fs.readFileSync(
              path.join(SDK_ROOT_ABS, '../../wasm/ecdsa_client_signer/pkg/ecdsa_client_signer_bg.wasm'),
            );
            (this as any).emitFile({
              type: 'asset',
              fileName: 'wasm/ecdsa_client_signer/pkg/ecdsa_client_signer_bg.wasm',
              source,
            });
            console.log('✅ Emitted dist/esm/wasm/ecdsa_client_signer/pkg/ecdsa_client_signer_bg.wasm');
          } catch (error) {
            console.error('❌ Failed to copy ECDSA client signer WASM asset:', error);
            throw error;
          }
        },
      },
    ],
  },
  // Confirm UI helpers and elements bundle for iframe usage
  // Build from confirm-ui.ts (container-agnostic); keep output filename stable
  {
    input: 'src/core/signingEngine/uiConfirm/ui/confirm-ui.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/tx-confirm-ui.js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Wallet iframe host + confirmer bundles
  {
    input: {
      // Tx Confirmer component
      'w3a-tx-confirmer':
        'src/core/signingEngine/uiConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts',
      'seams-passkey-registration-btn':
        'src/core/signingEngine/uiConfirm/ui/lit-components/passkey-registration-btn/entrypoints/seams-passkey-registration-btn.ts',
      // Wallet service host (headless)
      'wallet-iframe-host-runtime': 'src/SeamsWeb/walletIframe/host/index.ts',
      'wallet-iframe-host-near': 'src/SeamsWeb/walletIframe/host/entry-near.ts',
      'wallet-iframe-host-ecdsa': 'src/SeamsWeb/walletIframe/host/entry-ecdsa.ts',
      'wallet-iframe-host-full': 'src/SeamsWeb/walletIframe/host/entry-full.ts',
      // Export viewer host + bootstrap
      'iframe-export-bootstrap':
        'src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts',
    },
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/[name].js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: [...prodPlugins, emitWalletServiceStaticPlugin],
  },
  // Export Private Key viewer bundle (Lit element rendered inside iframe)
  {
    input: 'src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/viewer.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/export-private-key-viewer.js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Standalone bundles for HaloBorder + PasskeyHaloLoading (for iframe/embedded usage)
  {
    input: {
      'halo-border': 'src/core/signingEngine/uiConfirm/ui/lit-components/HaloBorder/index.ts',
      'passkey-halo-loading':
        'src/core/signingEngine/uiConfirm/ui/lit-components/PasskeyHaloLoading/index.ts',
    },
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/[name].js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Vite plugin ESM build (source moved to src/plugins)
  {
    input: 'src/plugins/vite.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_PLUGINS_ROOT_ABS,
      entryFileNames: 'plugins/[name].js',
      chunkFileNames: 'plugins/[name].js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
] satisfies import('rolldown').RolldownOptions[];

export default configs;
