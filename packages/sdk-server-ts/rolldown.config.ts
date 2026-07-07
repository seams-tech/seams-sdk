import * as path from 'path';
import * as fs from 'fs';

const SERVER_ROOT_ABS = process.cwd();
const SERVER_SRC_ROOT_ABS = path.resolve(SERVER_ROOT_ABS, 'src');

const toPosixPath = (p: string): string => p.split(path.sep).join('/');
const stripExt = (p: string): string => p.replace(/\.[^/.]+$/, '');
const stripLeadingDotDots = (p: string): string => {
  let out = p;
  while (out.startsWith('../')) out = out.slice(3);
  return out;
};

const preservedModuleOut = (opts: { facadeModuleId: string; rootAbs: string }) => {
  const facadeAbs = path.resolve(opts.facadeModuleId);
  const rel = toPosixPath(path.relative(opts.rootAbs, facadeAbs));
  const relNoExt = stripExt(stripLeadingDotDots(rel));
  return `${relNoExt}.js`;
};

const external = [
  'fs',
  'path',
  'url',
  'module',
  'crypto',
  'util',
  /^node:.*/,
  '@simplewebauthn/server',
  'bs58',
  'express',
  'tslib',
  /\.wasm$/,
];

const listSourceInputs = (dirAbs: string): string[] => {
  const entries = fs.readdirSync(dirAbs, { withFileTypes: true });
  const inputs: string[] = [];
  for (const entry of entries) {
    const entryAbs = path.join(dirAbs, entry.name);
    if (entry.isDirectory()) {
      inputs.push(...listSourceInputs(entryAbs));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith('.ts')) continue;
    if (entry.name.endsWith('.d.ts')) continue;
    if (entry.name.endsWith('.typecheck.ts')) continue;
    if (entry.name.endsWith('.test.ts')) continue;
    inputs.push(toPosixPath(path.relative(SERVER_ROOT_ABS, entryAbs)));
  }
  return inputs.sort();
};

const aliasConfig = {
  '@seams-internal/console-shared': path.resolve(
    SERVER_ROOT_ABS,
    '../console-shared-ts/src/index.ts',
  ),
  '@seams-internal/console-shared/*': path.resolve(SERVER_ROOT_ABS, '../console-shared-ts/src/*'),
  '@seams-internal/shared-ts/*': path.resolve(SERVER_ROOT_ABS, '../shared-ts/src/*'),
  '@shared/*': path.resolve(SERVER_ROOT_ABS, '../shared-ts/src/*'),
  '@server': path.resolve(SERVER_ROOT_ABS, 'src/index.ts'),
  '@server/*': path.resolve(SERVER_ROOT_ABS, 'src/*'),
};

const preservedEntryFileNames = (chunk: { facadeModuleId?: string | null; name: string }) => {
  if (!chunk.facadeModuleId) return `${chunk.name}.js`;
  return preservedModuleOut({
    facadeModuleId: chunk.facadeModuleId,
    rootAbs: SERVER_SRC_ROOT_ABS,
  });
};

export default [
  {
    input: listSourceInputs(SERVER_SRC_ROOT_ABS),
    output: {
      dir: 'dist/esm',
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: SERVER_SRC_ROOT_ABS,
      entryFileNames: preservedEntryFileNames,
      chunkFileNames: preservedEntryFileNames,
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  {
    input: 'src/router/express-adaptor.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      entryFileNames: 'router/express.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  {
    input: 'src/router/cloudflare-adaptor.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      entryFileNames: 'router/cloudflare.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  {
    input: 'src/router/ror-adaptor.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      entryFileNames: 'router/ror.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  {
    input: 'src/wasm/signer.ts',
    output: {
      dir: 'dist/esm',
      format: 'esm',
      entryFileNames: 'wasm/signer.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
];
