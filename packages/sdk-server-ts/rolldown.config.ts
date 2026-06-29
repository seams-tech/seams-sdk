import * as path from 'path';

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

const aliasConfig = {
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
    input: 'src/index.ts',
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
