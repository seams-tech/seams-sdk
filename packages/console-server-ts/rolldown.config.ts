import * as fs from 'fs';
import * as path from 'path';

const PACKAGE_ROOT_ABS = process.cwd();
const PACKAGE_SRC_ROOT_ABS = path.resolve(PACKAGE_ROOT_ABS, 'src');

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
    inputs.push(toPosixPath(path.relative(PACKAGE_ROOT_ABS, entryAbs)));
  }
  return inputs.sort();
};

const external = [
  'fs',
  'path',
  'url',
  'module',
  'crypto',
  'util',
  /^node:.*/,
  /^@seams\/sdk-server\/internal\//,
  '@seams/sdk-server',
  'bs58',
  'express',
  'tslib',
  /\.wasm$/,
];

const aliasConfig = {
  '@seams-internal/console-shared': path.resolve(
    PACKAGE_ROOT_ABS,
    '../console-shared-ts/src/index.ts',
  ),
  '@seams-internal/console-shared/*': path.resolve(
    PACKAGE_ROOT_ABS,
    '../console-shared-ts/src/*',
  ),
  '@seams-internal/console-server': path.resolve(PACKAGE_ROOT_ABS, 'src/index.ts'),
  '@seams-internal/console-server/*': path.resolve(PACKAGE_ROOT_ABS, 'src/*'),
  '@seams-internal/shared-ts': path.resolve(PACKAGE_ROOT_ABS, '../shared-ts/src/index.ts'),
  '@seams-internal/shared-ts/*': path.resolve(PACKAGE_ROOT_ABS, '../shared-ts/src/*'),
};

const preservedEntryFileNames = (chunk: { facadeModuleId?: string | null; name: string }) => {
  if (!chunk.facadeModuleId) return `${chunk.name}.js`;
  return preservedModuleOut({
    facadeModuleId: chunk.facadeModuleId,
    rootAbs: PACKAGE_SRC_ROOT_ABS,
  });
};

export default [
  {
    input: listSourceInputs(PACKAGE_SRC_ROOT_ABS),
    output: {
      dir: 'dist/esm',
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: PACKAGE_SRC_ROOT_ABS,
      entryFileNames: preservedEntryFileNames,
      chunkFileNames: preservedEntryFileNames,
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
];
