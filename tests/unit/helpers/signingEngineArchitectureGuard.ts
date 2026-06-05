import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const signingEngineRoot = path.join(repoRoot, 'client/src/core/signingEngine');

const targetTopLevelFolders = [
  'assembly',
  'flows',
  'session',
  'stepUpConfirmation',
  'threshold',
  'chains',
  'uiConfirm',
  'workers',
  'nonce',
  'webauthnAuth',
  'useCases',
] as const;
const targetContractFolders = [
  'assembly',
  'flows',
  'chains',
  'stepUpConfirmation',
  'uiConfirm',
  'workers',
  'webauthnAuth',
  'useCases',
] as const;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listProductionTypeScriptFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith('.ts')) {
      files.push(path.relative(repoRoot, fullPath));
    }
  }
  return files;
}

function isTypeFixture(relativePath: string): boolean {
  return relativePath.endsWith('.typecheck.ts');
}

function extractImportSpecifiers(source: string): string[] {
  return Array.from(
    source.matchAll(/\bfrom\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
  )
    .map((match) => match[1] || match[2])
    .filter(Boolean);
}

function resolveSigningEngineImport(fromRelativePath: string, specifier: string): string | null {
  if (specifier === '@/web/SeamsWeb/signingSurface/BrowserSigningSurface') {
    return 'client/src/web/SeamsWeb/assembly/BrowserSigningSurface';
  }
  if (specifier.startsWith('@/core/signingEngine/')) {
    return `client/src/core/signingEngine/${specifier.slice('@/core/signingEngine/'.length)}`;
  }
  if (specifier === '@/core/signingEngine') {
    return 'client/src/core/signingEngine';
  }
  if (!specifier.startsWith('.')) return null;

  const resolved = path.resolve(path.join(repoRoot, path.dirname(fromRelativePath)), specifier);
  const relative = path.relative(repoRoot, resolved).replaceAll(path.sep, '/');
  if (relative === 'client/src/web/SeamsWeb/assembly/BrowserSigningSurface') return relative;
  if (!relative.startsWith('client/src/core/signingEngine')) return null;
  return relative;
}

function signingEngineTopLevel(relativePath: string): string | null {
  const prefix = 'client/src/core/signingEngine/';
  if (!relativePath.startsWith(prefix)) return null;
  const first = relativePath.slice(prefix.length).split('/')[0] || null;
  if (first === 'SigningEngine') return 'SigningEngine.ts';
  if (first === 'index') return 'index.ts';
  return first;
}

function sliceTypeAlias(source: string, name: string): string {
  const start = source.indexOf(`export type ${name}`);
  if (start < 0) throw new Error(`missing exported type ${name}`);
  const next = source.indexOf('\nexport type ', start + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

function stripNeverOptionalGuards(source: string): string {
  return source.replace(/\b\w+\?:\s*never;?/g, '');
}


export {
  repoRoot,
  signingEngineRoot,
  targetTopLevelFolders,
  targetContractFolders,
  readRepoSource,
  listProductionTypeScriptFiles,
  isTypeFixture,
  extractImportSpecifiers,
  resolveSigningEngineImport,
  signingEngineTopLevel,
  sliceTypeAlias,
  stripNeverOptionalGuards,
};
