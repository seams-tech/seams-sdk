import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const typesRoot = path.join(serverRoot, 'dist/types');
const sharedTypesRoot = path.join(typesRoot, 'shared-ts/src');

function listDeclarationFiles(directory) {
  const declarations = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      declarations.push(...listDeclarationFiles(entryPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.d.ts')) {
      declarations.push(entryPath);
    }
  }
  return declarations;
}

function toModuleSpecifier(value) {
  const posixValue = value.split(path.sep).join('/');
  return posixValue.startsWith('.') ? posixValue : `./${posixValue}`;
}

function replaceSharedSpecifier(declarationPath, source) {
  const relativeSharedRoot = toModuleSpecifier(
    path.relative(path.dirname(declarationPath), sharedTypesRoot),
  );
  return source
    .replaceAll('@seams-internal/shared-ts/', `${relativeSharedRoot}/`)
    .replaceAll('@shared/', `${relativeSharedRoot}/`);
}

for (const declarationPath of listDeclarationFiles(typesRoot)) {
  const source = fs.readFileSync(declarationPath, 'utf8');
  const rewritten = replaceSharedSpecifier(declarationPath, source);
  if (rewritten !== source) {
    fs.writeFileSync(declarationPath, rewritten);
  }
}
