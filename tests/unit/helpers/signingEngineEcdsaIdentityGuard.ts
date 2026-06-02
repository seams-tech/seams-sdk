import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

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

function listSourceFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) {
    return /\.(ts|tsx|rs)$/.test(relativePath) ? [relativePath] : [];
  }
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) return listSourceFiles(entryPath);
    return /\.(ts|tsx|rs)$/.test(entry.name) ? [entryPath] : [];
  });
}

function findCallObjects(source: string, callName: string): string[] {
  const objects: string[] = [];
  let searchFrom = 0;
  const needle = `${callName}({`;

  while (true) {
    const callStart = source.indexOf(needle, searchFrom);
    if (callStart < 0) break;

    let depth = 0;
    let end = -1;
    for (let i = callStart + callName.length + 1; i < source.length; i += 1) {
      const char = source[i];
      if (char === '{') depth += 1;
      if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }

    if (end < 0) break;
    objects.push(source.slice(callStart, end));
    searchFrom = end;
  }

  return objects;
}

function findLoggerCalls(source: string): string[] {
  const calls: string[] = [];
  const pattern = /(?:^|[^\w])(?:this|ctx|options|input)?\.?logger\.(?:info|warn|error|debug)\(/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const openParenIndex = source.indexOf('(', match.index);
    if (openParenIndex < 0) continue;
    let depth = 0;
    let end = -1;
    for (let i = openParenIndex; i < source.length; i += 1) {
      const char = source[i];
      if (char === '(') depth += 1;
      if (char === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) break;
    calls.push(source.slice(match.index, end));
    pattern.lastIndex = end;
  }
  return calls;
}

function lineNumberForIndex(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
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

function findTypeDeclaration(source: string, name: string): string {
  const declarationPattern = new RegExp(`\\b(?:export\\s+)?(type|interface)\\s+${name}\\b`);
  const match = declarationPattern.exec(source);
  if (!match) throw new Error(`Missing declaration ${name}`);

  if (match[1] === 'interface') {
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) throw new Error(`Could not parse interface ${name}`);
    return block;
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
      return source.slice(match.index, i + 1);
    }
  }

  throw new Error(`Could not parse type ${name}`);
}

function findObjectBlockAfter(source: string, needle: string): string {
  const start = source.indexOf(needle);
  if (start < 0) throw new Error(`Missing object block after ${needle}`);
  const openBraceIndex = source.indexOf('{', start);
  const block = findBalancedBlock(source, openBraceIndex);
  if (!block) throw new Error(`Could not parse object block after ${needle}`);
  return block;
}

function findChainedMethodCallObjects(
  source: string,
  methodNames: string[],
  receiverPattern = '\\b\\w+',
): Array<{ methodName: string; line: number; block: string }> {
  const calls: Array<{ methodName: string; line: number; block: string }> = [];
  const pattern = new RegExp(
    `(?:${receiverPattern})\\s*\\.(?:${methodNames.join('|')})\\s*\\(\\s*{`,
    'g',
  );
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const dottedNames = [...match[0].matchAll(/\.(\w+)/g)];
    const methodName = dottedNames[dottedNames.length - 1]?.[1];
    if (!methodName) continue;
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) continue;
    calls.push({
      methodName,
      line: lineNumberForIndex(source, match.index),
      block,
    });
    pattern.lastIndex = openBraceIndex + block.length;
  }
  return calls;
}

function findMethodDeclarationAndBody(source: string, methodName: string): string | null {
  const methodStart = source.indexOf(`async ${methodName}(`);
  if (methodStart < 0) return null;
  const openParenIndex = source.indexOf('(', methodStart);
  let parenDepth = 0;
  let closeParenIndex = -1;
  for (let i = openParenIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '(') parenDepth += 1;
    if (char === ')') {
      parenDepth -= 1;
      if (parenDepth === 0) {
        closeParenIndex = i;
        break;
      }
    }
  }
  if (closeParenIndex < 0) return null;
  const bodyOpenIndex = source.indexOf('{', closeParenIndex);
  const bodyBlock = findBalancedBlock(source, bodyOpenIndex);
  return bodyBlock ? source.slice(methodStart, bodyOpenIndex) + bodyBlock : null;
}

function expectRequiredFields(block: string, fields: string[], context: string): string[] {
  return fields
    .filter((field) => !new RegExp(`\\b${field}\\s*(?::|,)`).test(block))
    .map((field) => `${context} is missing required ${field}`);
}

function expectDeclaredFields(block: string, fields: string[], context: string): string[] {
  return fields
    .filter((field) => !new RegExp(`\\b${field}\\??\\s*:`).test(block))
    .map((field) => `${context} does not declare ${field}`);
}

function expectAnyDeclaredField(block: string, fields: string[], context: string): string[] {
  return fields.some((field) => new RegExp(`\\b${field}\\??\\s*:`).test(block))
    ? []
    : [`${context} does not declare any of: ${fields.join(', ')}`];
}

function expectNoField(block: string, field: string, context: string): string[] {
  const searchable = block.replace(new RegExp(`\\b${field}\\?:\\s*never\\b`, 'g'), '');
  return new RegExp(`\\b${field}\\s*(?::|\\?:|,)`).test(searchable)
    ? [`${context} exposes ${field}`]
    : [];
}

function expectNoNearAccountId(
  block: string,
  context: string,
  options: { allowNeverTripwire?: boolean } = {},
): string[] {
  const searchable = options.allowNeverTripwire
    ? block.replace(/\bnearAccountId\?:\s*never\b/g, '')
    : block;
  return /\bnearAccountId\b/.test(searchable) ? [`${context} exposes nearAccountId`] : [];
}


export {
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
  expectNoNearAccountId,
};
