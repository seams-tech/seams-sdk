import { readFile } from 'node:fs/promises';
import { dirname, join, normalize } from 'node:path';

const entrypoint = 'server/src/cloudflare.ts';
const checkedExtensions = ['.ts', '.tsx', '.js', '.mjs'];
const forbiddenPatterns = [
  { name: 'Node builtin import', pattern: /from\s+['"]node:|import\s+['"]node:/ },
  { name: 'Node process global', pattern: /\bprocess\./ },
  { name: 'Node Buffer global', pattern: /\bBuffer\b/ },
  { name: 'child process runtime', pattern: /child_process|PythonSubprocessVoiceIdVerifierTransport/ },
  { name: 'filesystem runtime', pattern: /node:fs|from\s+['"]fs/ },
  { name: 'Node path runtime', pattern: /node:path|from\s+['"]path/ },
  { name: 'Node URL runtime', pattern: /node:url|from\s+['"]url/ },
  { name: 'dev server import', pattern: /devServer/ },
];

const visited = new Set();
const failures = [];
await visit(entrypoint);

if (failures.length > 0) {
  console.error('Worker boundary check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Worker boundary check passed.');

async function visit(filePath) {
  const normalizedPath = normalize(filePath);
  if (visited.has(normalizedPath)) {
    return;
  }
  visited.add(normalizedPath);

  const content = await readFile(normalizedPath, 'utf8');
  const lines = content.split('\n');
  for (const [lineIndex, line] of lines.entries()) {
    for (const forbidden of forbiddenPatterns) {
      if (forbidden.pattern.test(line)) {
        failures.push(`${normalizedPath}:${lineIndex + 1}: ${forbidden.name}`);
      }
    }
  }

  for (const importPath of relativeImports(content)) {
    await visit(resolveImport(normalizedPath, importPath));
  }
}

function relativeImports(content) {
  const imports = [];
  const importPattern = /(?:import|export)\s+(?:type\s+)?(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/g;
  for (const match of content.matchAll(importPattern)) {
    const importPath = match[1];
    if (importPath.startsWith('./') || importPath.startsWith('../')) {
      imports.push(importPath);
    }
  }
  return imports;
}

function resolveImport(fromFile, importPath) {
  if (checkedExtensions.some((extension) => importPath.endsWith(extension))) {
    return normalize(join(dirname(fromFile), importPath));
  }
  return normalize(join(dirname(fromFile), `${importPath}.ts`));
}
