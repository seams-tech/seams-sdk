import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const docsRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const typedFencePattern = /^```(?:ts|tsx|typescript|js|javascript)(?<metadata>.*)$/gm;
const allowedLabels = new Set([
  'Application pseudocode',
  'Generated data',
  'Import example',
  'Partial example',
  'Protocol sketch',
]);

function collectMarkdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return collectMarkdownFiles(path);
    return entry.isFile() && entry.name.endsWith('.md') ? [path] : [];
  });
}

function labelFromMetadata(metadata) {
  const match = metadata.match(/\[([^\]]+)\]/);
  return match?.[1] ?? null;
}

const failures = collectMarkdownFiles(docsRoot).flatMap((sourceFile) => {
  const source = readFileSync(sourceFile, 'utf8');
  return [...source.matchAll(typedFencePattern)].flatMap((match) => {
    const label = labelFromMetadata(match.groups?.metadata ?? '');
    if (label && allowedLabels.has(label)) return [];
    const line = source.slice(0, match.index).split('\n').length;
    return [`${relative(docsRoot, sourceFile)}:${line}: classify this typed code fence`];
  });
});

if (failures.length > 0) {
  console.error(
    `Unclassified TypeScript or JavaScript documentation fences:\n${failures.join('\n')}`,
  );
  process.exitCode = 1;
} else {
  console.log('All raw typed documentation fences are explicitly classified.');
}
