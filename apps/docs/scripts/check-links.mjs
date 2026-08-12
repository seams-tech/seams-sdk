import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, join, normalize, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const docsRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const markdownLinkPattern = /(?<!!)\[[^\]]*\]\((?<target>[^)\s]+)(?:\s+["'][^"']*["'])?\)/g;
const controlCharacterPattern = new RegExp(String.raw`[\u0000-\u001F]`, 'g');

function collectMarkdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return collectMarkdownFiles(path);
    return entry.isFile() && entry.name.endsWith('.md') ? [path] : [];
  });
}

function isExternalTarget(target) {
  return /^(?:[a-z]+:|\/\/)/i.test(target);
}

function stripSuffix(target) {
  return decodeURIComponent(target.split(/[?#]/, 1)[0] ?? '');
}

function fragmentFromTarget(target) {
  const fragment = target.split('#', 2)[1];
  return fragment ? decodeURIComponent(fragment) : null;
}

function routeCandidates(sourceFile, target) {
  const cleanTarget = stripSuffix(target);
  const basePath = cleanTarget.startsWith('/')
    ? join(docsRoot, cleanTarget.slice(1))
    : resolve(dirname(sourceFile), cleanTarget);

  if (extname(basePath)) {
    const publicPath = cleanTarget.startsWith('/')
      ? join(docsRoot, 'public', cleanTarget.slice(1))
      : basePath;
    return [basePath, publicPath];
  }

  return [basePath, `${basePath}.md`, join(basePath, 'index.md')];
}

function resolveTargetFile(sourceFile, target) {
  if (isExternalTarget(target)) return null;

  // A fragment-only link addresses the page containing the link.
  if (target.startsWith('#')) return sourceFile;

  return routeCandidates(sourceFile, target).find(existsSync) ?? null;
}

function slugifyHeading(heading) {
  return heading
    .normalize('NFKD')
    .replace(/[\u0300-\u036F]/g, '')
    .replace(controlCharacterPattern, '')
    .replace(/[\s~`!@#$%^&*()\-_+=[\]{}|\\;:"'“”‘’<>,.?/]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/^(\d)/, '_$1')
    .toLowerCase();
}

function headingText(rawHeading) {
  return rawHeading
    .replace(/\s+#+\s*$/, '')
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/[`*_~]/g, '')
    .trim();
}

function headingSlugs(sourceFile) {
  const source = readFileSync(sourceFile, 'utf8');
  const used = new Map();
  const slugs = new Set();
  let fenceMarker = null;

  for (const line of source.split('\n')) {
    const fence = line.match(/^\s*(`{3,}|~{3,})/);
    if (fence) {
      const marker = fence[1][0];
      fenceMarker = fenceMarker === marker ? null : (fenceMarker ?? marker);
      continue;
    }
    if (fenceMarker) continue;

    const match = line.match(/^#{1,6}\s+(.+?)\s*$/);
    if (!match) continue;

    const baseSlug = slugifyHeading(headingText(match[1]));
    const count = used.get(baseSlug) ?? 0;
    used.set(baseSlug, count + 1);
    slugs.add(count === 0 ? baseSlug : `${baseSlug}-${count}`);
  }

  return slugs;
}

function targetFragmentExists(target, targetFile) {
  const fragment = fragmentFromTarget(target);
  if (!fragment) return true;
  if (!targetFile.endsWith('.md')) return true;
  return headingSlugs(targetFile).has(fragment);
}

function findBrokenLinks(sourceFile) {
  const source = readFileSync(sourceFile, 'utf8');
  return [...source.matchAll(markdownLinkPattern)]
    .map((match) => match.groups?.target)
    .filter((target) => {
      if (target === undefined || isExternalTarget(target)) return false;
      const targetFile = resolveTargetFile(sourceFile, target);
      return targetFile === null || !targetFragmentExists(target, targetFile);
    });
}

const failures = collectMarkdownFiles(docsRoot).flatMap((sourceFile) =>
  findBrokenLinks(sourceFile).map(
    (target) => `${normalize(relative(docsRoot, sourceFile))}: ${target}`,
  ),
);

if (failures.length > 0) {
  console.error(`Broken internal documentation links:\n${failures.join('\n')}`);
  process.exitCode = 1;
} else {
  console.log('All internal documentation links resolve.');
}
