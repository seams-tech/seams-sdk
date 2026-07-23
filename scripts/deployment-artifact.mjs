import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';

const artifactKinds = new Set([
  'gateway-wasm',
  'pages',
  'signer-iframe',
  'router',
  'deriver-a',
  'deriver-b',
  'signing-worker',
]);
const targets = new Set(['staging', 'production']);

const command = process.argv[2];
const options = parseOptions(process.argv.slice(3));

switch (command) {
  case 'create':
    await createManifest(options);
    break;
  case 'verify':
    await verifyManifest(options);
    break;
  default:
    throw new Error(
      'usage: deployment-artifact.mjs <create|verify> --kind <kind> --target <target> --sha <sha> --root <directory> --manifest <file> [--identity-json <json>] [--metadata-json <json>]',
    );
}

async function createManifest(rawOptions) {
  const input = parseCommonOptions(rawOptions);
  const root = await resolveExistingDirectory(input.root);
  const files = await collectFiles(root);
  if (files.length === 0) {
    throw new Error(`deployment artifact ${input.kind} contains no files`);
  }
  const identity = parseIdentity(rawOptions.get('identity-json'));
  const metadata = parseJsonObject(rawOptions.get('metadata-json'), 'artifact metadata');
  const manifest = {
    schemaVersion: 1,
    kind: input.kind,
    target: input.target,
    sourceSha: input.sourceSha,
    createdAt: new Date().toISOString(),
    contentDigestSha256: digestFileRecords(files),
    identity,
    metadata,
    files,
  };
  await mkdir(dirname(input.manifest), { recursive: true });
  await writeFile(input.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`${input.kind} artifact ${manifest.contentDigestSha256}`);
}

async function verifyManifest(rawOptions) {
  const input = parseCommonOptions(rawOptions);
  const root = await resolveExistingDirectory(input.root);
  const manifest = parseManifest(JSON.parse(await readFile(input.manifest, 'utf8')));
  if (manifest.kind !== input.kind) {
    throw new Error(`artifact kind mismatch: expected ${input.kind}, received ${manifest.kind}`);
  }
  if (manifest.target !== input.target) {
    throw new Error(
      `artifact target mismatch: expected ${input.target}, received ${manifest.target}`,
    );
  }
  if (manifest.sourceSha !== input.sourceSha) {
    throw new Error(
      `artifact source SHA mismatch: expected ${input.sourceSha}, received ${manifest.sourceSha}`,
    );
  }
  const expectedIdentity = parseIdentity(rawOptions.get('identity-json'));
  if (stableJson(manifest.identity) !== stableJson(expectedIdentity)) {
    throw new Error('artifact public deployment identity mismatch');
  }
  const files = await collectFiles(root);
  if (stableJson(files) !== stableJson(manifest.files)) {
    throw new Error('artifact file inventory or digest mismatch');
  }
  const contentDigestSha256 = digestFileRecords(files);
  if (contentDigestSha256 !== manifest.contentDigestSha256) {
    throw new Error('artifact content digest mismatch');
  }
  console.log(`${input.kind} artifact verified ${contentDigestSha256}`);
}

function parseCommonOptions(rawOptions) {
  const kind = requiredOption(rawOptions, 'kind');
  const target = requiredOption(rawOptions, 'target');
  const sourceSha = requiredOption(rawOptions, 'sha');
  const root = resolve(requiredOption(rawOptions, 'root'));
  const manifest = resolve(requiredOption(rawOptions, 'manifest'));
  if (!artifactKinds.has(kind)) {
    throw new Error(`unsupported deployment artifact kind: ${kind}`);
  }
  if (!targets.has(target)) {
    throw new Error(`unsupported deployment target: ${target}`);
  }
  if (!/^[0-9a-f]{7,64}$/u.test(sourceSha)) {
    throw new Error('deployment artifact SHA must be lowercase hexadecimal');
  }
  return { kind, target, sourceSha, root, manifest };
}

function parseManifest(value) {
  if (!isRecord(value) || value.schemaVersion !== 1) {
    throw new Error('invalid deployment artifact manifest');
  }
  if (
    typeof value.kind !== 'string' ||
    typeof value.target !== 'string' ||
    typeof value.sourceSha !== 'string' ||
    typeof value.createdAt !== 'string' ||
    typeof value.contentDigestSha256 !== 'string' ||
    !isRecord(value.identity) ||
    !isRecord(value.metadata) ||
    !Array.isArray(value.files)
  ) {
    throw new Error('deployment artifact manifest fields are invalid');
  }
  const files = value.files.map(parseFileRecord);
  return {
    schemaVersion: 1,
    kind: value.kind,
    target: value.target,
    sourceSha: value.sourceSha,
    createdAt: value.createdAt,
    contentDigestSha256: value.contentDigestSha256,
    identity: value.identity,
    metadata: value.metadata,
    files,
  };
}

function parseFileRecord(value) {
  if (
    !isRecord(value) ||
    typeof value.path !== 'string' ||
    typeof value.sha256 !== 'string' ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0
  ) {
    throw new Error('deployment artifact file record is invalid');
  }
  return { path: value.path, sha256: value.sha256, size: value.size };
}

async function collectFiles(root) {
  const paths = await walk(root, root);
  const records = await Promise.all(
    paths.map(async (path) => {
      const bytes = await readFile(path);
      return {
        path: relative(root, path).split(sep).join('/'),
        sha256: createHash('sha256').update(bytes).digest('hex'),
        size: bytes.byteLength,
      };
    }),
  );
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

async function walk(root, current) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.name === '.DS_Store') {
      continue;
    }
    const path = resolve(current, entry.name);
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      throw new Error(
        `deployment artifacts cannot contain symbolic links: ${relative(root, path)}`,
      );
    }
    if (stats.isDirectory()) {
      files.push(...(await walk(root, path)));
      continue;
    }
    if (!stats.isFile()) {
      throw new Error(
        `deployment artifacts can contain regular files only: ${relative(root, path)}`,
      );
    }
    files.push(path);
  }
  return files;
}

async function resolveExistingDirectory(path) {
  const canonical = await realpath(path);
  const stats = await lstat(canonical);
  if (!stats.isDirectory()) {
    throw new Error(`artifact root is not a directory: ${path}`);
  }
  return canonical;
}

function digestFileRecords(files) {
  const hash = createHash('sha256');
  for (const file of files) {
    hash.update(`${file.sha256}  ${file.size}  ${file.path}\n`);
  }
  return hash.digest('hex');
}

function parseIdentity(value) {
  return parseJsonObject(value, 'artifact identity');
}

function parseJsonObject(value, label) {
  const object = value === undefined ? {} : JSON.parse(value);
  if (!isRecord(object)) {
    throw new Error(`${label} JSON must be an object`);
  }
  return object;
}

function stableJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortJson(child)]),
    );
  }
  return value;
}

function parseOptions(args) {
  const parsed = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!option?.startsWith('--') || value === undefined) {
      throw new Error(`invalid deployment artifact argument: ${option ?? '<missing>'}`);
    }
    parsed.set(option.slice(2), value);
  }
  return parsed;
}

function requiredOption(parsed, name) {
  const value = parsed.get(name);
  if (!value) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
