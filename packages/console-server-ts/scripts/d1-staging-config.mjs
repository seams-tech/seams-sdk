import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const repoRoot = path.resolve(packageRoot, '../..');
export const defaultD1StagingConsoleConfigPath = path.join(packageRoot, 'wrangler.d1-staging-console.toml');
export const defaultD1StagingRouterApiConfigPath = path.join(packageRoot, 'wrangler.d1-staging-router-api.toml');
export const d1StagingConfigManifestFlagFields = Object.freeze({
  '--console-config': 'consoleConfigPath',
  '--environment': 'environmentName',
  '--generated-at': 'generatedAtIso',
  '--manifest': 'manifestPath',
  '--mode': 'mode',
  '--router-api-config': 'routerApiConfigPath',
});
export const d1StagingConfigManifestArgDefaults = Object.freeze({
  consoleConfigPath: '',
  environmentName: 'staging',
  generatedAtIso: '',
  manifestPath: '',
  mode: 'dry-run',
  routerApiConfigPath: '',
});
export const d1StagingRouterApiManifestArgDefaults = Object.freeze({
  environmentName: 'staging',
  generatedAtIso: '',
  manifestPath: '',
  mode: 'dry-run',
  routerApiConfigPath: '',
});

export function readSelectedWranglerConfig(input) {
  if (!existsSync(input.configPath)) {
    throw new Error(`${input.label} Wrangler config does not exist: ${relativeToRepo(input.configPath)}`);
  }
  const rawSource = readFileSync(input.configPath, 'utf8');
  return selectEnvironmentSource(rawSource, input.environmentName);
}

export function selectEnvironmentSource(source, environmentName) {
  const envPrefix = `env.${environmentName}`;
  if (!source.includes(`[${envPrefix}`) && !source.includes(`[[${envPrefix}`)) return source;

  const lines = source.split(/\r?\n/);
  const selected = [];
  let capture = 'root';
  for (const rawLine of lines) {
    const header = parseHeader(rawLine);
    if (header) {
      capture = captureMode(header, envPrefix);
      if (capture === 'env' && header !== envPrefix) {
        selected.push(stripEnvPrefix(rawLine, envPrefix));
      }
      continue;
    }
    if (capture === 'root' && isRootScalarLine(rawLine)) selected.push(rawLine);
    if (capture === 'env') selected.push(rawLine);
  }
  return selected.join('\n');
}

export function rootBody(source) {
  const lines = source.split(/\r?\n/);
  const selected = [];
  for (const rawLine of lines) {
    const line = stripInlineComment(rawLine).trim();
    if (line.startsWith('[') && line.endsWith(']')) break;
    selected.push(rawLine);
  }
  return selected.join('\n');
}

export function tableBody(source, tableName) {
  const blocks = tableBodies(source, `[${tableName}]`);
  return blocks.length > 0 ? blocks[blocks.length - 1] || '' : '';
}

export function arrayTableBodies(source, tableName) {
  return tableBodies(source, `[[${tableName}]]`);
}

export function readString(source, key) {
  const pattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*["']([^"']+)["']`, 'gm');
  let value = '';
  let match = pattern.exec(source);
  while (match) {
    value = normalizeString(match[1]);
    match = pattern.exec(source);
  }
  return value;
}

export function readArray(source, key) {
  const pattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*\\[([^\\]]*)\\]`, 'ms');
  const match = pattern.exec(source);
  if (!match) return [];
  const values = [];
  const itemPattern = /["']([^"']+)["']/g;
  let item = itemPattern.exec(match[1] || '');
  while (item) {
    const value = normalizeString(item[1]);
    if (value) values.push(value);
    item = itemPattern.exec(match[1] || '');
  }
  return values;
}

export function commaList(input) {
  const values = [];
  for (const part of input.split(',')) {
    const value = normalizeString(part);
    if (value) values.push(value);
  }
  return values;
}

export function secretStoreBindingNameForSecretName(secretName) {
  return normalizeString(secretName).toUpperCase().replace(/[^A-Z0-9]+/g, '_');
}

export function valueLooksPlaceholder(value) {
  const normalized = normalizeString(value);
  if (!normalized) return true;
  if (normalized.includes('<') || normalized.includes('>')) return true;
  return normalized.includes('00000000-0000-0000-0000-000000000');
}

export function shellArg(input) {
  const value = String(input);
  if (/^[A-Za-z0-9_./:=@%+,$-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function sqlString(input) {
  return `'${String(input).replace(/'/g, "''")}'`;
}

export function sqlStringList(values) {
  const quoted = [];
  for (const value of values) quoted.push(sqlString(value));
  return quoted.join(', ');
}

export function normalizeString(input) {
  const out = String(input || '').trim();
  return out || '';
}

export function sha256String(source) {
  return createHash('sha256').update(source).digest('hex');
}

export function sha256File(filePath) {
  return sha256String(readFileSync(filePath));
}

export function writeJsonManifest(filePath, manifest) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(manifest, null, 2)}\n`);
  return filePath;
}

export function writeD1StagingManifest(
  options,
  defaultRoot,
  manifest,
  fileName = `${manifestStamp(options.generatedAtIso)}.json`,
) {
  const manifestPath = writeJsonManifest(
    resolveManifestOutputPath(options.manifestPath, path.join(defaultRoot, fileName)),
    manifest,
  );
  return {
    manifestPath,
    manifest,
  };
}

export function printD1StagingCliError(error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

export function requireNextArg(args, index, flag) {
  const value = args[index + 1] || '';
  if (!value) throw new Error(`${flag} requires a value`);
  return value;
}

export function parseFlagArgs(args, defaults, flagFields) {
  const options = { ...defaults };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] || '';
    if (arg === '--') continue;
    const config = flagFields[arg];
    if (typeof config === 'string') {
      options[config] = requireNextArg(args, index, arg);
      index += 1;
      continue;
    }
    if (config && config.kind === 'boolean') {
      options[config.field] = true;
      continue;
    }
    if (config && config.kind === 'string') {
      const value = requireNextArg(args, index, arg);
      options[config.field] = config.parse ? config.parse(value) : value;
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

export function resolvePackagePath(input, fallback) {
  const value = normalizeString(input);
  if (!value) return fallback;
  if (path.isAbsolute(value)) return value;
  return path.resolve(packageRoot, value);
}

export function resolveRequiredPackagePath(input, label) {
  const value = normalizeString(input);
  if (!value) throw new Error(`${label} is required`);
  return resolvePackagePath(value, value);
}

export function resolveManifestOutputPath(input, fallbackPath) {
  return resolvePackagePath(input, fallbackPath);
}

export function normalizeConsoleRouterApiD1StagingConfig(input, config = {}) {
  return {
    consoleConfigPath: resolvePackagePath(
      input.consoleConfigPath,
      config.consoleConfigPath || defaultD1StagingConsoleConfigPath,
    ),
    routerApiConfigPath: resolvePackagePath(
      input.routerApiConfigPath,
      config.routerApiConfigPath || defaultD1StagingRouterApiConfigPath,
    ),
    environmentName: normalizeString(input.environmentName) || 'staging',
  };
}

export function normalizeRouterApiD1StagingConfig(input, config = {}) {
  return {
    routerApiConfigPath: resolvePackagePath(
      input.routerApiConfigPath,
      config.routerApiConfigPath || defaultD1StagingRouterApiConfigPath,
    ),
    environmentName: normalizeString(input.environmentName) || 'staging',
  };
}

export function normalizeConsoleRouterApiD1StagingOptions(input, config) {
  return {
    ...normalizeConsoleRouterApiD1StagingConfig(input, config),
    generatedAtIso: normalizeGeneratedAtIso(input.generatedAtIso),
    manifestPath: normalizeString(input.manifestPath),
    mode: normalizeStagingMode(input.mode, config.modes, config.modeLabel),
    commandRunner: input.commandRunner || runShellCommand,
  };
}

export function relativeToPackage(inputPath) {
  const relativePath = path.relative(packageRoot, inputPath);
  return relativePath || '.';
}

export function wranglerPackageCommand(args, options = {}) {
  const command = `pnpm --dir packages/console-server-ts exec wrangler ${args}`;
  if (options.ci === true) return `CI=true ${command}`;
  return command;
}

export function wranglerCommand(args, configPath, options = {}) {
  return wranglerPackageCommand(`${args} --config ${shellArg(relativeToPackage(configPath))}`, options);
}

export function wranglerR2Command(args, configPath) {
  return wranglerCommand(`r2 ${args}`, configPath);
}

export function printStagingManifestResult(result, label, dryRunHeading, dryRunLines = []) {
  console.log(`${label}: ${relativeToRepo(result.manifestPath)}`);
  if (result.manifest.mode !== 'dry-run') return;
  console.log(dryRunHeading);
  for (const line of dryRunLines) console.log(line);
}

export function d1StagingCommandLines(commands) {
  const lines = [];
  for (const command of commands) {
    if (typeof command === 'string') {
      lines.push(command);
      continue;
    }
    lines.push(command.command);
  }
  return lines;
}

export function d1StagingHttpLines(endpoints) {
  const lines = [];
  for (const endpoint of endpoints) {
    const fixturePath = endpoint.fixture?.relativePath;
    const fixture = fixturePath ? ` fixture=${fixturePath}` : '';
    lines.push(`${endpoint.method} ${endpoint.url}${fixture}`);
  }
  return lines;
}

export async function executeD1StagingJsonEndpoint(input) {
  if (!input.fetchImpl) throw new Error('fetch is not available in this Node runtime');
  const startedAtIso = new Date().toISOString();
  const endpoint = input.endpoint;
  const request = d1StagingJsonRequest(input);
  const response = await fetchD1StagingJsonWithTimeout({
    fetchImpl: input.fetchImpl,
    request,
    timeoutMs: input.timeoutMs,
  });
  const body = await readD1StagingJsonBody(
    response,
    normalizeString(input.nonJsonBodyLabel) || 'D1 staging endpoint',
  );
  assertD1StagingJsonEndpointResponse({
    endpoint,
    status: response.status,
    body,
  });
  return {
    id: endpoint.id,
    url: endpoint.url,
    status: response.status,
    ok: true,
    startedAtIso,
    completedAtIso: new Date().toISOString(),
    body,
  };
}

export function isJsonRecord(input) {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

export function d1IntegrityCheckValues(input) {
  const values = [];
  collectD1IntegrityCheckValues(input, values);
  return values;
}

function collectD1IntegrityCheckValues(value, output) {
  if (Array.isArray(value)) {
    for (const item of value) collectD1IntegrityCheckValues(item, output);
    return;
  }
  if (!isJsonRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (d1IntegrityCheckKey(key) && typeof child === 'string') output.push(child);
    collectD1IntegrityCheckValues(child, output);
  }
}

function d1IntegrityCheckKey(input) {
  return String(input).toLowerCase().replace(/[^a-z0-9]+/g, '') === 'integritycheck';
}

export function d1TimeTravelBookmarkValue(input) {
  const values = [];
  collectD1TimeTravelBookmarkValues(input, values);
  return values[0] || '';
}

function collectD1TimeTravelBookmarkValues(value, output) {
  if (Array.isArray(value)) {
    for (const item of value) collectD1TimeTravelBookmarkValues(item, output);
    return;
  }
  if (!isJsonRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (d1TimeTravelBookmarkKey(key) && isUsableD1TimeTravelBookmarkValue(child)) {
      output.push(normalizeString(child));
    }
    collectD1TimeTravelBookmarkValues(child, output);
  }
}

function d1TimeTravelBookmarkKey(input) {
  return String(input).toLowerCase().replace(/[^a-z0-9]+/g, '') === 'bookmark';
}

function isUsableD1TimeTravelBookmarkValue(input) {
  const value = normalizeString(input);
  if (!value) return false;
  if (value.includes('<') || value.includes('>')) return false;
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/.test(value);
}

export function normalizeStagingOrigin(input, label, options = {}) {
  const value = normalizeString(input);
  if (!value) throw new Error(`${label} is required`);
  const allowHttpInDryRun = options.allowHttpInDryRun === true;
  let url;
  try {
    url = new URL(value);
  } catch {
    const protocolLabel = allowHttpInDryRun ? 'HTTP(S)' : 'HTTPS';
    throw new Error(`${label} must be an absolute ${protocolLabel} origin`);
  }
  if (allowHttpInDryRun) {
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new Error(`${label} must be an HTTP(S) origin`);
    }
    if (options.mode === 'remote' && url.protocol !== 'https:') {
      throw new Error(`${label} must use https in remote mode`);
    }
  } else if (url.protocol !== 'https:') {
    throw new Error(`${label} must use https`);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`${label} must not include a path, query, or fragment`);
  }
  return url.origin;
}

export function normalizeStagingTimeoutMs(input) {
  const value = normalizeString(input);
  if (!value) return 10_000;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 100 || parsed > 60_000) {
    throw new Error('--timeout-ms must be an integer between 100 and 60000');
  }
  return parsed;
}

function d1StagingJsonRequest(input) {
  if (input.request) return input.request;
  return {
    url: input.endpoint.url,
    method: input.endpoint.method,
    headers: {
      accept: 'application/json',
    },
  };
}

async function fetchD1StagingJsonWithTimeout(input) {
  const controller = new AbortController();
  const timeout = setTimeout(abortD1StagingJsonFetch, input.timeoutMs, controller);
  try {
    return await input.fetchImpl(input.request.url, {
      method: input.request.method,
      headers: input.request.headers,
      body: input.request.body,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function abortD1StagingJsonFetch(controller) {
  controller.abort();
}

async function readD1StagingJsonBody(response, label) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} returned non-JSON body: ${text.slice(0, 200)}`);
  }
}

function assertD1StagingJsonEndpointResponse(input) {
  if (input.status !== input.endpoint.expectedStatus) {
    throw new Error(
      `${input.endpoint.id} returned HTTP ${input.status}; expected ${input.endpoint.expectedStatus}`,
    );
  }
  if (!isJsonRecord(input.body)) {
    throw new Error(`${input.endpoint.id} returned a non-object JSON body`);
  }
  for (const entry of Object.entries(input.endpoint.expectedJson)) {
    assertD1StagingJsonField({
      endpointId: input.endpoint.id,
      fieldName: entry[0],
      expected: entry[1],
      body: input.body,
    });
  }
}

function assertD1StagingJsonField(input) {
  if (input.body[input.fieldName] === input.expected) return;
  throw new Error(
    `${input.endpointId} returned ${input.fieldName}=${JSON.stringify(
      input.body[input.fieldName],
    )}; expected ${JSON.stringify(input.expected)}`,
  );
}

export function manifestStamp(input) {
  return normalizeString(input).replace(/[:.]/g, '-');
}

export function compactIsoStamp(iso) {
  return iso.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

export function normalizeOptionalIso(input, label) {
  const value = normalizeString(input);
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`${label} must be an ISO timestamp`);
  return date.toISOString();
}

export function normalizeGeneratedAtIso(input) {
  return normalizeOptionalIso(input, '--generated-at') || new Date().toISOString();
}

export function normalizeStagingMode(input, modes, label) {
  const value = normalizeString(input) || 'dry-run';
  for (const mode of modes) {
    if (mode === value) return value;
  }
  throw new Error(`Unknown ${label} mode: ${value}`);
}

export function normalizeR2BucketName(input, label = '--r2-bucket') {
  const value = normalizeString(input);
  if (!value) throw new Error(`${label} is required`);
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)) {
    throw new Error(`${label} must be a bucket name, not a full object path`);
  }
  if (value.includes('..')) throw new Error(`${label} must not contain consecutive dots`);
  return value;
}

export function stagingReadinessFailureMessage(label, errors) {
  const lines = [`D1 staging ${label} requires readiness-clean configs:`];
  for (const error of errors) lines.push(`- ${error}`);
  return lines.join('\n');
}

export function isDirectInvocation(importMetaUrl) {
  const invoked = process.argv[1] ? path.resolve(process.argv[1]) : '';
  return invoked === fileURLToPath(importMetaUrl);
}

export function runShellCommand(command) {
  const result = spawnSync(command, {
    cwd: repoRoot,
    shell: true,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  return requireSuccessfulCommandResult(command, {
    command,
    status: result.status,
    stdout: normalizeString(result.stdout),
    stderr: normalizeString(result.stderr),
  });
}

export function runCommandArgs(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    input: options.input === null ? undefined : options.input,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  const renderedCommand = commandWithArgs(command, args);
  return requireSuccessfulCommandResult(renderedCommand, {
    command: renderedCommand,
    status: result.status,
    stdout: normalizeString(result.stdout),
    stderr: normalizeString(result.stderr),
  });
}

export function requireSuccessfulCommandResult(command, result) {
  if (result.status === 0) return result;
  throw new Error(commandFailureMessage(command, result));
}

export function commandFailureMessage(command, result) {
  const lines = [`Command failed: ${command}`];
  if (result.stdout) lines.push(`stdout:\n${normalizeString(result.stdout)}`);
  if (result.stderr) lines.push(`stderr:\n${normalizeString(result.stderr)}`);
  return lines.join('\n');
}

function commandWithArgs(command, args) {
  if (!args || args.length === 0) return command;
  return `${command} ${args.map(shellArg).join(' ')}`;
}

export function relativeToRepo(inputPath) {
  const relativePath = path.relative(repoRoot, inputPath);
  return relativePath || '.';
}

function tableBodies(source, headerText) {
  const bodies = [];
  const lines = source.split(/\r?\n/);
  let capture = false;
  let current = [];
  for (const rawLine of lines) {
    const line = stripInlineComment(rawLine).trim();
    const isHeader = line.startsWith('[') && line.endsWith(']');
    if (isHeader) {
      if (capture) bodies.push(current.join('\n'));
      capture = line === headerText;
      current = [];
      continue;
    }
    if (capture) current.push(rawLine);
  }
  if (capture) bodies.push(current.join('\n'));
  return bodies;
}

function parseHeader(rawLine) {
  const line = stripInlineComment(rawLine).trim();
  if (!line.startsWith('[') || !line.endsWith(']')) return '';
  if (line.startsWith('[[') && line.endsWith(']]')) return line.slice(2, -2).trim();
  return line.slice(1, -1).trim();
}

function captureMode(header, envPrefix) {
  if (header === envPrefix || header.startsWith(`${envPrefix}.`)) return 'env';
  return 'skip';
}

function stripEnvPrefix(rawLine, envPrefix) {
  return rawLine.replace(`[[${envPrefix}.`, '[[').replace(`[${envPrefix}.`, '[');
}

function isRootScalarLine(rawLine) {
  const line = stripInlineComment(rawLine).trim();
  return (
    line.startsWith('name =') ||
    line.startsWith('main =') ||
    line.startsWith('compatibility_date =') ||
    line.startsWith('compatibility_flags =')
  );
}

function stripInlineComment(input) {
  let quote = '';
  let escaped = false;
  let output = '';
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index] || '';
    if (quote) {
      output += char;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      output += char;
      continue;
    }
    if (char === '#') break;
    output += char;
  }
  return output;
}

export function escapeRegExp(input) {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
