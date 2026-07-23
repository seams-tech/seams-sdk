import {
  accessSync,
  closeSync,
  copyFileSync,
  constants,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIR, '../../..');
const CORE_MANIFEST = join(REPOSITORY_ROOT, 'crates/ed25519-yao/Cargo.toml');
const WORKER_MANIFEST = join(REPOSITORY_ROOT, 'crates/ed25519-yao-cloudflare-bench/Cargo.toml');
const CORE_SOURCE = join(REPOSITORY_ROOT, 'crates/ed25519-yao/src/passive.rs');
const OT_SOURCE = join(REPOSITORY_ROOT, 'crates/ed25519-yao/src/passive/ot.rs');
const WASM_TARGET = 'wasm32-unknown-unknown';
const WORKER_WASM = 'ed25519_yao_cloudflare_bench.wasm';
const SENDER_ACCEPT_SYMBOL = /SenderAwaitExtension.*6accept/;
const SECRET_BIT_PREFIX =
  String.raw`i32\.load8_u[\s\S]{0,500}?i32\.shr_u[\s\S]{0,200}?` +
  String.raw`i32\.const\s+1[\s\S]{0,100}?i32\.and`;
const SECRET_BIT_BRANCH = new RegExp(
  `${SECRET_BIT_PREFIX}[\\s\\S]{0,120}?i32\\.eqz[\\s\\S]{0,100}?br_if`,
  'g',
);
const SECRET_BIT_MASK = new RegExp(
  `${SECRET_BIT_PREFIX}[\\s\\S]{0,120}?call[\\s\\S]{0,80}?i32\\.sub`,
  'g',
);

function fail(message) {
  throw new Error(message);
}

function isExecutable(path) {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function executableCandidates(name) {
  const pathEntries = (process.env.PATH ?? '').split(':').filter(Boolean);
  const candidates = [];
  for (const entry of pathEntries) {
    candidates.push(join(entry, name));
  }
  return candidates;
}

function resolveLlvmObjdump() {
  const configured = process.env.LLVM_OBJDUMP;
  const candidates = [];
  if (configured !== undefined && configured.length > 0) {
    candidates.push(configured);
  }
  candidates.push(...executableCandidates('llvm-objdump'));
  candidates.push('/opt/homebrew/opt/llvm/bin/llvm-objdump');
  const resolved = candidates.find(isExecutable);
  if (resolved === undefined) {
    fail(
      'llvm-objdump is required for the generated-WASM constant-time gate; install LLVM or set LLVM_OBJDUMP to its absolute path',
    );
  }
  return resolved;
}

function runInherited(command, args, environment = {}) {
  const result = spawnSync(command, args, {
    cwd: REPOSITORY_ROOT,
    env: { ...process.env, ...environment },
    stdio: 'inherit',
  });
  if (result.error !== undefined) {
    fail(`failed to run ${command}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`${command} exited with status ${String(result.status)}`);
  }
}

function runCaptured(command, args) {
  const result = spawnSync(command, args, {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error !== undefined) {
    fail(`failed to run ${command}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`${command} exited with status ${String(result.status)}: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

function runCapturedThroughFile(command, args) {
  const temporary = mkdtempSync(join(tmpdir(), 'ed25519-yao-command-output-'));
  const stdoutPath = join(temporary, 'stdout.txt');
  const stdout = openSync(stdoutPath, 'w', 0o600);
  try {
    let result;
    try {
      result = spawnSync(command, args, {
        cwd: REPOSITORY_ROOT,
        encoding: 'utf8',
        stdio: ['ignore', stdout, 'pipe'],
      });
    } finally {
      closeSync(stdout);
    }
    if (result.error !== undefined) {
      fail(`failed to run ${command}: ${result.error.message}`);
    }
    if (result.status !== 0) {
      fail(`${command} exited with status ${String(result.status)}: ${result.stderr.trim()}`);
    }
    return readFileSync(stdoutPath, 'utf8');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function findFiles(directory, predicate) {
  const matches = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      matches.push(...findFiles(path, predicate));
    } else if (entry.isFile() && predicate(path)) {
      matches.push(path);
    }
  }
  return matches;
}

function requireSingleFile(directory, predicate, label) {
  const matches = findFiles(directory, predicate);
  if (matches.length !== 1) {
    fail(`expected exactly one ${label} under ${directory}, found ${matches.length}`);
  }
  return matches[0];
}

function isEd25519YaoAssembly(path) {
  return /ed25519_yao-[^/]+\.s$/u.test(path);
}

function requireUniqueSourceLine(path, fragment) {
  const lines = readFileSync(path, 'utf8').split(/\r?\n/u);
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].includes(fragment)) {
      matches.push(index + 1);
    }
  }
  if (matches.length !== 1) {
    fail(`expected one '${fragment}' source line in ${path}, found ${matches.length}`);
  }
  return matches[0];
}

function normalizedDerivedTraits(deriveBody) {
  const normalized = [];
  for (const traitName of deriveBody.split(',')) {
    normalized.push(traitName.trim());
  }
  return normalized;
}

function assertSecretBitWrappersCannotUseDebug() {
  const source = readFileSync(CORE_SOURCE, 'utf8');
  const secretBitWrappers = ['WireValue', 'ChoiceBit'];
  for (const wrapper of secretBitWrappers) {
    const declaration = new RegExp(
      String.raw`#\[derive\(([^)]*)\)\][\s\S]{0,120}?struct\s+${wrapper}\b`,
      'u',
    ).exec(source);
    if (declaration === null) {
      fail(`constant-time source gate cannot find the ${wrapper} declaration`);
    }
    const derivedTraits = normalizedDerivedTraits(declaration[1]);
    if (derivedTraits.includes('Debug')) {
      fail(`${wrapper} contains secret bits and must not implement Debug`);
    }
  }
}

function assemblyFileId(assemblyLines, sourceSuffix) {
  const filePattern = /^\s*\.file\s+(\d+)\s+.*"([^"]+)"\s*$/u;
  const matches = [];
  for (const line of assemblyLines) {
    const match = line.match(filePattern);
    if (match !== null && match[2].endsWith(sourceSuffix)) {
      matches.push(Number(match[1]));
    }
  }
  const unique = [...new Set(matches)];
  if (unique.length !== 1) {
    fail(`expected one assembly file id for ${sourceSuffix}, found ${unique.length}`);
  }
  return unique[0];
}

function instructionMnemonic(line) {
  const trimmed = line.trim();
  if (
    trimmed.length === 0 ||
    trimmed.startsWith('.') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith(';') ||
    trimmed.endsWith(':')
  ) {
    return undefined;
  }
  return trimmed.match(/^([A-Za-z][A-Za-z0-9.]*)\b/u)?.[1]?.toLowerCase();
}

function isConditionalBranch(mnemonic) {
  if (['cbz', 'cbnz', 'tbz', 'tbnz'].includes(mnemonic)) {
    return true;
  }
  if (mnemonic.startsWith('b.')) {
    return true;
  }
  if (mnemonic.startsWith('j') && mnemonic !== 'jmp') {
    return true;
  }
  return ['beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu'].includes(mnemonic);
}

function sensitiveLineInstructions(assemblyLines, fileId, sourceLine) {
  const locationPattern = /^\s*\.loc\s+(\d+)\s+(\d+)\s+/u;
  let sensitive = false;
  const instructions = [];
  for (const line of assemblyLines) {
    const location = line.match(locationPattern);
    if (location !== null) {
      sensitive = Number(location[1]) === fileId && Number(location[2]) === sourceLine;
      continue;
    }
    if (sensitive) {
      const mnemonic = instructionMnemonic(line);
      if (mnemonic !== undefined) {
        instructions.push({ line: line.trim(), mnemonic });
      }
    }
  }
  return instructions;
}

function assertNativeSensitiveLine(assemblyLines, sourceSuffix, sourceLine, label) {
  const fileId = assemblyFileId(assemblyLines, sourceSuffix);
  const instructions = sensitiveLineInstructions(assemblyLines, fileId, sourceLine);
  if (instructions.length === 0) {
    fail(`${label} produced no line-mapped optimized host instructions`);
  }
  const branches = [];
  for (const instruction of instructions) {
    if (isConditionalBranch(instruction.mnemonic)) {
      branches.push(instruction);
    }
  }
  if (branches.length > 0) {
    const branchLines = [];
    for (const branch of branches) {
      branchLines.push(branch.line);
    }
    fail(
      `${label} contains conditional branches in optimized host code: ${branchLines.join(', ')}`,
    );
  }
  let xorFound = false;
  for (const instruction of instructions) {
    if (instruction.mnemonic.includes('xor') || instruction.mnemonic.startsWith('eor')) {
      xorFound = true;
      break;
    }
  }
  if (!xorFound) {
    fail(`${label} line mapping contains no XOR instruction; the regression gate lost coverage`);
  }
}

function buildAndInspectHost(targetDirectory) {
  runInherited(
    'cargo',
    [
      'rustc',
      '--locked',
      '--manifest-path',
      CORE_MANIFEST,
      '--release',
      '--lib',
      '--features',
      'phase9-role-benchmark',
      '--',
      '-Cdebuginfo=2',
      '--emit=asm',
    ],
    { CARGO_TARGET_DIR: targetDirectory },
  );
  const assembly = requireSingleFile(
    join(targetDirectory, 'release/deps'),
    isEd25519YaoAssembly,
    'Ed25519 Yao host assembly file',
  );
  const assemblyLines = readFileSync(assembly, 'utf8').split(/\r?\n/u);
  const wireLine = requireUniqueSourceLine(CORE_SOURCE, 'self.0[index] ^= u8::conditional_select');
  const otLine = requireUniqueSourceLine(OT_SOURCE, 'target[index] ^= u8::conditional_select');
  assertNativeSensitiveLine(assemblyLines, 'src/passive.rs', wireLine, 'WireLabel conditional XOR');
  assertNativeSensitiveLine(assemblyLines, 'src/passive/ot.rs', otLine, 'IKNP row conditional XOR');
}

function buildWorker(targetDirectory, feature) {
  runInherited(
    'cargo',
    [
      'build',
      '--locked',
      '--manifest-path',
      WORKER_MANIFEST,
      '--target',
      WASM_TARGET,
      '--release',
      '--no-default-features',
      '--features',
      feature,
    ],
    { CARGO_TARGET_DIR: targetDirectory },
  );
  const wasm = join(targetDirectory, WASM_TARGET, 'release', WORKER_WASM);
  accessSync(wasm, constants.R_OK);
  return wasm;
}

function symbolNames(symbolTable, pattern) {
  const matches = [];
  for (const line of symbolTable.split(/\r?\n/u)) {
    const symbol = line.trim().split(/\s+/u).at(-1);
    if (symbol !== undefined && pattern.test(symbol)) {
      matches.push(symbol);
    }
  }
  return matches;
}

function countMatches(text, pattern) {
  pattern.lastIndex = 0;
  return [...text.matchAll(pattern)].length;
}

function qualifyWasmPatterns() {
  const vulnerable = [
    'i32.load8_u 0',
    'local.get 1',
    'i32.shr_u',
    'i32.const 1',
    'i32.and',
    'i32.eqz',
    'br_if 0',
  ].join('\n');
  const safe = [
    'i32.load8_u 0',
    'local.get 1',
    'i32.shr_u',
    'i32.const 1',
    'i32.and',
    'call 2713',
    'i32.sub',
    'local.get 2',
    'i32.and',
    'i32.xor',
  ].join('\n');
  if (countMatches(vulnerable, SECRET_BIT_BRANCH) !== 1) {
    fail('the WASM regression matcher did not reject its vulnerable qualification fixture');
  }
  if (countMatches(safe, SECRET_BIT_BRANCH) !== 0) {
    fail('the WASM regression matcher rejected its branchless qualification fixture');
  }
  if (countMatches(safe, SECRET_BIT_MASK) !== 1) {
    fail('the WASM mask matcher did not accept its branchless qualification fixture');
  }
}

function assertNoSecretBitBranch(disassembly, label) {
  const count = countMatches(disassembly, SECRET_BIT_BRANCH);
  if (count !== 0) {
    fail(`${label} contains ${count} load/shift/secret-bit branch sequence(s)`);
  }
}

function inspectWorkerWasm(llvmObjdump, wasm, feature, requireSender) {
  const symbolTable = runCaptured(llvmObjdump, ['-t', wasm]);
  const disassembly = runCapturedThroughFile(llvmObjdump, ['-d', wasm]);
  assertNoSecretBitBranch(disassembly, `${feature} Worker WASM`);

  const senderSymbols = symbolNames(symbolTable, SENDER_ACCEPT_SYMBOL);
  if (requireSender && senderSymbols.length !== 1) {
    fail(`${feature} Worker WASM must contain exactly one IKNP sender accept symbol`);
  }
  if (!requireSender && senderSymbols.length !== 0) {
    fail(`${feature} Worker WASM unexpectedly contains an IKNP sender accept symbol`);
  }
  if (senderSymbols.length === 1) {
    const sender = runCaptured(llvmObjdump, [`--disassemble-symbols=${senderSymbols[0]}`, wasm]);
    assertNoSecretBitBranch(sender, `${feature} IKNP sender`);
    const maskCount = countMatches(sender, SECRET_BIT_MASK);
    if (maskCount !== 1) {
      fail(
        `${feature} IKNP sender must contain exactly one optimizer-resistant secret-bit mask sequence, found ${maskCount}`,
      );
    }
  }
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function inspectWorkerArtifacts(aWasm, bWasm) {
  qualifyWasmPatterns();
  const llvmObjdump = resolveLlvmObjdump();
  const before = Object.freeze({
    a: sha256File(aWasm),
    b: sha256File(bWasm),
  });
  inspectWorkerWasm(llvmObjdump, aWasm, 'deriver-a', true);
  inspectWorkerWasm(llvmObjdump, bWasm, 'deriver-b', false);
  const after = Object.freeze({
    a: sha256File(aWasm),
    b: sha256File(bWasm),
  });
  if (before.a !== after.a || before.b !== after.b) {
    fail('Worker WASM changed while constant-time inspection was running');
  }
  return Object.freeze({
    schema: 'ed25519_yao_worker_constant_time_codegen_v1',
    inspector: 'llvm-objdump-secret-bit-branch-gate-v1',
    result: 'pass',
    roles: Object.freeze({
      a: Object.freeze({ wasm_sha256: before.a }),
      b: Object.freeze({ wasm_sha256: before.b }),
    }),
  });
}

function main() {
  if (!['arm64', 'x64'].includes(process.arch)) {
    fail(`unsupported host architecture '${process.arch}'; expected arm64 or x64`);
  }
  const temporary = mkdtempSync(join(tmpdir(), 'ed25519-yao-ct-codegen-'));
  try {
    assertSecretBitWrappersCannotUseDebug();
    const cargoTarget = join(temporary, 'cargo-target');
    buildAndInspectHost(cargoTarget);
    const deriverA = buildWorker(cargoTarget, 'deriver-a-cross-account');
    const deriverACopy = join(temporary, 'deriver-a.wasm');
    copyFileSync(deriverA, deriverACopy);
    const deriverB = buildWorker(cargoTarget, 'deriver-b-cross-account');
    inspectWorkerArtifacts(deriverACopy, deriverB);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  process.stdout.write(
    'constant-time codegen gate passed: optimized host and Deriver A/B Worker WASM retain branchless IKNP and WireLabel selection\n',
  );
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`constant-time codegen gate failed: ${message}\n`);
    process.exitCode = 1;
  }
}
