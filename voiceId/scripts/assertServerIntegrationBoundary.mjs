import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const checkedRoots = [
  '../packages/sdk-server-ts/src/core',
  '../packages/sdk-server-ts/src/router',
];

const forbidden = [
  /from\s+['"][^'"]*voiceId\/server\/src\/(store|verifier|transcript|VoiceIdService)/,
  /from\s+['"][^'"]*voiceId\/server\/src\/store\//,
  /from\s+['"][^'"]*voiceId\/server\/src\/verifier\//,
  /from\s+['"][^'"]*voiceId\/server\/src\/transcript\//,
  /from\s+['"][^'"]*voiceId\/server\/src\/VoiceIdService/,
  /from\s+['"]@seams\/voice-id\/server\/src\/(store|verifier|transcript|VoiceIdService)/,
];

const failures = [];
for (const root of checkedRoots) {
  for await (const filePath of walk(root)) {
    if (!filePath.endsWith('.ts')) {
      continue;
    }
    const content = await readFile(filePath, 'utf8');
    for (const [lineIndex, line] of content.split('\n').entries()) {
      if (forbidden.some((pattern) => pattern.test(line))) {
        failures.push(`${filePath}:${lineIndex + 1}: direct VoiceID concrete import`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error('Server integration boundary check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Server integration boundary check passed.');

async function* walk(root) {
  const { readdir } = await import('node:fs/promises');
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      yield* walk(path);
    } else if (entry.isFile()) {
      yield path;
    }
  }
}
