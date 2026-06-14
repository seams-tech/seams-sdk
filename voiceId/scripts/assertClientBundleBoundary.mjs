import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const roots = ['client', 'demo', 'shared'];
const checkedExtensions = new Set(['.ts', '.tsx', '.js', '.mjs', '.html']);
const forbiddenPatterns = [
  { name: 'server verifier import', pattern: /server\/src\/verifier|server\\src\\verifier/ },
  { name: 'Python verifier package', pattern: /voiceid_verifier/ },
  { name: 'SpeechBrain runtime', pattern: /\bspeechbrain\b/i },
  { name: 'PyTorch runtime', pattern: /\btorch\b|\btorchaudio\b/i },
  { name: 'ECAPA model id', pattern: /spkrec-ecapa|ecapa-voxceleb/i },
  { name: 'model checkpoint file', pattern: /\.(?:pt|pth|ckpt|onnx)\b/i },
  { name: 'Node child process', pattern: /node:child_process|child_process/ },
];

const failures = [];
for (const root of roots) {
  for (const filePath of await listFiles(root)) {
    if (!checkedExtensions.has(extensionOf(filePath))) {
      continue;
    }
    const content = await readFile(filePath, 'utf8');
    const lines = content.split('\n');
    for (const [lineIndex, line] of lines.entries()) {
      for (const forbidden of forbiddenPatterns) {
        if (forbidden.pattern.test(line)) {
          failures.push(`${filePath}:${lineIndex + 1}: ${forbidden.name}`);
        }
      }
    }
  }
}

if (failures.length > 0) {
  console.error('Client bundle boundary check failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log('Client bundle boundary check passed.');

async function listFiles(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listFiles(entryPath));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

function extensionOf(filePath) {
  const lastDot = filePath.lastIndexOf('.');
  return lastDot === -1 ? '' : filePath.slice(lastDot);
}
