#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(repoRoot, 'repository-split.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

function parseArguments(argv) {
  const options = {
    includeUntracked: false,
    output: '',
    sdkServerTarball: '',
    walletTarball: '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--output') {
      options.output = path.resolve(argv[index + 1] || '');
      index += 1;
      continue;
    }
    if (argument === '--include-untracked') {
      options.includeUntracked = true;
      continue;
    }
    if (argument === '--sdk-server-tarball') {
      options.sdkServerTarball = path.resolve(argv[index + 1] || '');
      index += 1;
      continue;
    }
    if (argument === '--wallet-tarball') {
      options.walletTarball = path.resolve(argv[index + 1] || '');
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!options.output) {
    throw new Error('Usage: extract-repositories.mjs --output <new-directory>');
  }
  return options;
}

function isPathWithin(relativePath, parentPath) {
  return relativePath === parentPath || relativePath.startsWith(`${parentPath}/`);
}

function isExcluded(relativePath, excludedPaths) {
  return excludedPaths.some((excludedPath) => isPathWithin(relativePath, excludedPath));
}

function existsInWorkingTree(relativePath) {
  return fs.existsSync(path.join(repoRoot, relativePath));
}

function listRepositoryFiles(sourcePaths, excludedPaths, includeUntracked) {
  const argumentsList = ['ls-files', '-z', '--cached'];
  if (includeUntracked) {
    argumentsList.push('--others', '--exclude-standard');
  }
  argumentsList.push('--', ...sourcePaths);
  const output = execFileSync('git', argumentsList, {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  return output
    .split('\0')
    .filter(Boolean)
    .filter(existsInWorkingTree)
    .filter((relativePath) => !isExcluded(relativePath, excludedPaths))
    .sort();
}

function copyRepositoryFiles(files, destination) {
  for (const relativePath of files) {
    const sourcePath = path.join(repoRoot, relativePath);
    const destinationPath = path.join(destination, relativePath);
    fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
    fs.copyFileSync(sourcePath, destinationPath);
    fs.chmodSync(destinationPath, fs.statSync(sourcePath).mode);
  }
}

function packageManagerVersion() {
  const rootPackage = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  return rootPackage.packageManager;
}

function publicRootPackage() {
  return {
    name: 'seams-wallet-sdk',
    private: true,
    type: 'module',
    packageManager: packageManagerVersion(),
    scripts: {
      'build:wasm': 'pnpm -C packages/wallet build:wasm',
      build:
        'pnpm run build:wasm && pnpm -C packages/wallet-server build && pnpm -C packages/wallet build:sdk',
      'type-check':
        'pnpm run build:wasm && pnpm -C packages/wallet-server type-check && pnpm -C packages/wallet type-check',
      'build:self-host':
        'pnpm -C examples/self-host-cloudflare-worker exec wrangler deploy --dry-run',
    },
  };
}

function privateRootPackage() {
  return {
    name: 'seams-cloud',
    private: true,
    type: 'module',
    packageManager: packageManagerVersion(),
    scripts: {
      build:
        'pnpm -C packages/console-server-ts build && pnpm -C apps/web-server build && pnpm -C apps/seams-site build',
      'type-check':
        'pnpm -C packages/console-shared-ts type-check && pnpm -C packages/console-server-ts type-check && pnpm -C apps/web-server build',
      'deploy:backend': 'node ./scripts/deploy-backend.mjs',
      'deploy:frontend': 'node ./scripts/deploy-frontend.mjs',
    },
  };
}

function workspaceManifest(workspacePackages) {
  const lines = ['packages:'];
  for (const workspacePackage of workspacePackages) {
    lines.push(`  - ${workspacePackage}`);
  }
  lines.push('nodeLinker: hoisted', 'verifyDepsBeforeRun: false', '');
  return lines.join('\n');
}

function repositoryReadme(repositoryName) {
  if (repositoryName === 'seams-wallet-sdk') {
    return [
      '# Seams Wallet SDK',
      '',
      'Open-source browser and server wallet SDKs, signer runtimes, Rust/Wasm crates,',
      'documentation, and the self-hosted Cloudflare Worker example.',
      '',
      'Published packages:',
      '',
      '- `@seams/wallet`',
      '- `@seams/wallet-server`',
      '',
      'The hosted dashboard, organization management, billing, email, and policy',
      'management services are maintained separately.',
      '',
    ].join('\n');
  }
  return [
    '# Seams Cloud',
    '',
    'Private hosted dashboard, console, policy, organization, billing, email, and',
    'deployment code. This repository consumes exact versions of the public Seams',
    'wallet SDK packages.',
    '',
  ].join('\n');
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function writeRootFiles(repositoryName, repository, destination) {
  const rootPackage =
    repositoryName === 'seams-wallet-sdk' ? publicRootPackage() : privateRootPackage();
  writeJson(path.join(destination, 'package.json'), rootPackage);
  fs.writeFileSync(
    path.join(destination, 'pnpm-workspace.yaml'),
    workspaceManifest(repository.workspacePackages),
  );
  fs.writeFileSync(path.join(destination, 'README.md'), repositoryReadme(repositoryName));
}

function publicDependencyValue(packageName, options) {
  if (packageName === '@seams/wallet' && options.walletTarball) {
    return `file:${options.walletTarball}`;
  }
  if (packageName === '@seams/wallet-server' && options.sdkServerTarball) {
    return `file:${options.sdkServerTarball}`;
  }
  return manifest.publicSdkVersion;
}

function pinPrivatePublicDependencies(destination, options) {
  const packageFiles = [
    'apps/seams-site/package.json',
    'apps/web-server/package.json',
    'packages/console-server-ts/package.json',
  ];
  for (const relativePath of packageFiles) {
    const packagePath = path.join(destination, relativePath);
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    for (const dependencyName of ['@seams/wallet', '@seams/wallet-server']) {
      if (!packageJson.dependencies?.[dependencyName]) continue;
      packageJson.dependencies[dependencyName] = publicDependencyValue(dependencyName, options);
    }
    writeJson(packagePath, packageJson);
  }
}

function assertDestinationIsNew(destination) {
  if (fs.existsSync(destination)) {
    throw new Error(`Refusing to overwrite existing extraction destination: ${destination}`);
  }
}

function materializeRepository(repositoryName, repository, outputRoot, options) {
  const destination = path.join(outputRoot, repositoryName);
  assertDestinationIsNew(destination);
  fs.mkdirSync(destination, { recursive: true });
  const sourcePaths = [...manifest.commonPaths, ...repository.sourcePaths];
  const files = listRepositoryFiles(sourcePaths, repository.excludePaths, options.includeUntracked);
  copyRepositoryFiles(files, destination);
  writeRootFiles(repositoryName, repository, destination);
  if (repositoryName === 'seams-cloud') {
    pinPrivatePublicDependencies(destination, options);
  }
  return { destination, fileCount: files.length };
}

const options = parseArguments(process.argv.slice(2));
if (fs.existsSync(options.output) && fs.readdirSync(options.output).length > 0) {
  throw new Error(`Extraction output must be empty: ${options.output}`);
}
fs.mkdirSync(options.output, { recursive: true });

for (const [repositoryName, repository] of Object.entries(manifest.repositories)) {
  const result = materializeRepository(repositoryName, repository, options.output, options);
  console.log(`[repository-split] ${repositoryName}: ${result.fileCount} files`);
  console.log(`[repository-split] path: ${result.destination}`);
}
