import fs from 'node:fs';
import path from 'node:path';

function toPosixPath(filePath) {
  return filePath.split(path.sep).join('/');
}

function collectRegexLineMatches(source, regex, patternLabel) {
  const lines = source.split(/\r?\n/);
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!regex.test(line)) continue;
    matches.push({
      line: index + 1,
      pattern: patternLabel,
      text: line.trim(),
    });
  }
  return matches;
}

export function findStableExperimentalExportBoundaryViolations(repoRoot) {
  const rootIndexPath = path.join(repoRoot, 'packages/sdk-web/src/index.ts');
  const experimentalDirPath = path.join(repoRoot, 'packages/sdk-web/src/experimental');
  const sdkPackagePath = path.join(repoRoot, 'packages/sdk-web/package.json');

  if (!fs.existsSync(rootIndexPath)) {
    return {
      checks: [],
      error: `[check-stable-experimental-export-boundaries] missing file: ${rootIndexPath}`,
    };
  }
  if (!fs.existsSync(sdkPackagePath)) {
    return {
      checks: [],
      error: `[check-stable-experimental-export-boundaries] missing file: ${sdkPackagePath}`,
    };
  }

  const rootSource = fs.readFileSync(rootIndexPath, 'utf8');
  const sdkPackage = JSON.parse(fs.readFileSync(sdkPackagePath, 'utf8'));

  const rootForbiddenMatches = [
    ...collectRegexLineMatches(
      rootSource,
      /^\s*export\s+.*from\s+['"]\.\/core\/signingEngine\//,
      "export from './core/signingEngine/*' (internal)",
    ),
    ...collectRegexLineMatches(
      rootSource,
      /^\s*export\s+.*from\s+['"]\.\/utils\/intentDigest/,
      "export from './utils/intentDigest*' (threshold internals)",
    ),
    ...collectRegexLineMatches(
      rootSource,
      /^\s*export\s+.*from\s+['"]\.\/threshold['"]/,
      "export from './threshold' (must stay in subpath export)",
    ),
  ].map((match) => ({
    file: toPosixPath(path.relative(repoRoot, rootIndexPath)),
    line: match.line,
    pattern: match.pattern,
    text: match.text,
  }));

  const experimentalDirViolations = fs.existsSync(experimentalDirPath)
    ? [
        {
          file: toPosixPath(path.relative(repoRoot, experimentalDirPath)),
          line: null,
          pattern: 'packages/sdk-web/src/experimental must not exist',
          text: 'remove experimental directory and expose stable APIs via explicit subpaths',
        },
      ]
    : [];

  const packageExports =
    sdkPackage?.exports && typeof sdkPackage.exports === 'object'
      ? Object.keys(sdkPackage.exports)
      : [];
  const experimentalExportViolations = packageExports
    .filter((key) => key === './experimental' || key.startsWith('./experimental/'))
    .map((key) => ({
      file: toPosixPath(path.relative(repoRoot, sdkPackagePath)),
      line: null,
      pattern: key,
      text: 'experimental export is forbidden',
    }));

  return {
    checks: [
      {
        id: 'root-forbidden-internal-signing-exports',
        description:
          'Root packages/sdk-web/src/index.ts must not export signing internals or threshold subpath modules',
        violations: rootForbiddenMatches,
      },
      {
        id: 'experimental-directory-removed',
        description: 'packages/sdk-web/src/experimental directory must be removed',
        violations: experimentalDirViolations,
      },
      {
        id: 'package-no-experimental-exports',
        description: 'packages/sdk-web/package.json must not export ./experimental* subpaths',
        violations: experimentalExportViolations,
      },
    ],
    error: null,
  };
}
