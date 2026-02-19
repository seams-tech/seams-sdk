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
  const rootIndexPath = path.join(repoRoot, 'client/src/index.ts');
  const experimentalIndexPath = path.join(repoRoot, 'client/src/experimental/index.ts');

  if (!fs.existsSync(rootIndexPath)) {
    return {
      checks: [],
      error: `[check-stable-experimental-export-boundaries] missing file: ${rootIndexPath}`,
    };
  }
  if (!fs.existsSync(experimentalIndexPath)) {
    return {
      checks: [],
      error: `[check-stable-experimental-export-boundaries] missing file: ${experimentalIndexPath}`,
    };
  }

  const rootSource = fs.readFileSync(rootIndexPath, 'utf8');
  const experimentalSource = fs.readFileSync(experimentalIndexPath, 'utf8');

  const rootForbiddenMatches = [
    ...collectRegexLineMatches(
      rootSource,
      /^\s*export\s+.*from\s+['"]\.\/core\/signing\//,
      "export from './core/signing/*'",
    ),
    ...collectRegexLineMatches(
      rootSource,
      /^\s*export\s+.*from\s+['"]\.\/utils\/intentDigest/,
      "export from './utils/intentDigest*'",
    ),
  ].map((match) => ({
    file: toPosixPath(path.relative(repoRoot, rootIndexPath)),
    line: match.line,
    pattern: match.pattern,
    text: match.text,
  }));

  const requiredExports = [
    {
      pattern: /^\s*export\s+\*\s+from\s+['"]\.\/signing['"];\s*$/m,
      label: "export * from './signing';",
    },
    {
      pattern: /^\s*export\s+\*\s+from\s+['"]\.\/threshold['"];\s*$/m,
      label: "export * from './threshold';",
    },
  ];

  const experimentalMissingExports = [];
  for (const required of requiredExports) {
    if (required.pattern.test(experimentalSource)) continue;
    experimentalMissingExports.push({
      file: toPosixPath(path.relative(repoRoot, experimentalIndexPath)),
      line: null,
      pattern: required.label,
      text: 'missing required re-export',
    });
  }

  return {
    checks: [
      {
        id: 'root-forbidden-experimental-exports',
        description: 'Root client/src/index.ts must not export experimental signing internals',
        violations: rootForbiddenMatches,
      },
      {
        id: 'experimental-required-exports',
        description: 'client/src/experimental/index.ts must re-export ./signing and ./threshold',
        violations: experimentalMissingExports,
      },
    ],
    error: null,
  };
}
