#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const WASM_HEADER_SIZE = 8;
const SECTION_NAMES = [
  'custom',
  'type',
  'import',
  'function',
  'table',
  'memory',
  'global',
  'export',
  'start',
  'element',
  'code',
  'data',
  'data_count',
  'tag',
];
const ATTRIBUTION_GROUPS = {
  nearThreshold: ['threshold_signatures', 'ot_based_ecdsa', 'generate_triple', 'presign'],
  messagePack: ['rmp_serde', 'rmp::'],
  futures: ['futures'],
  secp256k1: ['k256', 'secp256k1'],
  p256: ['p256::', 'p256['],
  cbor: ['ciborium', 'cbor', 'cose'],
  eip1559: ['eip1559'],
  derivation: ['derive', 'hkdf'],
  allocation: ['alloc::', '__rust_alloc', 'dlmalloc'],
  panic: ['panic', 'unwrap_failed'],
  bindings: ['wasm_bindgen', 'serde_wasm_bindgen'],
};

function fail(message) {
  throw new Error(message);
}

function readU32(bytes, initialOffset) {
  let offset = initialOffset;
  let result = 0;
  let shift = 0;
  for (let index = 0; index < 5; index += 1) {
    if (offset >= bytes.length) {
      fail('truncated unsigned LEB128 value');
    }
    const byte = bytes[offset];
    offset += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: offset };
    }
    shift += 7;
  }
  fail('oversized unsigned LEB128 value');
}

function readName(bytes, initialOffset, limit) {
  const length = readU32(bytes, initialOffset);
  const end = length.nextOffset + length.value;
  if (end > limit) {
    fail('truncated Wasm name');
  }
  return {
    value: new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(length.nextOffset, end)),
    nextOffset: end,
  };
}

function validateHeader(bytes) {
  const expected = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  if (bytes.length < WASM_HEADER_SIZE) {
    fail('truncated WebAssembly header');
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (bytes[index] !== expected[index]) {
      fail('unsupported WebAssembly magic or version');
    }
  }
}

function parseSections(bytes) {
  validateHeader(bytes);
  const sections = [];
  let offset = WASM_HEADER_SIZE;
  while (offset < bytes.length) {
    const start = offset;
    const id = bytes[offset];
    offset += 1;
    const payloadLength = readU32(bytes, offset);
    const payloadStart = payloadLength.nextOffset;
    const end = payloadStart + payloadLength.value;
    if (end > bytes.length) {
      fail(`section ${id} exceeds artifact length`);
    }
    let customName = null;
    if (id === 0) {
      customName = readName(bytes, payloadStart, end).value;
    }
    sections.push({
      id,
      name: SECTION_NAMES[id] ?? `unknown_${id}`,
      customName,
      start,
      payloadStart,
      end,
      encodedBytes: end - start,
      payloadBytes: payloadLength.value,
    });
    offset = end;
  }
  return sections;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareSurfaceEntry(left, right) {
  const leftKey = `${left.module ?? ''}\0${left.name}\0${left.kind}`;
  const rightKey = `${right.module ?? ''}\0${right.name}\0${right.kind}`;
  return leftKey.localeCompare(rightKey);
}

function moduleSurface(bytes) {
  const module = new WebAssembly.Module(bytes);
  return {
    imports: WebAssembly.Module.imports(module).sort(compareSurfaceEntry),
    exports: WebAssembly.Module.exports(module).sort(compareSurfaceEntry),
  };
}

function publicSection(section) {
  return {
    id: section.id,
    name: section.name,
    customName: section.customName,
    encodedBytes: section.encodedBytes,
    payloadBytes: section.payloadBytes,
  };
}

function skipLimits(bytes, initialOffset, limit) {
  const flags = readU32(bytes, initialOffset);
  const minimum = readU32(bytes, flags.nextOffset);
  let offset = minimum.nextOffset;
  if ((flags.value & 0x01) !== 0) {
    offset = readU32(bytes, offset).nextOffset;
  }
  if (offset > limit) {
    fail('truncated Wasm limits');
  }
  return offset;
}

function countImportedFunctions(bytes, sections) {
  const section = sections.find((candidate) => candidate.id === 2);
  if (section === undefined) {
    return 0;
  }
  const count = readU32(bytes, section.payloadStart);
  let offset = count.nextOffset;
  let functions = 0;
  for (let index = 0; index < count.value; index += 1) {
    offset = readName(bytes, offset, section.end).nextOffset;
    offset = readName(bytes, offset, section.end).nextOffset;
    if (offset >= section.end) {
      fail('truncated Wasm import descriptor');
    }
    const kind = bytes[offset];
    offset += 1;
    if (kind === 0) {
      functions += 1;
      offset = readU32(bytes, offset).nextOffset;
    } else if (kind === 1) {
      offset += 1;
      offset = skipLimits(bytes, offset, section.end);
    } else if (kind === 2) {
      offset = skipLimits(bytes, offset, section.end);
    } else if (kind === 3) {
      offset += 2;
    } else if (kind === 4) {
      offset += 1;
      offset = readU32(bytes, offset).nextOffset;
    } else {
      fail(`unsupported Wasm import kind ${kind}`);
    }
  }
  return functions;
}

function parseFunctionNames(bytes, sections) {
  const names = new Map();
  const section = sections.find(
    (candidate) => candidate.id === 0 && candidate.customName === 'name',
  );
  if (section === undefined) {
    return names;
  }
  let offset = readName(bytes, section.payloadStart, section.end).nextOffset;
  while (offset < section.end) {
    const subsectionId = bytes[offset];
    offset += 1;
    const size = readU32(bytes, offset);
    const subsectionEnd = size.nextOffset + size.value;
    if (subsectionEnd > section.end) {
      fail('truncated Wasm name subsection');
    }
    if (subsectionId === 1) {
      const count = readU32(bytes, size.nextOffset);
      let entryOffset = count.nextOffset;
      for (let index = 0; index < count.value; index += 1) {
        const functionIndex = readU32(bytes, entryOffset);
        const name = readName(bytes, functionIndex.nextOffset, subsectionEnd);
        names.set(functionIndex.value, name.value);
        entryOffset = name.nextOffset;
      }
    }
    offset = subsectionEnd;
  }
  return names;
}

function parseFunctionBodies(bytes, sections) {
  const section = sections.find((candidate) => candidate.id === 10);
  if (section === undefined) {
    return [];
  }
  const importedFunctions = countImportedFunctions(bytes, sections);
  const count = readU32(bytes, section.payloadStart);
  const bodies = [];
  let offset = count.nextOffset;
  for (let index = 0; index < count.value; index += 1) {
    const size = readU32(bytes, offset);
    const end = size.nextOffset + size.value;
    if (end > section.end) {
      fail('truncated Wasm function body');
    }
    bodies.push({ functionIndex: importedFunctions + index, bodyBytes: size.value });
    offset = end;
  }
  return bodies;
}

function symbolGroups(symbols) {
  const groups = {};
  for (const [group, tokens] of Object.entries(ATTRIBUTION_GROUPS)) {
    const matches = symbols.filter((symbol) => {
      const normalized = symbol.name.toLowerCase();
      return tokens.some((token) => normalized.includes(token));
    });
    groups[group] = {
      functionCount: matches.length,
      bodyBytes: matches.reduce((sum, symbol) => sum + symbol.bodyBytes, 0),
    };
  }
  return groups;
}

function symbolStats(bytes, sections) {
  const names = parseFunctionNames(bytes, sections);
  if (names.size === 0) {
    return { available: false, reason: 'name custom section absent' };
  }
  const symbols = parseFunctionBodies(bytes, sections).map((body) => ({
    ...body,
    name: names.get(body.functionIndex) ?? `<function:${body.functionIndex}>`,
  }));
  const named = symbols.filter((symbol) => !symbol.name.startsWith('<function:'));
  const topByBodyBytes = [...named]
    .sort((left, right) => right.bodyBytes - left.bodyBytes)
    .slice(0, 40);
  return {
    available: true,
    definedFunctionCount: symbols.length,
    namedFunctionCount: named.length,
    groups: symbolGroups(named),
    topByBodyBytes,
  };
}

function artifactStats(bytes) {
  const sections = parseSections(bytes);
  return {
    sha256: sha256(bytes),
    bytes: {
      raw: bytes.length,
      gzip9: gzipSync(bytes, { level: 9, mtime: 0 }).length,
      brotli11: brotliCompressSync(bytes, {
        params: {
          [constants.BROTLI_PARAM_QUALITY]: 11,
          [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_GENERIC,
        },
      }).length,
    },
    sections: sections.map(publicSection),
    symbols: symbolStats(bytes, sections),
    surface: moduleSurface(bytes),
  };
}

function shouldStripCustomSection(name) {
  return (
    name === 'name' ||
    name === 'producers' ||
    name === 'sourceMappingURL' ||
    name === 'external_debug_info' ||
    name.startsWith('.debug_') ||
    name.startsWith('reloc..debug_')
  );
}

function stripMetadata(bytes) {
  const retained = [bytes.subarray(0, WASM_HEADER_SIZE)];
  const removed = [];
  for (const section of parseSections(bytes)) {
    if (section.id === 0 && shouldStripCustomSection(section.customName)) {
      removed.push(publicSection(section));
    } else {
      retained.push(bytes.subarray(section.start, section.end));
    }
  }
  return { bytes: Buffer.concat(retained), removed };
}

function surfacesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function inspect(inputPath) {
  const bytes = readFileSync(inputPath);
  return {
    schema: 'seams.refactor89.wasm-inspection.v1',
    artifact: basename(inputPath),
    ...artifactStats(bytes),
  };
}

function summary(inputPath) {
  const inspection = inspect(inputPath);
  return {
    schema: 'seams.refactor89.wasm-summary.v1',
    artifact: inspection.artifact,
    sha256: inspection.sha256,
    bytes: inspection.bytes,
    sections: inspection.sections,
    symbolGroups: inspection.symbols.groups ?? null,
    topSymbols: inspection.symbols.topByBodyBytes?.slice(0, 15) ?? [],
    importCount: inspection.surface.imports.length,
    exports: inspection.surface.exports,
  };
}

function strip(inputPath, outputPath) {
  const input = readFileSync(inputPath);
  const before = artifactStats(input);
  const stripped = stripMetadata(input);
  writeFileSync(outputPath, stripped.bytes);
  const after = artifactStats(stripped.bytes);
  return {
    schema: 'seams.refactor89.wasm-strip-map.v1',
    input: basename(inputPath),
    output: basename(outputPath),
    before,
    after,
    removedSections: stripped.removed,
    exportAndImportSurfaceUnchanged: surfacesEqual(before.surface, after.surface),
  };
}

function assertStripped(inputPath) {
  const inspection = inspect(inputPath);
  const forbidden = inspection.sections.filter(
    (section) => section.id === 0 && shouldStripCustomSection(section.customName),
  );
  if (forbidden.length > 0) {
    fail(
      `${inputPath} contains forbidden custom sections: ${forbidden
        .map((section) => section.customName)
        .join(', ')}`,
    );
  }
  return {
    schema: 'seams.refactor89.wasm-stripped-assertion.v1',
    artifact: basename(inputPath),
    sha256: inspection.sha256,
    passed: true,
  };
}

function compareSurfaces(leftPath, rightPath) {
  const left = inspect(leftPath);
  const right = inspect(rightPath);
  const equal = surfacesEqual(left.surface, right.surface);
  if (!equal) {
    fail(`Wasm import/export surface changed between ${leftPath} and ${rightPath}`);
  }
  return {
    schema: 'seams.refactor89.wasm-surface-comparison.v1',
    left: { artifact: left.artifact, sha256: left.sha256 },
    right: { artifact: right.artifact, sha256: right.sha256 },
    equal,
  };
}

function main(arguments_) {
  const [operation, inputPath, outputPath] = arguments_;
  if (operation === 'inspect' && inputPath !== undefined && outputPath === undefined) {
    process.stdout.write(`${JSON.stringify(inspect(inputPath), null, 2)}\n`);
    return;
  }
  if (operation === 'summary' && inputPath !== undefined && outputPath === undefined) {
    process.stdout.write(`${JSON.stringify(summary(inputPath), null, 2)}\n`);
    return;
  }
  if (operation === 'assert-stripped' && inputPath !== undefined && outputPath === undefined) {
    process.stdout.write(`${JSON.stringify(assertStripped(inputPath), null, 2)}\n`);
    return;
  }
  if (operation === 'compare-surface' && inputPath !== undefined && outputPath !== undefined) {
    process.stdout.write(`${JSON.stringify(compareSurfaces(inputPath, outputPath), null, 2)}\n`);
    return;
  }
  if (operation === 'strip' && inputPath !== undefined && outputPath !== undefined) {
    process.stdout.write(`${JSON.stringify(strip(inputPath, outputPath), null, 2)}\n`);
    return;
  }
  fail(
    'usage: wasm-metadata.mjs inspect|summary|assert-stripped <wasm> | strip|compare-surface <input-wasm> <output-wasm>',
  );
}

main(process.argv.slice(2));
