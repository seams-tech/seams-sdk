# Seams SDK Rename Completion Plan

Date created: 2026-04-22
Last rescanned: 2026-04-30

## Objective

Complete the SDK-wide rename to Seams across package metadata, public exports,
examples, docs, server helpers, EVM smart-account code, tests, generated build
artifacts, and local development tooling.

This is a breaking cleanup. Do not keep legacy aliases, deprecated exports,
fallback environment variables, duplicate docs, or compatibility package paths.
The active codebase should read as if Seams had always been the product name.

## Canonical Public Surface

- Package name: `@seams/sdk`
- Root SDK export: `SeamsPasskey`
- React exports: `SeamsPasskeyProvider`, `SeamsContextProvider`, `useSeams`
- Config types: `SeamsConfigsInput`, `SeamsConfigsReadonly`
- Vite plugins: `seamsWallet`, `seamsApp`, `seamsWalletServer`,
  `seamsAppServer`, `seamsBuildHeaders`, `seamsHeaders`, `seamsServeSdk`,
  `seamsWalletService`
- Next plugins: `seamsNextApp`, `seamsNextWallet`, `seamsNextHeaders`
- EVM smart account: `SeamsSmartAccount`, `SeamsSmartAccountFactory`,
  `ISeamsSmartAccount`
- Runtime identifiers: `seams-jwt`, `x-seams-*`, `VITE_SEAMS_*`

## Rename Rules

1. Do not export legacy symbols from public SDK entrypoints.
2. Do not keep legacy package imports in examples, docs, tests, or tsconfig
   paths.
3. Do not keep fallback support for old environment variables, auth headers,
   cookie names, storage keys, or protocol-domain strings.
4. Do not keep duplicate files for old and new names.
5. Rename files and directories when their names contain old product terms.
6. Regenerate generated artifacts after renaming sources instead of editing
   generated output by hand.
7. Update tests to assert the Seams public surface.
8. Use "specs" when referring to specifications.

## Current Scope

- Root package metadata, workspace config, lockfile, lint/prettier ignores, and
  GitHub workflows.
- SDK package metadata, TypeScript config, build-path helpers, build scripts,
  generated declarations, and runtime bundles.
- Public client SDK under `client/src/index.ts`, `client/src/core/SeamsPasskey`,
  `client/src/core/types/seams.ts`, `client/src/react`, and
  `client/src/plugins`.
- Wallet iframe runtime under `client/src/core/WalletIframe`.
- Server and relayer code under `server/src`, `examples/relay-server`,
  `examples/relay-cloudflare-worker`, and `examples/self-host-cloudflare-worker`.
- Example site and docs under `examples/seams-site` and `examples/seams-docs`.
- EVM smart-account Solidity source, interfaces, ABI metadata, deploy scripts,
  selector helpers, and tests.
- Persistent/runtime identifiers in IndexedDB names, local storage keys, cookie
  names, email recovery prefixes, AAD/domain-separation strings, threshold
  prefixes, auth headers, and route examples.
- Rust/WASM crates, formal verification fixtures, and test harnesses.

## Execution Checklist

1. Rename filesystem paths for SDK core, React provider/context, type modules,
   example apps/docs, tests, and EVM smart-account source/ABI files.
2. Rewrite source, tests, docs, configs, package metadata, environment variables,
   headers, cookies, storage keys, and protocol-domain strings to Seams names.
3. Update `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `.github` workflows, root
   scripts, and example package names.
4. Regenerate SDK declarations and runtime bundles with `pnpm -C sdk run build`.
5. Verify package subpath exports for:
   - `@seams/sdk`
   - `@seams/sdk/threshold`
   - `@seams/sdk/plugins/headers`
   - `@seams/sdk/plugins/next`
   - `@seams/sdk/plugins/vite`
   - `@seams/sdk/server`
   - `@seams/sdk/server/router/express`
   - `@seams/sdk/server/router/cloudflare`
   - `@seams/sdk/server/router/ror`
   - `@seams/sdk/server/wasm/signer`
   - `@seams/sdk/react`
   - `@seams/sdk/react/provider`
   - `@seams/sdk/react/profile`
   - `@seams/sdk/react/passkey-auth-menu`
   - `@seams/sdk/react/styles`
6. Run targeted verification:
   - `git grep -n -I -e '<legacy brand markers>' -- .`
   - `rg -n '<legacy brand markers>' sdk/dist -g '!**/*.map'`
   - `pnpm -C sdk run build`
   - `pnpm -C examples/seams-site run typecheck`
   - `pnpm -C examples/seams-docs exec tsc --noEmit --pretty false`

## Completion Criteria

- No tracked file paths contain legacy product terms.
- No tracked text files contain legacy product terms.
- Generated SDK runtime bundles and declarations expose Seams names only.
- Example site and docs typecheck against `@seams/sdk`.
- The SDK build succeeds from renamed sources.
- Any remaining verification failures are unrelated to the rename and are
  documented with exact commands and failure areas.
