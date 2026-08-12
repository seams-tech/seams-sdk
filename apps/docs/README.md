# Seams documentation app

The docs are a VitePress application served at `docs.seams.sh`. The root route
is the Start here guide; product marketing remains on the main Seams site.

## Local checks

```bash
pnpm -C apps/docs type-check
pnpm check:docs-links
pnpm check:docs-fences
pnpm -C apps/docs build
```

Runnable examples live under `src/examples` and are rendered into Markdown with
VitePress code imports. The docs type check compiles those source files against
the workspace SDK declarations.

## Keep docs and the public SDK together

Update the docs in the same change whenever a public SDK signature, result
union, configuration branch, package export, or public route changes. Add or
update a compiled example for runnable TypeScript and TSX. Label partial,
protocol, and application-specific examples so readers do not mistake them for
copyable SDK code.

Use `apps/seams-site` as the source for product language, typography, brand
assets, semantic color roles, and interaction treatment.
