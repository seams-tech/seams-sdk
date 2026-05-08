# Refactor 33 Folder Ownership README Template

Use this template for each new top-level folder under
`client/src/core/signingEngine`.

```md
# <folder-name>

## Owns

- <The lifecycle state, boundary, or operation surface this folder owns.>

## May Import

- `<allowed-folder-or-file>`

## Must Not Import

- `<forbidden-folder-or-file>`

## Entrypoints

- `<file>.ts`: <who calls this file and why>
```

Keep each ownership README short. It is a review guard, not a design document.
