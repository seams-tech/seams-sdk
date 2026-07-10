import Lake
open Lake DSL

require aeneas from "./tools/aeneas/backends/lean"

package «ed25519-yao-boundary»

@[default_target] lean_lib Ed25519Yao

@[default_target] lean_lib Ed25519YaoBoundary
