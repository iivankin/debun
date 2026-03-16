# debun

`debun` turns Bun `--compile` binaries and extracted Bun payloads into a readable workspace.

It can:
- extract the raw `__BUN` section
- carve out embedded BunFS files like `index.js`, `chunk-*.js`, `html`, `css`, `png`, `txt`, `wasm`, and native `.node` blobs
- format JS with Oxc
- deterministically rename minified locals
- split CommonJS and lazy-init bundles into separate files when the input is a single wrapped bundle

## Install

Install the latest release binary in one step on macOS/Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/iivankin/debun/main/install.sh | bash
```

By default this installs `debun` into `~/.local/bin`.

```bash
debun --help
```

To install into a different directory:

```bash
curl -fsSL https://raw.githubusercontent.com/iivankin/debun/main/install.sh | DEBUN_INSTALL_DIR=/usr/local/bin bash
```

## Usage

Basic usage:

```bash
debun <input-binary-or-js> --out-dir <output-dir>
```

Examples:

```bash
debun ./app-binary --out-dir ./out/app
debun ./bundle.js --out-dir ./out/bundle
```

Available flags:

```bash
debun <input> [--out-dir <dir>] [--module-name <name>] [--no-rename]
```

## Output

Typical output directory:

```text
output/
  summary.json
  symbols.txt             # only when renaming produced a symbol map
  modules/
  modules.txt
  embedded/
    manifest.json
    files/
```

Important files:
- `summary.json`: machine-friendly overview of the generated workspace and the first useful artifact to inspect
- `symbols.txt`: old symbol -> new symbol mapping, only when renaming produced one
- `modules/`: split CJS/lazy-init modules when the source is a single wrapped bundle
- `embedded/manifest.json`: machine-friendly inventory of extracted embedded files, entrypoint, and recovered metadata
- `embedded/files/`: recovered BunFS file tree

## What Works Well

- Bun native binaries
- Bun asset bundles embedded into a compiled server binary
- binaries that contain a `__BUN` section with BunFS paths and inline payloads
- Linux-style Bun executables that append the standalone graph trailer instead of using a `__BUN` section

## Current Scope

`debun` is strongest in two cases:
- a single big Bun bundle that uses CommonJS/lazy-init helpers
- a Bun-compiled binary that embeds already-separated BunFS assets

For the first case it can reconstruct internal module files.
For the second case it extracts the asset graph as separate files and rewrites the main JS bundle into a readable form, but it does not yet generate a second readable copy for every extracted ESM chunk.

## Development

Local verification:

```bash
cargo fmt --all
cargo check
cargo build --release
```

CI lives in:

```text
.github/workflows/ci.yml
```
