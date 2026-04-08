# debun

`debun` turns Bun `--compile` binaries and extracted Bun payloads into a readable workspace.

It can:
- extract the raw `__BUN` section
- carve out embedded BunFS files like `index.js`, `chunk-*.js`, `html`, `css`, `png`, `txt`, `wasm`, and native `.node` blobs
- format JS with Oxc
- deterministically rename minified locals
- split CommonJS and lazy-init bundles into separate files when the input is a single wrapped bundle and `--unbundle` is enabled
- pack edited extracted BunFS files back into a Bun standalone binary
- generate portable `.patch` bundles from edited extracted BunFS files and apply them to an original standalone binary

## Install

Install the latest release binary in one step on macOS/Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/iivankin/debun/main/install.sh | bash
```

By default this installs `debun` into `~/.local/bin`.

```bash
debun --help
```

Install the latest release binary in one step on Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/iivankin/debun/main/install.ps1 | iex"
```

This installs `debun.exe` into `%USERPROFILE%\.local\bin` and adds that directory to your user `PATH` if needed.

## Usage

Basic usage:

```bash
debun <input-binary-or-js> --out-dir <output-dir>
```

Examples:

```bash
debun ./app-binary --out-dir ./out/app
debun ./bundle.js --out-dir ./out/bundle
debun ./bundle.js --out-dir ./out/bundle --unbundle
debun pack ./out/app --out ./app-binary.repacked
debun patch ./out/app --out ./app-binary.patch
debun apply-patch ./app-binary.patch ./app-binary --out ./app-binary.patched
```

Available flags:

```bash
debun <input> [--out-dir <dir>] [--module-name <name>] [--no-rename] [--unbundle]
debun pack [<dir>] [--out <file>]
debun patch [<dir>] [--out <file>]
debun apply-patch <patch-file> [<input-binary>] [--out <file>]
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
- `modules/`: split CJS/lazy-init modules when the source is a single wrapped bundle and `--unbundle` is enabled
- `embedded/manifest.json`: machine-friendly inventory of extracted embedded files, entrypoint, standalone layout/Bun version, and recovered metadata
- `embedded/files/`: recovered BunFS file tree plus raw/decoded standalone sourcemap and `module_info` sidecars when Bun stored them

## Repack

Use `pack` to rebuild a Bun standalone executable from edited extracted files:

```bash
debun pack ./out/app --out ./app-binary.repacked
```

`unpack` saves repack support under `<out>/.debun/`, including the original standalone executable as a local base.

`pack` reads replacements from the first matching directory:
- `<dir>/embedded/files`
- `<dir>/files`
- `<dir>` itself

`pack` supports Bun standalone executables. It uses the saved base executable from `.debun/` and swaps only the embedded standalone payload.
On macOS the packed output is re-signed ad-hoc automatically, because mutating the Mach-O bytes invalidates the original embedded signature.

## Patch Workflow

Use `patch` when you want a portable bundle of just the changes you made after unpacking:

```bash
debun ./app-binary --out-dir ./out/app
# edit ./out/app/embedded/files/...
debun patch ./out/app --out ./app-binary.patch
debun apply-patch ./app-binary.patch ./app-binary --out ./app-binary.patched
```

`patch` compares the edited workspace against the saved base executable under `.debun/` and writes a debun `.patch` bundle.
`apply-patch` validates that the target standalone binary still matches the original bytes expected by the patch before rebuilding the embedded payload.

The patch workflow follows the same packable surface as `pack`:
- BunFS file contents
- `.debun-sourcemap.bin`
- `.debun-bytecode.bin`
- `.debun-module-info.bin`

Decoded helper files like `.debun-sourcemap.json` and `.debun-module-info.json` are read-only views and are not included in patches.

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
cargo test
cargo build --release
```

CI lives in:

```text
.github/workflows/ci.yml
```
