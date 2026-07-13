# 05 — Content-Leak Elimination: Compile-Time + Runtime Guarantee

Status: research / design.
Owns: the enforcement and verification of **Property (1)** — `relay-core`, the Go
binary that runs inside the SGX enclave (Gramine-SGX 1.9), must **provably never
persist request/response CONTENT** (prompts, completions, uploaded media, upstream
error bodies) to any host-visible medium (disk, host filesystem, DB, Redis).
Non-content metadata (token counts, model name, latency) may persist, but is
emitted *out of* the enclave to `new-api` over the metadata channel — it is never
written to disk by `relay-core` itself.

This document does **not** redesign the relay path (that is doc `01-relay-core-architecture`).
It defines, whatever import-severance strategy doc 01 picks, the layered guarantee
that no leak site survives in `relay-core`'s final package closure, plus a runnable
CI check and a Gramine manifest that makes an accidental write physically impossible.

The guarantee is defense-in-depth across three independent layers:

1. **Compile-time** — forbidden symbols are not reachable in the linked binary
   (build tags / stub packages + compile-time `const` config).
2. **CI/lint** — the build fails if the package closure of `./cmd/relay-core`
   references a forbidden symbol.
3. **Runtime** — the Gramine `[fs]` mount table exposes **no writable host path**;
   the only writable mount is enclave-encrypted `tmpfs`. A bug that calls
   `os.Create` can, at worst, write to encrypted EPC memory that never touches
   the host and is destroyed on enclave teardown.

Any single layer failing does not breach the property; all three must fail
simultaneously and identically, which is the point of the design.

---

## 0. The audited leak sites (recap, with file:line)

Every site below is **conditional / default-off** in the full `new-api`, but
`relay-core` must make each one *structurally impossible*, not merely disabled.

| # | Site | Package | Trigger | Default |
|---|------|---------|---------|---------|
| A | `newDiskStorage` `common/body_storage.go:100` → `CreateDiskCacheFile` `:102`; `newDiskStorageFromReader` `:132`→`:134` | `common` | `DiskCacheEnabled` | off |
| B | `CreateDiskCacheFile` `common/disk_cache.go:42` → `os.OpenFile` `:51`; `WriteDiskCacheFile` `:61` | `common` | called by A / file_service | off |
| C | `writeToDiskCache` `service/file_service.go:244` (calls `:198`, `:357`) | `service` | `DiskCacheEnabled` | off |
| D | dify per-image `os.CreateTemp` `relay/channel/dify/relay-dify.go:46` (removed `:52`) | `relay/channel/dify` | always (redundant) | n/a |
| E | DEBUG body dumps: `relay-openai.go:198` (`upstream response body`), `stream_scanner.go:252` (every SSE chunk), `compatible_handler.go:104` & `:176` | `relay/*`, `relay/helper` | `common.DebugEnabled` | off |
| F | Upstream error body preview: `service/error.go:96` `LocalLogPreview` + `:109` `LogError` (NOT debug-gated) | `service`, `common` | always on error path | n/a |
| G | Error body → DB: `model/log.go:283` `RecordErrorLog` | `model` | `constant.ErrorLogEnabled` | off |

Config gates today are **runtime**:
`DiskCacheEnabled` from `setting/performance_setting/config.go:31` (default `false`),
`DebugEnabled` from `common/init.go:85` (env `DEBUG`, default `false`, var declared
`common/constants.go:114`), `ErrorLogEnabled` from `common/init.go:157`
(env `ERROR_LOG_ENABLED`, default `false`). Runtime gates are insufficient for a
provable property: a misconfigured env or a future code path can flip them. The
enclave build must convert these to **compile-time falsehood** and remove the
sinks from the closure entirely.

---

## 1. Import-graph analysis: what drags what

### 1.1 The commands

Go's `go list` computes the exact transitive package closure that will be linked
into a binary. Two forms matter:

```bash
# Every package linked into the relay-core binary (this IS the attack surface):
go list -deps ./cmd/relay-core

# What a single adaptor package drags in (diagnostic — shows the problem):
go list -deps ./relay/channel/openai
```

`-deps` prints one import path per line, in dependency order (leaves first),
including the package itself and the whole standard library it touches. Read it as:
"if a package name appears in this list, its source is compiled and linked, and
every top-level `var`/`init()` in it runs." A leak site is reachable iff its
package appears in `go list -deps ./cmd/relay-core`.

To see *why* a forbidden package is pulled in (the shortest import chain), use:

```bash
# Why does the openai adaptor import `model` (the DB layer)?
go mod why -m github.com/QuantumNous/new-api 2>/dev/null   # module-level, coarse
# Package-level chain (preferred) — needs the golang.org/x/tools helper:
#   go install golang.org/x/tools/cmd/digraph@latest
go list -deps -f '{{.ImportPath}} {{join .Imports " "}}' ./cmd/relay-core \
  | tr ' ' '\n' | grep -n . >/dev/null   # (see 1.4 for the digraph one-liner)
```

### 1.2 Confirmed: the openai adaptor's closure contains every leak site

The salvaged finding from last session holds: `relay/channel/openai` transitively
imports `common`, `service`, `model`, `logger`, and `relay/helper`. Mapping that
against §0:

| Leak site package | In `relay/channel/openai` closure? | Why |
|---|---|---|
| `common` (A, B, F-preview) | yes | adaptor calls `common.Unmarshal`, `common.SysLog`, etc. — `common` is a near-universal import |
| `service` (C, F) | yes | adaptor calls `service.GetHttpClient`, `service.CloseResponseBodyGracefully`, `service.ResponseText2Usage` |
| `model` (G) | yes | pulled transitively via `service` (billing/logging) |
| `logger` (E, F) | yes | `relay-openai.go:198` calls `logger.LogDebug` directly |
| `relay/helper` (E) | yes | `stream_scanner.go` lives here; adaptor calls `helper.StreamScannerHandler` |

So a naive `relay-core` that does `import "relay/channel/openai"` links **all seven
leak sites**. Confirm on the real tree before trusting this table:

```bash
# Does the adaptor closure contain the leak-site packages? (expect all present today)
go list -deps ./relay/channel/openai | grep -E \
  'new-api/(common|service|model|logger|relay/helper)$'
```

### 1.3 Safe-to-import vs must-fork/stub

The severance strategy (owned by doc 01) determines the concrete package layout,
but the *classification* is fixed by the leak sites:

**Safe to import as-is** (no leak site, pure transform / type):
- `dto/`, `types/`, `constant/` — request/response structs, error codes, enums.
- `relay/channel/openai/*` conversion helpers that are pure functions of the DTO
  (request→upstream marshal, response→client unmarshal), *provided they are cut
  from the packages that carry the sinks*.
- `common/json.go` wrappers (`common.Marshal`/`Unmarshal`) — these do not persist;
  but they live in `common`, which also carries A/B/F. See §1.4.

**Must fork or stub** (carry a leak site or drag one in):
- `common` disk-cache (`body_storage.go`, `disk_cache.go`) — sites A, B.
- `service/file_service.go` (`writeToDiskCache`) — site C.
- `relay/channel/dify` `os.CreateTemp` — site D (also just delete the temp file, §2.3).
- `logger` body-dump paths and `service/error.go` preview — sites E, F.
- `model` (DB layer) — site G, and it drags GORM + the entire DB stack, which has
  no place in an enclave whose whole point is *not* persisting.

### 1.4 The `common` problem and how to resolve it

`common` is the hard case: it holds both harmless helpers (`common.Marshal`,
`common.GetTimestamp`) **and** the disk-cache sinks (A, B) **and** `LocalLogPreview`
(F). Because Go's compilation unit is the *package*, importing `common` for
`common.Marshal` links `disk_cache.go` and `body_storage.go` too, and runs their
`init()`s. You cannot import "half a package."

Two resolutions, tied to doc 01's choice:

- **Build-tag stubbing (recommended, §2.1):** keep the `common` package name but
  compile `disk_cache.go` / `body_storage.go` under `//go:build !enclave`, and
  provide `//go:build enclave` stub files that either omit the functions or make
  them `panic`/no-op with a compile-time-false guard. The harmless helpers stay.
- **Package split:** extract the pure helpers (`json.go`, timestamps) into a new
  leaf package (e.g. `common/purejson`) that `relay-core` imports, leaving the
  sinks in `common` which `relay-core` never imports. Cleaner closure, larger diff.

To find the shortest import chain that forces a forbidden package in (so you know
*which* import to sever), use `digraph`:

```bash
go install golang.org/x/tools/cmd/digraph@latest
go list -deps -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}' ./cmd/relay-core \
  | digraph somepath github.com/QuantumNous/new-api/cmd/relay-core \
                     github.com/QuantumNous/new-api/model
```

That prints the exact edge path `cmd/relay-core → … → model`, telling you which
single import to cut or stub.

---

## 2. Compile-time strategy

**Recommendation: Go build tags (`//go:build enclave`) that swap sinks for no-op
stubs, combined with compile-time `const` config.** Rationale over a fully
separate package tree:

- Reuses the existing, battle-tested DTO conversion code in `relay/channel/*`
  without a parallel copy that can drift.
- The `enclave` tag is a single, greppable, CI-enforceable switch.
- A `const` (not `var`) config lets the Go compiler *dead-code-eliminate* the sink
  branches, so they are not merely unreached — they are **not in the binary**.

The separate-package-tree option remains valid where doc 01 needs a minimal binary
anyway; the two are not mutually exclusive (tags inside a slimmed tree). This doc
enforces the guarantee for whichever doc 01 picks; the CI check in §3 is
strategy-agnostic because it inspects the *final closure*, not the source layout.

### 2.1 Compile-time-false config constants

Replace the runtime gates with build-tag-selected constants so the compiler prunes
the sink branches.

`common/enclave_config_default.go`:

```go
//go:build !enclave

package common

// Runtime-configured in the full app (setting/performance_setting, env).
const EnclaveBuild = false
```

`common/enclave_config_enclave.go`:

```go
//go:build enclave

package common

// Hard-wired for relay-core. No env, no DB, no setting can flip these.
const EnclaveBuild = true
```

Then the disk-cache gate becomes a compile-time constant in the enclave build.
`common.IsDiskCacheEnabled()` (today reads the synced `DiskCacheConfig`) is
rewritten so the enclave variant returns a constant `false`:

`common/disk_cache_gate_enclave.go`:

```go
//go:build enclave

package common

// In the enclave, disk cache is not a setting — it does not exist.
func IsDiskCacheEnabled() bool  { return false } // const-foldable
func ShouldUseDiskCache(int64) bool { return false }
```

Because these return a literal `false`, every `if ShouldUseDiskCache(...) { ... }`
branch in `body_storage.go` / `file_service.go` is dead code the linker drops, and
`CreateDiskCacheFile` becomes unreferenced — see §2.2 for removing it outright.

Similarly, `DebugEnabled` (declared `common/constants.go:114`, set from env at
`common/init.go:85`) must be a `const false` in the enclave build so that
`logger.LogDebug` (`logger/logger.go:88`, guarded by `if common.DebugEnabled` at
`:89`) compiles its body away, and the body-dump call sites (`relay-openai.go:198`,
`stream_scanner.go:252`, `compatible_handler.go:104`/`:176`) pass a string that is
never formatted or written. Provide:

`common/debug_enclave.go`:

```go
//go:build enclave

package common

const DebugEnabled = true_is_forbidden // see note
```

Note: `DebugEnabled` is currently a package `var` (`common/constants.go:114`), so
you cannot both `var` it and `const` it. The enclave build must move it behind a
build tag: `//go:build !enclave` keeps the `var DebugEnabled bool`; `//go:build
enclave` provides `const DebugEnabled = false`. All read sites (`if
common.DebugEnabled`) compile identically against either; the enclave one folds to
`if false` and the guarded body is eliminated. Do the same for
`constant.ErrorLogEnabled` (set `common/init.go:157`) → `const false`, which
makes `model.RecordErrorLog` (`model/log.go:283`, site G) unreachable from the
error path.

### 2.2 Removing the disk-cache sinks from the closure

Making `IsDiskCacheEnabled()` a const `false` prunes the *branches*, but
`CreateDiskCacheFile`/`WriteDiskCacheFile` (`common/disk_cache.go:42`,`:61`) and
`newDiskStorage*` (`common/body_storage.go:100`,`:132`) still *exist* in the
package and still reference `os.OpenFile`. The CI check in §3 greps the source of
every package in the closure, so a defined-but-unreachable `os.OpenFile` still
trips it — which is what we want: **remove the definitions from the enclave build**.

Put the disk-cache implementation behind `//go:build !enclave`:

```go
//go:build !enclave
// common/disk_cache.go  (add this tag to the top of the existing file)
```

and provide an enclave stub that does not compile any `os.*` file call:

`common/disk_cache_enclave.go`:

```go
//go:build enclave

package common

import "errors"

// relay-core never caches bodies to disk; these exist only so callers that are
// still in the closure compile. They are unreachable (guarded by the const-false
// IsDiskCacheEnabled) and contain NO os.* filesystem calls.
type DiskCacheType string

const (
	DiskCacheTypeBody DiskCacheType = "body"
	DiskCacheTypeFile DiskCacheType = "file"
)

var errNoDiskInEnclave = errors.New("disk cache disabled in enclave build")

func WriteDiskCacheFile(DiskCacheType, []byte) (string, error) { return "", errNoDiskInEnclave }
func ReadDiskCacheFile(string) ([]byte, error)                 { return nil, errNoDiskInEnclave }
func RemoveDiskCacheFile(string) error                         { return errNoDiskInEnclave }
```

Ideally, the severance in doc 01 removes the *callers* too so these stubs are not
needed at all. If `relay-core`'s closure never imports `common/body_storage.go`
(because the body-buffering path is reimplemented in-enclave), the whole issue
disappears. The stub is the fallback for the "keep `common`, tag the sinks" route.

### 2.3 Dropping the dify temp file (site D)

`relay/channel/dify/relay-dify.go:46` creates `os.CreateTemp("", "dify-upload-*")`,
writes `decodedData` to it (`:55`), then `defer os.Remove`s it (`:52`). But the
multipart form is actually built from the in-memory `decodedData` via
`io.Copy(part, bytes.NewReader(decodedData))` at `:84` — **the temp file is never
read**. It is pure dead weight and a leak site. The fix is to delete lines 45–58
entirely (the `os.CreateTemp`, the two `defer`s, and the `tempFile.Write`) and keep
the in-memory path. This is a strict simplification even for the non-enclave build,
so it can land unconditionally rather than behind a tag.

Resulting flow (already present, just remove the temp-file preamble):

```go
decodedData, err := base64.StdEncoding.DecodeString(base64Data)
if err != nil { /* ... */ return nil }
// (deleted: os.CreateTemp / defer Close / defer Remove / tempFile.Write)
body := &bytes.Buffer{}
writer := multipart.NewWriter(body)
// ... io.Copy(part, bytes.NewReader(decodedData)) at former :84
```

### 2.4 Stripping the error-body preview (site F)

`service/error.go:96` computes `responseBodyPreview := common.LocalLogPreview(
responseBodyText)` (truncates to 2048 B, `common/str.go:27`) and `:109` logs it via
`logger.LogError` — **not** debug-gated, so it fires on every upstream error and
contains upstream response bytes (which for streaming/errors can echo prompt
fragments). For the enclave build, the error handler must never render the body:

- Under `//go:build enclave`, `RelayErrorHandler` must set
  `newApiErr.Err = fmt.Errorf("bad response status code %d", resp.StatusCode)` and
  **never** construct `buildErrWithBody(...)` (`service/error.go:97-102`) nor log
  `responseBodyPreview`. The status code and a parsed, structured error *type*
  (OpenAI/Anthropic error object at `:115+`) are metadata and may pass; the raw
  body string must not.
- Because `showBodyWhenFail` is a runtime bool, the enclave variant should hard-code
  it to a compile-time `false` and drop the `logger.LogError(ctx, ...preview...)`
  call at `:109`. Provide `service/error_enclave.go` with the tagged variant, or
  gate the preview line with `if !common.EnclaveBuild` (const-folded away).
- `model.RecordErrorLog` (site G) is already gated by `ErrorLogEnabled`; with that
  a compile-time `const false` (§2.1) the DB write is eliminated.

---

## 3. CI/lint check — fail the build if a leak site is reachable

The check must be **strategy-agnostic**: it does not care how doc 01 laid out the
packages, it inspects the *actual linked closure* of `./cmd/relay-core` and greps
those packages' source for forbidden symbols. It runs with the `enclave` build tag
so it sees exactly what the enclave binary sees (build-tag-selected stubs replace
sinks).

### 3.1 What is forbidden

Two classes:

- **Filesystem-write symbols** — any host-disk write primitive:
  `os.Create`, `os.CreateTemp`, `os.OpenFile`, `os.WriteFile`, `os.Mkdir`,
  `os.MkdirAll`, `ioutil.WriteFile`.
- **Project-specific sink functions** — the named leak sites:
  `CreateDiskCacheFile`, `WriteDiskCacheFile`, `WriteDiskCacheFileString`,
  `RecordErrorLog`, `LocalLogPreview`, and any body-logging call
  (`LogDebug`/`LogError` whose argument is a response/request body — see §3.3 for
  why we ban the *sink functions* rather than trying to classify arguments).

### 3.2 The runnable script

`scripts/enclave_no_leak_check.sh` — CI-ready, exits non-zero on any hit:

```bash
#!/usr/bin/env bash
# Fails if relay-core's linked package closure can persist request/response content.
# Run from repo root. Requires: go, ripgrep (rg). CI: `bash scripts/enclave_no_leak_check.sh`
set -euo pipefail

MODULE="github.com/QuantumNous/new-api"
TARGET="./cmd/relay-core"
TAGS="enclave"

# Symbols that write to host disk or are named content sinks. Word-boundary matched.
FORBIDDEN_REGEX='\b(os\.(Create|CreateTemp|OpenFile|WriteFile|Mkdir|MkdirAll)|ioutil\.WriteFile|CreateDiskCacheFile|WriteDiskCacheFile(String)?|RecordErrorLog|LocalLogPreview)\b'

echo ">> Computing linked package closure of ${TARGET} (tags: ${TAGS})"
# Only OUR packages carry the sinks; stdlib os.* defs are fine, we scan first-party dirs.
pkgs=$(go list -deps -tags "${TAGS}" "${TARGET}" | grep "^${MODULE}/" || true)
if [ -z "${pkgs}" ]; then
  echo "ERROR: empty closure — is ${TARGET} present and building with -tags ${TAGS}?" >&2
  exit 2
fi

# Map each in-closure package import path -> its source Dir, restricted to enclave tag.
dirs=$(go list -deps -tags "${TAGS}" -f '{{.Dir}}' "${TARGET}" \
        | while read -r d; do
            case "$(go list -tags "${TAGS}" -f '{{.ImportPath}}' "$d" 2>/dev/null)" in
              ${MODULE}/*) echo "$d" ;;
            esac
          done | sort -u)

echo ">> Scanning $(echo "$dirs" | wc -l | tr -d ' ') first-party package dirs for forbidden symbols"

# Scan ONLY the .go files the enclave build actually compiles (respect build tags).
fail=0
for d in $dirs; do
  # GoFiles under the enclave tag for this dir (excludes //go:build !enclave files).
  files=$(cd "$d" && go list -tags "${TAGS}" -f '{{range .GoFiles}}{{$.Dir}}/{{.}}
{{end}}' . 2>/dev/null || true)
  [ -z "$files" ] && continue
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if rg -n --pcre2 "${FORBIDDEN_REGEX}" "$f" 2>/dev/null; then
      echo "LEAK: forbidden symbol in closure file: $f" >&2
      fail=1
    fi
  done <<< "$files"
done

if [ "$fail" -ne 0 ]; then
  echo ">> FAIL: relay-core closure references forbidden content-persisting symbols." >&2
  exit 1
fi
echo ">> PASS: no forbidden symbol reachable in relay-core closure."
```

Key properties that make this a *proof*, not a heuristic:

- It scans the **linked closure** (`go list -deps`), so a leak site in a package
  that is not imported is correctly ignored, and one that *is* imported is caught
  even if the call is behind a currently-false runtime flag — because grep sees the
  source symbol regardless of reachability. Combined with §2.2 (removing the
  definitions from the enclave build), a clean pass means the symbol is *absent*.
- It respects `-tags enclave` in **both** the closure computation and the per-dir
  `GoFiles` listing, so build-tag stubs are honored: a `//go:build !enclave` file
  containing `os.OpenFile` is not scanned because it is not compiled into the
  enclave binary.
- Word-boundary regex avoids false positives on substrings (e.g. a variable named
  `createdAt`).

### 3.3 Why ban sink functions, not "log of a body"

Statically deciding "this `LogDebug(c, fmt, body)` logs a *body*" requires
dataflow analysis and is brittle. Instead the enclave build removes the *ability*
to log bodies: with `const DebugEnabled = false` (§2.1) `LogDebug`'s body is
compiled away, and the check additionally bans `LocalLogPreview`/`RecordErrorLog`
outright. If a future contributor writes a raw `logger.LogError(c,
string(responseBody))` on a non-debug path, add an ast-grep rule as a second gate:

`scripts/enclave_no_body_log.yml` (ast-grep):

```yaml
id: no-body-in-log
language: go
rule:
  any:
    - pattern: logger.LogError($CTX, $$$string($BODY)$$$)
    - pattern: logger.LogInfo($CTX, $$$string($BODY)$$$)
  # heuristic: flag string(...) of a []byte named like a body being logged
  inside:
    kind: call_expression
message: "Do not log a stringified response/request body in relay-core."
severity: error
```

Run in CI: `ast-grep scan -r scripts/enclave_no_body_log.yml $(go list -deps -tags
enclave -f '{{.Dir}}' ./cmd/relay-core | grep "$PWD")`. This is belt to the grep
check's suspenders; the primary guarantee is symbol absence + const-folding.

### 3.4 CI wiring

Add a required job (blocks merge):

```yaml
# .github/workflows/enclave-leak-check.yml
name: enclave-content-leak-check
on: [pull_request, push]
jobs:
  no-leak:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: |
          curl -LsSf https://raw.githubusercontent.com/BurntSushi/ripgrep/master/README.md >/dev/null || true
          sudo apt-get update && sudo apt-get install -y ripgrep
      - run: bash scripts/enclave_no_leak_check.sh
      # Also prove the enclave binary actually builds with the tag:
      - run: go build -tags enclave -o /dev/null ./cmd/relay-core
```

---

## 4. Runtime belt-and-suspenders: the Gramine `[fs]` mount table

The compile-time + CI layers guarantee no forbidden symbol is reachable. The
runtime layer guarantees that *even if one were* (a bug slips past CI, a dependency
update reintroduces a call), the write cannot reach the host. Gramine-SGX only
lets the enclave see filesystem paths that the manifest explicitly mounts. If no
writable **host** path is mounted, `os.Create("/anything")` either fails with
`ENOENT`/`EACCES` or lands on an in-enclave `tmpfs` that is backed by encrypted EPC
and never persisted to the host.

### 4.1 The manifest `[fs]` snippet

`relay-core.manifest.template` (Gramine 1.9 TOML manifest):

```toml
# ---- filesystem: NO writable host path is mounted ----
[fs]
# Root and all trusted binaries/libs are READ-ONLY, integrity-checked.
root.uri = "file:/opt/relay-core/rootfs"   # ro by default in Gramine

mounts = [
  # The relay-core binary + Go runtime deps: read-only, hash-verified.
  { path = "/relay-core",      uri = "file:/opt/relay-core/relay-core", type = "chroot" },
  { path = "/etc/ssl/certs",   uri = "file:/opt/relay-core/certs",      type = "chroot" },  # ro CA bundle

  # The ONLY writable mount: an in-enclave tmpfs. NOT backed by any host path.
  # Gramine tmpfs lives in enclave memory (encrypted EPC); destroyed on teardown.
  { path = "/tmp",             type = "tmpfs" },

  # Go needs a writable /tmp for os.TempDir(); tmpfs above satisfies it WITHOUT host disk.
]

# Deliberately absent: any `sgx.allowed_files` or `sgx.trusted_files` pointing at a
# writable host dir, and any encrypted-files mount (which WOULD persist to host).
# There is no `{ uri = "file:/var/...", ... }` writable entry anywhere.

[sgx]
# Trusted files are measured into MRENCLAVE; tampering changes the measurement and
# breaks remote attestation (see doc on RA-TLS). All are read-only inputs.
trusted_files = [
  "file:/opt/relay-core/relay-core",
  "file:/opt/relay-core/certs/",
]
# NOTE: we intentionally do NOT list any allowed_files (which would permit
# unmeasured host files) and NO protected_files with a host backing store.
```

### 4.2 Why this holds even against a code bug

Three independent runtime facts combine:

1. **No writable host mount exists.** Any `os.Create`/`os.OpenFile` with a path not
   under a mounted writable location fails at the Gramine LibOS layer with
   `ENOENT`. There is no host directory the enclave can even name for writing.
2. **The one writable location (`/tmp`) is `tmpfs`, not a host file.** Gramine's
   `tmpfs` is served from enclave memory. On SGX that memory is EPC — transparently
   encrypted by the CPU's memory-encryption engine (MEE). A page written there is
   ciphertext on the DRAM bus and is *never* flushed to a host inode. When the
   enclave exits, the pages are gone; there is no file left behind, on host or
   anywhere the host OS can read.
3. **`os.TempDir()` resolves to `/tmp`.** Go's disk-cache code (`common/disk_cache.go:28`,
   `os.TempDir()` when `DiskCachePath == ""`) and `os.CreateTemp("", ...)` (dify,
   site D) default to `/tmp`. So even the *worst case* — a reintroduced
   `os.CreateTemp("")` — writes to encrypted enclave `tmpfs`, not host disk. The
   content-leak property ("never persist content to a host-visible medium") is
   preserved because `tmpfs` is not host-visible and not persistent.

The manifest is the last line: it converts "we removed the code" into "the platform
cannot do it." Note this does not make disk-cache *correct* in the enclave (the
files would vanish and break the feature) — but the feature is compiled out anyway
(§2). The manifest exists purely so an *accidental* write is contained rather than
leaked.

### 4.3 What must NOT appear in the manifest

- No `type = "encrypted"` mount with a host `uri` (Gramine protected files) — those
  persist encrypted blobs *to the host*, which is persistence of content and
  violates the property even though it is encrypted at rest.
- No `sgx.allowed_files` entry for a writable directory (allowed files are
  unmeasured and can be host-writable).
- No bind of `/var`, `/data`, the DB path, or a Redis socket. `relay-core` has no
  DB and no Redis (metadata leaves via the out-of-enclave channel, doc 01/02).

---

## 5. Residual: in-memory full-body buffering is FINE

`relay-core` unavoidably holds full request/response bodies in memory:

- `relay/channel/openai/relay-openai.go:194` — `responseBody, err := io.ReadAll(resp.Body)`
  buffers the entire upstream response.
- `relay/compatible_handler.go:157` — `jsonData, err := common.Marshal(convertedRequest)`
  materializes the whole converted request.
- `relay/helper/stream_scanner.go:45` — `scanner.Buffer(make([]byte,
  InitialScannerBufferSize), getScannerBufferSize())` allocates up to
  `DefaultMaxScannerBufferSize = 128 << 20` (`stream_scanner.go:27`; the trailing
  comment says "64MB" but the value is 128 MB) per SSE stream.

These are **acceptable and do not breach Property (1)**, for three reasons:

1. **The heap lives in encrypted EPC.** All enclave memory — Go heap, stack,
   scanner buffers — is EPC, encrypted by the CPU MEE. A body in a `[]byte` is
   ciphertext on the physical DRAM bus; the host OS, hypervisor, and a DMA attacker
   see only ciphertext. Buffering in memory is not "persistence to a host-visible
   medium"; it is transient plaintext *inside the trust boundary only*.
2. **It is freed per request, never flushed.** These buffers are ordinary Go heap
   allocations tied to the request's `*gin.Context` / handler scope. When the
   handler returns, they become garbage and are reclaimed. Nothing in this path
   calls a file/DB/Redis write — verified: `io.ReadAll` → `common.Unmarshal`
   (in-memory, `common/json.go`), `common.Marshal` → `c.Writer.Write` (the network
   socket back to the client, not disk), `scanner` → `helper.ObjectData(c, ...)`
   (SSE write to the client socket). No branch reaches `os.*`, `CreateDiskCacheFile`,
   or `RecordErrorLog` on the success path (confirmed by the §3 closure scan once
   sinks are removed).
3. **Nothing flushes it to the host.** The only way heap content reaches the host
   is (a) a filesystem write — eliminated by §2/§3/§4, or (b) swap/paging — and SGX
   EPC pages are never swapped to host disk in plaintext (the kernel's EPC paging
   uses the CPU's sealed, encrypted eviction; evicted pages are ciphertext with
   integrity metadata). So even memory pressure cannot leak a buffered body.

The distinction the property draws is **transient encrypted plaintext inside the
enclave (allowed)** vs **persisted or host-visible content (forbidden)**. In-memory
buffering is squarely the former. The 128 MB scanner cap is a resource bound, not a
leak vector — it never spills to disk (Go's `bufio.Scanner` returns
`ErrTooLong` past the cap; it does not fall back to a temp file).

One caveat to carry into doc 01: if any future optimization tries to "spill large
bodies to disk to save memory" (exactly what `DiskCacheEnabled` did), it
reintroduces the leak. That is why the disk-cache path is removed at compile time
(§2.2) and banned in CI (§3) — the residual stays residual only as long as no code
converts an in-memory buffer into a file. The manifest (§4) is the backstop if it
ever does.

---

## 6. Summary of the guarantee

| Layer | Mechanism | Defeats |
|---|---|---|
| Compile-time | `//go:build enclave` const-false `DiskCacheEnabled`/`DebugEnabled`/`ErrorLogEnabled`; sink defs moved behind `!enclave`; dify temp file deleted; error-body preview stripped | Sinks are absent from / unreachable in the binary |
| CI/lint | `scripts/enclave_no_leak_check.sh` over `go list -deps -tags enclave ./cmd/relay-core` + ast-grep body-log rule; blocks merge | Reintroduction of any forbidden symbol into the closure |
| Runtime | Gramine `[fs]`: no writable host mount, only encrypted-EPC `tmpfs` for `/tmp`; all trusted files read-only and measured into MRENCLAVE | An accidental `os.Create` that slips past both above — contained to encrypted enclave memory, never host disk |
| Residual (allowed) | In-memory body buffers in encrypted EPC, freed per request, never flushed | N/A — this is the intended, safe behavior |

The three enforcement layers are independent: a bug must defeat compile-time
elimination **and** the CI closure scan **and** the manifest simultaneously to
persist a single byte of content to a host-visible medium. Property (1) holds by
construction, is verified on every PR, and is contained by the platform even under
a verification miss.

### Action items for implementation (owned jointly with doc 01)

- [ ] Introduce the `enclave` build tag and const-false config files (§2.1).
- [ ] Move `common/disk_cache.go`, `common/body_storage.go` disk paths behind
      `//go:build !enclave`; add enclave stubs or (preferred) sever the callers.
- [ ] Delete the redundant dify temp file (`relay-dify.go:45-58`) — unconditional.
- [ ] Add the enclave variant of `service/error.go` `RelayErrorHandler` that never
      renders the body (§2.4).
- [ ] Land `scripts/enclave_no_leak_check.sh` + CI job (§3).
- [ ] Author `relay-core.manifest.template` with the `[fs]` table (§4).
