# Monthly Maintenance Checklist

SimpleAuth does **not** use Dependabot or any other update bot. Dependencies are reviewed and updated by a maintainer **once a month**, using this checklist. Do the steps in order. Every command is run from the repository root unless a step says otherwise.

**What you need:** Go (the version in `go.mod`), Node.js 20+, Python 3.11+, Docker, the GitHub CLI (`gh`, logged in), and optionally the .NET 8 SDK.

The `govulncheck` job in CI (`.github/workflows/security.yml`) still runs on every push and pull request and **every Monday at 06:00 UTC**. It fails the build if the Go code reaches a known vulnerability, so an urgent Go security fix will show up there between monthly checks.

---

## 1. Start from an up-to-date `master` on a new branch

```bash
git checkout master
git pull --ff-only
git checkout -b chore/monthly-maintenance-$(date +%Y-%m)
```

## 2. Go toolchain

The Go version appears in **three places**, and they must always move together:

| File | What to change | Example |
|---|---|---|
| `go.mod` | the `go` line | `go 1.26.8` |
| `Dockerfile` | the builder image | `FROM golang:1.26-alpine AS builder` |
| `.github/workflows/security.yml` | the `govulncheck` version, if a newer one supports your Go version | `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0` |

1. Find the newest **patch** release of your current Go minor version (always use the latest patch — `.0` releases usually have known vulnerabilities):

   ```bash
   curl -s 'https://go.dev/dl/?mode=json' | python3 -c "import json,sys; print([r['version'] for r in json.load(sys.stdin)])"
   ```

2. Set it in `go.mod` (replace `1.26.8` with the version you found):

   ```bash
   go mod edit -go=1.26.8
   ```

3. Moving to a new **minor** version (e.g. 1.26 → 1.27) is a bigger change: also update the `Dockerfile` builder tag, and add an upgrade note to `CHANGELOG.md` ("building from source now requires Go 1.27").

4. Check whether a newer `govulncheck` exists and which Go version it needs:

   ```bash
   curl -s https://proxy.golang.org/golang.org/x/vuln/@latest
   curl -s https://proxy.golang.org/golang.org/x/vuln/@v/<VERSION>.mod | grep '^go '
   ```

   Only move the pin in `security.yml` if that `go` line is **not newer** than the one in `go.mod`.

## 3. Go server dependencies

```bash
go list -m -u all | grep '\['          # lists modules that have a newer version in [brackets]
go get -u ./...                         # update direct + indirect deps to the latest minor/patch
go mod tidy
git diff go.mod                         # review every version change
```

- If `go get` changes the `go` line in `go.mod`, a dependency now needs a newer Go. Do step 2 for that version instead of accepting whatever `.0` it picked.
- Do not take a new **major** version (a `/v2`, `/v3` … import path) without reading its release notes.

Run the vulnerability scanner (use the same version as `security.yml`):

```bash
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Exit code `0` means no reachable vulnerabilities. Anything else: update the module named in the output (or Go itself, if it says "Standard library").

## 4. Go SDK (`sdk/go`)

```bash
cd sdk/go
go list -m -u all | grep '\['
go get -u ./... && go mod tidy
go build ./... && go vet ./...
cd ../..
```

## 5. JavaScript / TypeScript SDK (`sdk/js`)

```bash
cd sdk/js
npm outdated                 # shows current vs latest for typescript and @types/node
npm install --save-dev typescript@latest @types/node@latest
npm run typecheck            # must pass
cd ../..
```

## 6. Python SDK (`sdk/python`)

The minimum versions live in `sdk/python/pyproject.toml`: `dependencies` (`requests`, `cryptography`), `[project.optional-dependencies]` (`fastapi`, `starlette`, `flask`, `django`), and `[build-system] requires` (`setuptools`). For each package, check the latest release:

```bash
python3 -m pip index versions requests
python3 -m pip index versions cryptography
# …repeat for fastapi, starlette, flask, django, setuptools
```

Raise a `>=` lower bound only when the newer version fixes a security issue or is needed. Then confirm the package still installs and imports:

```bash
python3 -m venv /tmp/sa-venv && /tmp/sa-venv/bin/pip install ./sdk/python \
  && /tmp/sa-venv/bin/python -c "import simpleauth; print('ok')"
```

## 7. .NET SDK (`sdk/dotnet`)

The .NET SDK currently has no NuGet package references. Only check that it still builds (needs the .NET 8 SDK; CI also does this):

```bash
dotnet build sdk/dotnet/SimpleAuth.csproj -c Release
```

## 8. GitHub Actions

Every action in `.github/workflows/*.yml` is pinned to a **full commit SHA** with the version in a comment, e.g.:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

1. List what is in use:

   ```bash
   grep -rhoE 'uses: [^ ]+@[^ ]+ # [^ ]+' .github/workflows | sort -u
   ```

2. For each action, find the latest release tag (replace `actions/checkout`):

   ```bash
   gh release view --repo actions/checkout --json tagName -q .tagName
   ```

   For `github/codeql-action`, `gh release view` returns a `codeql-bundle-…` tag, which is **not** the action version. Use this instead:

   ```bash
   gh api 'repos/github/codeql-action/tags?per_page=100' --jq '.[].name' | grep -E '^v4\.[0-9]+\.[0-9]+$' | sort -V | tail -1
   ```

3. Get the commit SHA for that tag and replace **both** the SHA and the `# vX.Y.Z` comment on every line that uses the action:

   ```bash
   gh api repos/actions/checkout/commits/v7.0.1 --jq .sha
   ```

   `github/codeql-action/init`, `/autobuild`, and `/analyze` must always use the **same** SHA.

## 9. Test everything

All of these must pass before you open the pull request:

```bash
go vet ./...
go test -race -count=1 ./...
make -C test/integration test            # full Docker integration suite (real LDAP, central + standalone); tears itself down
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
(cd sdk/go && go build ./... && go vet ./...)
(cd sdk/js && npm install && npm run typecheck)
docker build -t simpleauth:maintenance-check .
```

The integration suite is **not** run by CI, so running it here is the only place it runs.

## 10. Open the pull request

```bash
git add -A
git commit -m "chore: monthly maintenance $(date +%Y-%m)"
git push -u origin HEAD
gh pr create --base master --title "chore: monthly maintenance $(date +%Y-%m)" \
  --body "Monthly dependency + toolchain update. All steps of docs/MAINTENANCE.md done; tests pass."
```

Merge after CI is green. In `CHANGELOG.md`, add a line under the next version's `### Changed` (or `### Security`, if you fixed a vulnerability) listing what was updated.

## 11. Releasing (only when you want a new version)

1. Make sure `CHANGELOG.md` has a section `## vX.Y.Z` for the new version. The release workflow publishes that section as the top of the GitHub Release notes, so write it for operators: highlights, upgrade notes, security fixes.
2. Set the same version in the `VERSION` file (no `v`, e.g. `2.3.0`), commit, and merge to `master`.
3. Tag and push the tag from an up-to-date `master`:

   ```bash
   git checkout master && git pull --ff-only
   make tag            # creates and pushes tag v$(cat VERSION)
   ```

4. Watch the release run: `gh run watch` (or the repository's **Actions** tab). It builds the binaries and Docker image and creates the GitHub Release.
