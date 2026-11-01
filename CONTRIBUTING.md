# Contributing

Bug reports, questions and ideas are welcome as
[issues](https://github.com/hyperdrophq/hyperdrop-server/issues); security problems are reported
privately, as [SECURITY.md](SECURITY.md) describes. Pull requests with code are not accepted yet: the contribution terms
are still being settled, so a patch is better described in an issue, and the fix is written here.

The rest of this file is what a change must keep, for anyone reading or building the code.

## Checks

```sh
(cd core && go vet ./... && go test ./...)
(cd server && go mod tidy -diff && go vet ./... && go vet -tags acme ./... && TZ=UTC go test -race ./...)
(cd server && go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./... && go run golang.org/x/vuln/cmd/govulncheck@latest ./...)
shellcheck platforms/synology/build-spk.sh platforms/synology/scripts/*
shellcheck core/provision/provision.sh platforms/linux/install.sh.in platforms/linux/build-installer.sh
shellcheck platforms/linux/build-server.sh platforms/linux/verify-release.sh
platforms/synology/build-spk.sh "$(mktemp -d)"
```

Go 1.27.3 or newer (the `go` line of `server/go.mod`), shellcheck 0.9.0. Every change carries a
test that fails without it.

This repository is published from HyperDrop's main repository, and that project's own CI runs
these checks on the published tree before every publish; this repository carries no CI of its
own.

## Rules a change must keep

- **The wire is a contract with installed apps.** A server keeps serving every request and
  response of a client one minor version behind it. A new route, or a field a client sends or
  reads, is a minor version; a new response field is `omitempty` and its absence means "off". The
  server refuses an unknown request field (`decodeRequest`), so a client never sends one to a
  server too old to know it. See `docs/api.md` § Versions and the client header.
- **A schema change must survive a rollback to the previous release.** An update path restarts
  the previous binary when the new one does not come healthy. A change the previous release
  ignores (a nullable column or a table no published statement names) is added at the same
  schema stamp in `metadb/additive.go`. From the second public release on, a rollback test checks
  it against the previous release's `metadb`, frozen by `metadb/prevrelease/freeze.sh`, which is
  generated and never edited.
- **A new public route** owes an entry in `server/internal/api/origins.go` (which origin serves
  it) and in `inboxcoverage_test.go` (proving a Receive Inbox stays hidden on it). Both tests fail
  open when forgotten, which is why they walk the router.
- **Every id and path** goes through `shareid.ValidID` and `shareid.ValidRelPath` before a query
  or a path is composed from it. Relative paths on the wire are Unicode NFC.
- **Rows are the truth.** Create writes the row first; a commit renames the staged part, then
  writes the row; delete removes the rows, then the directory. A crash between the steps leaves
  something a sweep repairs, never a row pointing at nothing it cannot explain.

## Style

`gofmt`, and code that reads like the code around it. Comments describe how the code works now:
the behaviour, the contract, or a constraint the code cannot show. The history of a change belongs
in its commit message, not in a comment.
