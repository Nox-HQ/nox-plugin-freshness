# nox-plugin-freshness

Flags dependencies whose **provenance** is suspicious, rather than whose version
is known-vulnerable.

Track: **Supply Chain & Provenance** (`supply-chain`) · Risk class: `passive`

## Why this exists

nox's dependency coverage is OSV-backed: it answers *"does this version match a
published advisory"*. That is the right question for a CVE and the wrong one for
a package that turned hostile an hour ago.

On **2026-08-04** a worm compromised `keyv`, `file-entry-cache` and `flat-cache`
on npm. Checked hours later, OSV had **zero** advisories for all three:

```
keyv               advisories=0
file-entry-cache   advisories=0
flat-cache         advisories=0
lodash             advisories=10   ← control, the query works
```

So an OSV-backed scan of a backdoored tree reported clean. That is the expected
behaviour of a CVE scanner, not a defect in one — but it leaves a real gap, and
malicious releases are frequently *unpublished* rather than advised, so for many
of them an advisory never arrives at all.

## What it detects

Registry metadata carries signals that are live at the moment of compromise,
before anyone has written an advisory.

| rule | condition | severity |
|---|---|---|
| `FRESH-001` | resolved version published inside the review window (default 7 days) | medium |
| `FRESH-002` | the registry withdrew the version — npm unpublish, `latest` rolled backwards, Go `retract` | high |
| `FRESH-003` | a different account published this version than the previous one | medium |

Against the real registry, `keyv@6.0.0` reports:

```
published=2026-08-04T09:35:00Z  withdrawn=true
reason="the version is no longer published on the registry (unpublished or removed);
        registry `latest` is 5.6.0, below the pinned 6.0.0 — the tag was rolled back"
```

while `keyv@5.6.0` stays quiet — neither withdrawn nor fresh.

**None of these prove malice.** They say the circumstances warrant a look before
the version reaches a build.

## Ecosystems

| | publish time | withdrawal | publisher identity |
|---|---|---|---|
| npm | `time[version]` | unpublish + `dist-tags.latest` rollback | `_npmUser` per version |
| Go | proxy `@v/….info` → `Time` | `retract` in the module's latest `go.mod` | — not recorded per version |

`FRESH-003` is npm-only by necessity: Go versions are git tags with no
per-version publisher to compare, so maintainer takeover leaves no such trace.

Go is also structurally less exposed. It has no install-time hooks, so a
dependency cannot execute code merely by being downloaded, and `GOSUMDB` +
`go.sum` make retroactive tampering with a published version impossible. What
remains is the narrow case this plugin covers: a compromised maintainer tags a
**new** version and you upgrade into it.

## Usage

```bash
nox plugin call freshness scan workspace_root=. max_age_days=14
```

```yaml
# .nox.yaml — nox runs only the plugins named here
plugins:
  required:
    - nox/freshness
```

`FRESH-001` fires on legitimate fresh releases too. The highest-value placement
is an automated dependency-bump PR, where a freshly-published version is
precisely what is being proposed — rather than as a standing alarm on every
scan of an unchanged lockfile.

## Design notes

**Fingerprints are path-independent.** They derive from rule + ecosystem +
package + version, and nothing else. nox baselines are keyed by fingerprint, so
one that varies with the scan directory differs between a developer checkout, a
worktree and CI — which makes a reviewed finding impossible to accept durably.
There is a regression test for this.

**An unreachable registry is not a clean result.** Every lookup carries a
`Checked` flag, and unchecked dependencies are reported as a warning naming the
count. A scan that checked nothing must never be reported as a scan that found
nothing — the same failure this plugin exists to close, one layer up.

A `package-lock.json` older than v2 is rejected with an explicit error rather
than silently contributing zero dependencies.

## Development

```bash
make build
make test                                          # hermetic; no network
FRESHNESS_LIVE=1 go test -run TestLive -v ./...    # queries npm + proxy.golang.org
```

Live tests are gated so CI stays hermetic: a scanner whose suite depends on npm
being up goes red for reasons unrelated to its code.

## License

Apache-2.0
