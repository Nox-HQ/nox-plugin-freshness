// nox-plugin-freshness flags dependencies whose provenance is suspicious
// rather than whose version is known-vulnerable.
//
// The gap it fills: nox's dependency coverage is OSV-backed, so it answers
// "does this version match a published advisory". On 2026-08-04 a worm
// compromised keyv, file-entry-cache and flat-cache on npm. Hours later OSV
// still had zero advisories for all three, so an OSV-backed scan of a
// backdoored tree reported clean — and that is the expected behaviour, not a
// bug. A legitimate package that turned hostile an hour ago is a different
// detection problem from a version with a CVE.
//
// What is observable at that moment, from registry metadata alone:
//
//	FRESH-001  the version is hours old          keyv@6.0.0, published 09:35 that day
//	FRESH-002  the registry withdrew the version  npm rolled `latest` back to 5.6.0
//	FRESH-003  a different account published it   maintainer-account takeover
//
// None of these prove malice; each says the circumstances warrant a look
// before the version reaches a build.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

const (
	defaultMaxAgeDays = 7
	maxConcurrency    = 8
)

func main() {
	manifest := sdk.NewManifest("freshness", version).
		Capability("freshness", "Dependency provenance: version age, registry withdrawal, publisher changes").
		Tool("scan", "Flag dependencies whose provenance is suspicious", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive),
			sdk.WithNetworkHosts("registry.npmjs.org", "proxy.golang.org")).
		Build()

	srv := sdk.NewPluginServer(manifest).HandleTool("scan", handleScan)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := srv.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	maxAge := durationInput(req, "max_age_days", defaultMaxAgeDays)
	now := time.Now().UTC()

	deps, lockfiles, err := collectDeps(req.WorkspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("collect dependencies: %w", err)
	}

	resp := sdk.NewResponse()

	if len(lockfiles) == 0 {
		// Distinct from "scanned and found nothing": there was nothing to scan.
		return resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO,
			"no package-lock.json or go.mod found; nothing to check", "freshness").Build(), nil
	}

	results := lookupAll(ctx, deps)

	var unchecked []string
	for _, d := range deps {
		p := results[d.key()]

		if !p.Checked {
			unchecked = append(unchecked, fmt.Sprintf("%s (%v)", d.key(), p.Err))
			continue
		}

		resp.Package(d.Name, d.Version, d.Ecosystem)

		if p.Withdrawn {
			resp.Finding("FRESH-002",
				pluginv1.Severity_SEVERITY_HIGH,
				pluginv1.Confidence_CONFIDENCE_HIGH,
				fmt.Sprintf("%s %s@%s: %s. A registry withdraws a version before an advisory exists, so this fires while a CVE-based scan is still clean.",
					d.Ecosystem, d.Name, d.Version, p.WithdrawnReason)).
				At(d.File, d.Line, d.Line).
				WithFingerprint(fingerprint("FRESH-002", d)).
				WithMetadata("package", d.Name).
				WithMetadata("version", d.Version).
				WithMetadata("ecosystem", d.Ecosystem).
				Done()
		}

		if !p.PublishedAt.IsZero() {
			if age := now.Sub(p.PublishedAt); age < maxAge {
				resp.Finding("FRESH-001",
					pluginv1.Severity_SEVERITY_MEDIUM,
					pluginv1.Confidence_CONFIDENCE_MEDIUM,
					fmt.Sprintf("%s %s@%s was published %s ago (%s), inside the %s review window. Freshly published versions are where a compromised release lands before anyone has assessed it.",
						d.Ecosystem, d.Name, d.Version,
						humanDuration(age), p.PublishedAt.Format(time.RFC3339), humanDuration(maxAge))).
					At(d.File, d.Line, d.Line).
					WithFingerprint(fingerprint("FRESH-001", d)).
					WithMetadata("package", d.Name).
					WithMetadata("version", d.Version).
					WithMetadata("published_at", p.PublishedAt.Format(time.RFC3339)).
					WithMetadata("age_hours", fmt.Sprintf("%.1f", age.Hours())).
					Done()
			}
		}

		// Only meaningful where the ecosystem records a per-version publisher,
		// and only when both sides are known: an empty field is missing data,
		// not evidence of a change.
		if p.Publisher != "" && p.PrevPublisher != "" && p.Publisher != p.PrevPublisher {
			resp.Finding("FRESH-003",
				pluginv1.Severity_SEVERITY_MEDIUM,
				pluginv1.Confidence_CONFIDENCE_MEDIUM,
				fmt.Sprintf("%s %s@%s was published by %q, but %s was published by %q. A change of publishing account is how a maintainer-account takeover first shows up.",
					d.Ecosystem, d.Name, d.Version, p.Publisher, p.PrevVersion, p.PrevPublisher)).
				At(d.File, d.Line, d.Line).
				WithFingerprint(fingerprint("FRESH-003", d)).
				WithMetadata("publisher", p.Publisher).
				WithMetadata("previous_publisher", p.PrevPublisher).
				Done()
		}
	}

	// The point of the plugin is that absence of findings should mean the
	// registry was asked. If it was not, say so loudly and name the count —
	// a scan that checked nothing must not be reported as a scan that found
	// nothing.
	if len(unchecked) > 0 {
		sort.Strings(unchecked)
		shown := unchecked
		if len(shown) > 5 {
			shown = shown[:5]
		}
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING,
			fmt.Sprintf("%d of %d dependencies could not be checked against their registry; their provenance is unknown, not clean. First: %v",
				len(unchecked), len(deps), shown),
			"freshness")
	}

	resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO,
		fmt.Sprintf("checked %d/%d dependencies from %d lockfile(s) against registry metadata",
			len(deps)-len(unchecked), len(deps), len(lockfiles)),
		"freshness")

	return resp.Build(), nil
}

// lookupAll queries registries concurrently but with a bounded worker count,
// so a large lockfile does not turn a scan into a burst of traffic.
func lookupAll(ctx context.Context, deps []dep) map[string]provenance {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make(map[string]provenance, len(deps))
		sem     = make(chan struct{}, maxConcurrency)
		c       = newClient()
	)

	for _, d := range deps {
		wg.Add(1)
		go func(d dep) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			p := c.lookup(ctx, d)

			mu.Lock()
			results[d.key()] = p
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return results
}

// fingerprint identifies a finding by what it is about, not where the scan ran.
//
// nox baselines are keyed by fingerprint, so anything derived from an absolute
// path produces a different value on a developer machine, in a worktree, and
// on a CI runner — which makes the finding impossible to accept durably. The
// inputs here are the rule and the package coordinates and nothing else.
func fingerprint(rule string, d dep) string {
	sum := sha256.Sum256([]byte(rule + "\x00" + d.Ecosystem + "\x00" + d.Name + "\x00" + d.Version))
	return hex.EncodeToString(sum[:])
}

func durationInput(req sdk.ToolRequest, key string, fallbackDays float64) time.Duration {
	days := fallbackDays
	if raw, ok := req.Input[key]; ok {
		switch v := raw.(type) {
		case float64:
			days = v
		case int:
			days = float64(v)
		}
	}
	return time.Duration(days * float64(24*time.Hour))
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}
