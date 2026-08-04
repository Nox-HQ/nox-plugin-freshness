package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// provenance is what a registry can tell us about one pinned version without
// looking at its code.
//
// Checked is the field that matters most. A registry that could not be reached
// must not read as a package with nothing wrong: every consumer of this struct
// has to distinguish "asked and it was fine" from "never got an answer".
type provenance struct {
	Checked     bool
	Err         error
	PublishedAt time.Time

	// Withdrawn covers npm unpublish, a `latest` tag rolled backwards, Go
	// retractions — anything the registry says about a version it no longer
	// stands behind.
	Withdrawn       bool
	WithdrawnReason string

	// Publisher is the identity that pushed this version, where the ecosystem
	// records one per version. Go and Cargo do not, so this stays empty there.
	Publisher     string
	PrevPublisher string
	PrevVersion   string
}

type client struct {
	http  *http.Client
	cache map[string]*npmPackument

	// Overridable so the tests can drive both registries from httptest and
	// assert on responses this code will actually meet in production.
	npmBase string
	goBase  string
}

func newClient() *client {
	return &client{
		http:    &http.Client{Timeout: 20 * time.Second},
		cache:   map[string]*npmPackument{},
		npmBase: "https://registry.npmjs.org",
		goBase:  "https://proxy.golang.org",
	}
}

func (c *client) lookup(ctx context.Context, d dep) provenance {
	switch d.Ecosystem {
	case "npm":
		return c.lookupNPM(ctx, d)
	case "go":
		return c.lookupGo(ctx, d)
	default:
		return provenance{Err: fmt.Errorf("unsupported ecosystem %q", d.Ecosystem)}
	}
}

// ---------- npm ----------

type npmPackument struct {
	DistTags map[string]string `json:"dist-tags"`
	Time     map[string]string `json:"time"`
	Versions map[string]struct {
		NPMUser struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
	} `json:"versions"`
}

func (c *client) packument(ctx context.Context, name string) (*npmPackument, error) {
	if p, ok := c.cache[name]; ok {
		return p, nil
	}
	// A scoped name (@scope/pkg) must keep its slash encoded, or the registry
	// reads it as a path segment and 404s.
	endpoint := c.npmBase + "/" + strings.Replace(url.PathEscape(name), "%2F", "%2f", 1)
	body, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var p npmPackument
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	c.cache[name] = &p
	return &p, nil
}

func (c *client) lookupNPM(ctx context.Context, d dep) provenance {
	p, err := c.packument(ctx, d.Name)
	if err != nil {
		return provenance{Err: err}
	}

	out := provenance{Checked: true}

	if ts, ok := p.Time[d.Version]; ok {
		if t, pErr := time.Parse(time.RFC3339, ts); pErr == nil {
			out.PublishedAt = t
		}
	}

	// Both checks below can be true at once — a compromised version is often
	// unpublished *and* leaves `latest` pointing backwards. Reasons accumulate
	// rather than overwrite: the second one used to clobber the first, which
	// hid the more specific fact behind the more generic one.
	var reasons []string

	// Gone from the versions map: unpublished or removed by npm. This is the
	// state a package lands in once a compromise is confirmed, and it happens
	// well before any advisory is written.
	if _, present := p.Versions[d.Version]; !present {
		reasons = append(reasons, "the version is no longer published on the registry (unpublished or removed)")
	}

	// `latest` pointing below the pinned version means the tag was rolled
	// backwards — the registry has stopped recommending what we install.
	if latest := p.DistTags["latest"]; latest != "" && semver.IsValid("v"+latest) && semver.IsValid("v"+d.Version) {
		if semver.Compare("v"+d.Version, "v"+latest) > 0 {
			reasons = append(reasons, fmt.Sprintf("registry `latest` is %s, below the pinned %s — the tag was rolled back", latest, d.Version))
		}
	}

	if len(reasons) > 0 {
		out.Withdrawn = true
		out.WithdrawnReason = strings.Join(reasons, "; ")
	}

	out.Publisher = p.Versions[d.Version].NPMUser.Name
	if prev := previousVersion(p, d.Version); prev != "" {
		out.PrevVersion = prev
		out.PrevPublisher = p.Versions[prev].NPMUser.Name
	}

	return out
}

// previousVersion finds the highest published release below ver, ignoring
// prereleases so an alpha does not become the comparison point for a stable.
func previousVersion(p *npmPackument, ver string) string {
	best := ""
	for v := range p.Versions {
		if !semver.IsValid("v"+v) || semver.Prerelease("v"+v) != "" {
			continue
		}
		if semver.Compare("v"+v, "v"+ver) >= 0 {
			continue
		}
		if best == "" || semver.Compare("v"+v, "v"+best) > 0 {
			best = v
		}
	}
	return best
}

// ---------- Go ----------

type goVersionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

func (c *client) lookupGo(ctx context.Context, d dep) provenance {
	// Module paths are case-folded for the proxy: an uppercase letter becomes
	// "!" + lowercase, so github.com/BurntSushi -> github.com/!burnt!sushi.
	escPath, err := module.EscapePath(d.Name)
	if err != nil {
		return provenance{Err: err}
	}
	escVer, err := module.EscapeVersion(d.Version)
	if err != nil {
		return provenance{Err: err}
	}
	base := c.goBase + "/" + escPath

	body, err := c.get(ctx, base+"/@v/"+escVer+".info")
	if err != nil {
		return provenance{Err: err}
	}
	var info goVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return provenance{Err: err}
	}

	out := provenance{Checked: true, PublishedAt: info.Time}

	// Go has no unpublish. Withdrawal is expressed as a `retract` directive in
	// the module's own latest go.mod, which is a stronger signal than npm's:
	// the author states it explicitly rather than it being inferred.
	if reason, retracted := c.goRetracted(ctx, base, d.Version); retracted {
		out.Withdrawn = true
		out.WithdrawnReason = reason
	}

	return out
}

func (c *client) goRetracted(ctx context.Context, base, version string) (string, bool) {
	latest, err := c.get(ctx, base+"/@latest")
	if err != nil {
		return "", false
	}
	var li goVersionInfo
	if err := json.Unmarshal(latest, &li); err != nil || li.Version == "" {
		return "", false
	}
	escLatest, err := module.EscapeVersion(li.Version)
	if err != nil {
		return "", false
	}
	modBytes, err := c.get(ctx, base+"/@v/"+escLatest+".mod")
	if err != nil {
		return "", false
	}
	f, err := modfile.Parse("go.mod", modBytes, nil)
	if err != nil {
		return "", false
	}
	for _, r := range f.Retract {
		if r == nil {
			continue
		}
		if semver.Compare(version, r.Low) >= 0 && semver.Compare(version, r.High) <= 0 {
			reason := strings.TrimSpace(r.Rationale)
			if reason == "" {
				reason = "no rationale given"
			}
			return "retracted by the module author in " + li.Version + ": " + reason, true
		}
	}
	return "", false
}

// ---------- shared ----------

func (c *client) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nox-plugin-freshness")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", endpoint, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
