package oidc

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Registry holds the configured providers by name.
//
// # Why a registry and not one provider per call site
//
// Discovery is a network round trip, and doing it per request would make an
// outage at any provider an outage here even for the requests that could have
// been served. Building them once at startup also means a misconfigured provider
// fails where somebody is watching rather than when a person clicks a button.
type Registry struct{ providers map[string]*Provider }

// NewRegistry builds every named provider.
//
// A provider that cannot be discovered is a FATAL configuration error rather
// than a silently absent button: the operator asked for it, and starting without
// it would leave a deployment that looks configured and refuses every sign-in
// through it.
func NewRegistry(ctx context.Context, configs map[string]Config) (*Registry, error) {
	r := &Registry{providers: make(map[string]*Provider, len(configs))}
	for name, cfg := range configs {
		p, err := New(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("oidc: provider %q: %w", name, err)
		}
		r.providers[name] = p
	}
	return r, nil
}

// Names lists the configured providers, sorted so a client renders them in a
// stable order rather than whatever the map yields.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.providers))
	for name := range r.providers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Get returns one provider.
func (r *Registry) Get(name string) (*Provider, bool) {
	p, ok := r.providers[strings.ToLower(name)]
	return p, ok
}
