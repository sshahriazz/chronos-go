package main

import (
	"io/fs"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestThePublishedDocumentOffersNoCleartextServer is the assertion behind
// proto/openapi.base.yaml's warning.
//
// The one credential this API has is a bearer token, and a bearer token is a
// password. `http://localhost:8090` was the FIRST entry in `servers`, which
// published "the default way to call this API is over a channel that does not
// protect the credential it carries". It is not coming back, and this is what
// stops it: the embedded artefact is the same bytes CI publishes and an auditor
// reads.
func TestThePublishedDocumentOffersNoCleartextServer(t *testing.T) {
	t.Parallel()

	for _, entry := range serversIn(t, embeddedSpec(t)) {
		if strings.HasPrefix(strings.ToLower(entry), "http://") {
			t.Errorf("the published document declares %s", entry)
		}
	}
}

// TestTheServedDocumentOffersTheLocalStack is the other half, and it is why
// removing the entry above cost nothing.
//
// A docs UI whose "Try it" button points at staging is a docs UI nobody uses
// locally. The local server is injected at SERVE time, by this binary, which
// only ever runs beside a dev stack.
func TestTheServedDocumentOffersTheLocalStack(t *testing.T) {
	t.Parallel()

	served := withLocalServer(embeddedSpec(t), "8090")
	entries := serversIn(t, served)

	if len(entries) == 0 {
		t.Fatal("the served document declares no servers at all")
	}
	if entries[0] != "http://localhost:8090" {
		t.Errorf("the first server is %q; the local stack must come first or the docs UI "+
			"sends every trial request to staging", entries[0])
	}
}

// TestInjectionIsNotWrittenBack pins the property that keeps the two documents
// one file apart: the injection is a serve-time copy, never a mutation.
func TestInjectionIsNotWrittenBack(t *testing.T) {
	t.Parallel()

	original := embeddedSpec(t)
	before := string(original)
	_ = withLocalServer(original, "8090")

	if string(original) != before {
		t.Error("withLocalServer mutated the embedded document")
	}
}

// TestADocumentWithoutServersIsServedUnchanged covers the branch that must not
// panic: a generator fault is checkopenapi's to report, and degrading the docs
// UI a second time here would add nothing.
func TestADocumentWithoutServersIsServedUnchanged(t *testing.T) {
	t.Parallel()

	in := []byte("openapi: 3.1.0\npaths: {}\n")
	if got := withLocalServer(in, "8090"); string(got) != string(in) {
		t.Errorf("a document with no servers block was rewritten:\n%s", got)
	}
}

func embeddedSpec(t *testing.T) []byte {
	t.Helper()
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		t.Fatalf("embedded assets unavailable: %v", err)
	}
	raw, err := fs.ReadFile(sub, "openapi.yaml")
	if err != nil {
		t.Fatalf("the embedded OpenAPI document is missing — run `make api-docs`: %v", err)
	}
	return raw
}

func serversIn(t *testing.T, spec []byte) []string {
	t.Helper()
	var doc struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		t.Fatalf("the document is not parseable YAML: %v", err)
	}
	out := make([]string, 0, len(doc.Servers))
	for _, s := range doc.Servers {
		out = append(out, s.URL)
	}
	return out
}
