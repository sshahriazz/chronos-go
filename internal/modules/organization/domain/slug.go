package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxSlugLen bounds the URL name.
//
// The published bound and the refused request are one number: this constant is
// what the protovalidate rule in the .proto is written from, and what the
// OpenAPI document publishes.
const MaxSlugLen = 48

// MinSlugLen keeps a slug distinguishable and typeable.
const MinSlugLen = 3

// slugRule is the shape a slug may take.
//
// Lowercase, digits and single hyphens, starting and ending alphanumeric. The
// restrictions are not cosmetic:
//
//   - No uppercase, so `acme` and `ACME` cannot be two organizations. The
//     reservation stream is named from the slug, and two casings would be two
//     streams naming one URL.
//   - No leading or trailing hyphen, and no doubled hyphen, so a slug cannot be
//     confused with the delimiters around it.
//   - No underscore, which is what ADR-030 reserves to separate a prefix from
//     a public id.
var slugRule = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// reservedSlugs are names that would collide with routes or impersonate the
// operator.
//
// Blocked here rather than in a route table, because the check has to happen
// where the claim is made: a slug reserved after the fact is a slug somebody
// already holds.
var reservedSlugs = map[string]bool{
	"admin": true, "api": true, "app": true, "auth": true, "billing": true,
	"chronos": true, "dashboard": true, "docs": true, "help": true,
	"internal": true, "login": true, "logout": true, "new": true,
	"operator": true, "public": true, "root": true, "settings": true,
	"signup": true, "static": true, "status": true, "support": true,
	"system": true, "www": true,
}

// NewSlug validates and normalises an organization's URL name.
//
// Normalisation is lowercasing and trimming only. It deliberately does NOT
// rewrite a bad slug into a good one — turning "Acme Corp!" into "acme-corp"
// silently gives somebody a URL they did not choose, and the two-way ambiguity
// that creates is how one organization ends up able to claim another's name.
func NewSlug(raw string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case slug == "":
		return "", fmt.Errorf("organization: a slug is required")
	case len(slug) < MinSlugLen:
		return "", fmt.Errorf("organization: %q is shorter than %d characters", slug, MinSlugLen)
	case len(slug) > MaxSlugLen:
		return "", fmt.Errorf("organization: a slug may not exceed %d characters", MaxSlugLen)
	case !slugRule.MatchString(slug):
		return "", fmt.Errorf("organization: %q may contain only lowercase letters, digits "+
			"and single hyphens, and must start and end with a letter or digit", slug)
	case reservedSlugs[slug]:
		return "", fmt.Errorf("organization: %q is reserved", slug)
	}
	return slug, nil
}

// MaxNameLen bounds the display name.
const MaxNameLen = 80

// NewName validates an organization's display name.
//
// Unlike the slug it is free text, so the rules are only the ones that stop it
// being unusable: not empty, not padded, and bounded.
func NewName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	switch {
	case name == "":
		return "", fmt.Errorf("organization: a name is required")
	case len(name) > MaxNameLen:
		return "", fmt.Errorf("organization: a name may not exceed %d characters", MaxNameLen)
	}
	return name, nil
}
