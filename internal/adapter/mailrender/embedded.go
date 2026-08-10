package mailrender

import (
	"context"
	"embed"
	"io/fs"
	"strings"
)

//go:embed templates
var embedded embed.FS

// Embedded is the built-in template set.
//
// Compiled into the binary rather than read from disk, for the same reason
// migrations are: an image cannot then drift from a mounted directory, and a
// deploy that forgot to ship a template fails at build time instead of the
// first time someone resets a password.
type Embedded struct{}

var _ Source = Embedded{}

func (Embedded) Templates(context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(embedded, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".tmpl") {
			return err
		}
		body, readErr := embedded.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		out[strings.TrimPrefix(p, "templates/")] = body
		return nil
	})
	return out, err
}

// Overlay layers operator-authored templates on top of the embedded set.
//
// This is what makes wording editable without a deploy. The embedded set stays
// the fallback, so an override that is deleted — or one that fails to parse and
// is rejected at load — leaves a working system rather than a silent gap.
type Overlay struct {
	Base     Source
	Override Source

	// OnOverrideError observes an unreachable override store. The fallback is
	// deliberate — outbound mail must not stop because a customisation table is
	// down — but a SILENT fallback would mean operator edits quietly stop
	// applying and nobody finds out.
	OnOverrideError func(error)
}

var _ Source = Overlay{}

func (o Overlay) Templates(ctx context.Context) (map[string][]byte, error) {
	base, err := o.Base.Templates(ctx)
	if err != nil {
		return nil, err
	}
	if o.Override == nil {
		return base, nil
	}
	over, err := o.Override.Templates(ctx)
	if err != nil {
		// Deliberate: an unreachable override store must not take down outbound
		// mail. Reported rather than swallowed, so the degradation is visible.
		if o.OnOverrideError != nil {
			o.OnOverrideError(err)
		}
		//nolint:nilerr // falling back to the embedded set is the intended outcome
		return base, nil
	}
	for k, v := range over {
		base[k] = v
	}
	return base, nil
}
