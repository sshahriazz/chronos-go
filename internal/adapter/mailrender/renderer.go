// Package mailrender turns a mail.Request into a rendered message.
//
// It uses html/template for the HTML part and text/template for the subject and
// plaintext part. That choice is deliberate and is a security decision, not a
// preference: html/template is CONTEXTUALLY auto-escaping — it knows whether a
// value is landing in an attribute, a URL, a style or a script, and escapes for
// that position. A workspace name of `"><script>` reaches an email body as text,
// not as markup. No general-purpose template engine gives that, and email HTML
// is exactly where user-supplied names end up.
//
// Templates are loaded from a Source rather than compiled in, so an operator can
// later override wording without a deploy. The embedded set is the default and
// the fallback.
package mailrender

import (
	"bytes"
	"context"
	"fmt"
	htmltemplate "html/template"
	"path"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"

	"github.com/chronos/chronos-go/internal/platform/mail"
)

// Source supplies template files, keyed by path.
//
// A port so the embedded set, a database of operator overrides and a test
// fixture are interchangeable. Paths look like "en/identity.welcome.html.tmpl".
type Source interface {
	Templates(ctx context.Context) (map[string][]byte, error)
}

// Renderer renders messages in the recipient's locale and timezone.
//
// Safe for concurrent use. Reload swaps the whole template set atomically, so a
// half-loaded set is never visible — a partially parsed set would render some
// messages with the old wording and some with the new.
type Renderer struct {
	source   Source
	from     mail.Address
	replyTo  mail.Address
	baseURL  string
	fallback string

	mu  sync.RWMutex
	set *templateSet
}

// Config is what a renderer needs beyond its templates.
type Config struct {
	// From is the envelope sender shown to recipients.
	From mail.Address

	// ReplyTo is optional; empty means replies go to From.
	ReplyTo mail.Address

	// BaseURL builds absolute links. Email clients do not resolve relative
	// URLs, so every link must be absolute or it is dead.
	BaseURL string

	// FallbackLocale is used when the recipient's locale has no template.
	// Empty defaults to "en".
	FallbackLocale string
}

func New(src Source, cfg Config) *Renderer {
	if cfg.FallbackLocale == "" {
		cfg.FallbackLocale = "en"
	}
	return &Renderer{
		source:   src,
		from:     cfg.From,
		replyTo:  cfg.ReplyTo,
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		fallback: cfg.FallbackLocale,
	}
}

var _ mail.Renderer = (*Renderer)(nil)

// Load parses every template. Call at startup; a failure here is a wiring bug
// and must stop the process rather than surface as a broken email later.
func (r *Renderer) Load(ctx context.Context) error {
	files, err := r.source.Templates(ctx)
	if err != nil {
		return fmt.Errorf("mailrender: reading templates: %w", err)
	}
	set, err := parse(files, r.funcs())
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.set = set
	r.mu.Unlock()
	return nil
}

// Reload re-parses from the source without dropping the current set on failure.
// This is what makes operator-edited wording possible without a restart.
func (r *Renderer) Reload(ctx context.Context) error { return r.Load(ctx) }

// Templates lists the loaded template names, for a startup log or an operator
// screen showing what can be overridden.
func (r *Renderer) Templates() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.set == nil {
		return nil
	}
	return r.set.names()
}

// Render produces the message.
func (r *Renderer) Render(_ context.Context, req mail.Request) (mail.Message, error) {
	if err := req.Validate(); err != nil {
		return mail.Message{}, err
	}

	r.mu.RLock()
	set := r.set
	r.mu.RUnlock()
	if set == nil {
		return mail.Message{}, fmt.Errorf("mailrender: templates are not loaded")
	}

	locale := set.resolveLocale(req.Template, req.Recipient.Locale, r.fallback)
	tpl, ok := set.lookup(locale, req.Template)
	if !ok {
		return mail.Message{}, fmt.Errorf("%w: %q", mail.ErrUnknownTemplate, req.Template)
	}

	data := r.viewData(req, locale)

	subject, err := renderText(tpl.subject, data)
	if err != nil {
		return mail.Message{}, fmt.Errorf("mailrender: subject of %s: %w", req.Template, err)
	}
	// A subject with a newline in it can inject arbitrary headers. Collapsing
	// whitespace is both cosmetic and the fix for that.
	subject = strings.Join(strings.Fields(subject), " ")
	if subject == "" {
		return mail.Message{}, fmt.Errorf("mailrender: %s produced an empty subject", req.Template)
	}

	text, err := renderText(tpl.text, data)
	if err != nil {
		return mail.Message{}, fmt.Errorf("mailrender: text body of %s: %w", req.Template, err)
	}

	var html bytes.Buffer
	if err := tpl.html.ExecuteTemplate(&html, "base", data); err != nil {
		return mail.Message{}, fmt.Errorf("mailrender: html body of %s: %w", req.Template, err)
	}

	msg := mail.Message{
		From:     r.from,
		ReplyTo:  r.replyTo,
		To:       mail.Address{Name: req.Recipient.Name, Email: req.Recipient.Address},
		Subject:  subject,
		HTML:     html.String(),
		Text:     strings.TrimSpace(text) + "\n",
		Class:    req.Class,
		Template: req.Template,
		Headers:  map[string]string{},
	}

	// Auto-submitted tells other mail systems not to reply with vacation
	// responders — an out-of-office bouncing off a password-reset address is
	// noise at best and a loop at worst.
	msg.Headers["Auto-Submitted"] = "auto-generated"
	msg.Headers["X-Chronos-Class"] = req.Class.String()
	msg.Headers["X-Chronos-Template"] = req.Template

	if req.Class.RequiresUnsubscribe() {
		// One-click unsubscribe. Security and Transactional mail deliberately
		// omits this: a user cannot opt out of being told their password
		// changed (notification.md §6).
		if url, ok := data["UnsubscribeURL"].(string); ok && url != "" {
			msg.Headers["List-Unsubscribe"] = "<" + url + ">"
			msg.Headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
		}
	}
	return msg, nil
}

// viewData assembles what templates may reference.
//
// Recipient data is passed as fields rather than merged into Data, so a caller
// cannot accidentally shadow Name or Email with attacker-influenced input from
// an event payload.
func (r *Renderer) viewData(req mail.Request, locale string) map[string]any {
	occurred := req.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	loc := time.UTC
	if req.Recipient.Timezone != "" {
		if l, err := time.LoadLocation(req.Recipient.Timezone); err == nil {
			loc = l
		}
	}

	data := map[string]any{
		"Name":       req.Recipient.Name,
		"Email":      req.Recipient.Address,
		"Locale":     locale,
		"Timezone":   loc.String(),
		"BaseURL":    r.baseURL,
		"Class":      req.Class.String(),
		"OccurredAt": occurred.In(loc),
		"Year":       occurred.In(loc).Year(),
	}
	// Caller data cannot overwrite the fields above.
	for k, v := range req.Data {
		if _, reserved := data[k]; reserved {
			continue
		}
		data[k] = v
	}
	return data
}

func (r *Renderer) funcs() map[string]any {
	return map[string]any{
		// url builds an absolute link. Email clients do not resolve relative
		// URLs, so a template that forgets this produces a dead link.
		"url": func(p string) string {
			return r.baseURL + "/" + strings.TrimLeft(p, "/")
		},
		// datetime renders an instant already converted to the reader's zone.
		"datetime": func(t time.Time) string { return t.Format("2 January 2006 at 15:04 MST") },
		"date":     func(t time.Time) string { return t.Format("2 January 2006") },
		"upper":    strings.ToUpper,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
	}
}

// ---------------------------------------------------------------------------
// template set
// ---------------------------------------------------------------------------

type compiled struct {
	subject *texttemplate.Template
	text    *texttemplate.Template
	html    *htmltemplate.Template
}

type templateSet struct {
	// byLocale[locale][name]
	byLocale map[string]map[string]*compiled
}

func (s *templateSet) lookup(locale, name string) (*compiled, bool) {
	m, ok := s.byLocale[locale]
	if !ok {
		return nil, false
	}
	c, ok := m[name]
	return c, ok
}

// resolveLocale walks the fallback chain: "de-AT" → "de" → the configured
// fallback. A missing regional variant must not mean a missing email.
func (s *templateSet) resolveLocale(name, want, fallback string) string {
	for _, candidate := range localeChain(want, fallback) {
		if m, ok := s.byLocale[candidate]; ok {
			if _, ok := m[name]; ok {
				return candidate
			}
		}
	}
	return fallback
}

func localeChain(want, fallback string) []string {
	var out []string
	if want != "" {
		out = append(out, want)
		if i := strings.IndexAny(want, "-_"); i > 0 {
			out = append(out, want[:i])
		}
	}
	return append(out, fallback)
}

func (s *templateSet) names() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range s.byLocale {
		for name := range m {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// parse compiles every template, composing each HTML body with the shared
// layout for its locale.
func parse(files map[string][]byte, funcs map[string]any) (*templateSet, error) {
	layouts := map[string]string{}
	for p, body := range files {
		if locale, kind, ok := layoutPath(p); ok && kind == "html" {
			layouts[locale] = string(body)
		}
	}

	set := &templateSet{byLocale: map[string]map[string]*compiled{}}

	for p, body := range files {
		locale, name, kind, ok := templatePath(p)
		if !ok || kind != "html" {
			continue
		}

		subjectSrc, ok := files[path.Join(locale, name+".subject.tmpl")]
		if !ok {
			return nil, fmt.Errorf("mailrender: %s/%s has no subject template", locale, name)
		}
		textSrc, ok := files[path.Join(locale, name+".txt.tmpl")]
		if !ok {
			// A plaintext alternative is not optional: HTML-only mail scores
			// badly with spam filters and is unreadable in text clients.
			return nil, fmt.Errorf("mailrender: %s/%s has no plaintext alternative", locale, name)
		}

		layout, ok := layouts[locale]
		if !ok {
			layout, ok = layouts["_"]
			if !ok {
				return nil, fmt.Errorf("mailrender: no layout for locale %q", locale)
			}
		}

		subject, err := texttemplate.New("subject").Funcs(funcs).Parse(string(subjectSrc))
		if err != nil {
			return nil, fmt.Errorf("mailrender: subject %s/%s: %w", locale, name, err)
		}
		text, err := texttemplate.New("text").Funcs(funcs).Parse(string(textSrc))
		if err != nil {
			return nil, fmt.Errorf("mailrender: text %s/%s: %w", locale, name, err)
		}
		html, err := htmltemplate.New("base").Funcs(funcs).Parse(layout)
		if err != nil {
			return nil, fmt.Errorf("mailrender: layout for %q: %w", locale, err)
		}
		if _, err := html.Parse(string(body)); err != nil {
			return nil, fmt.Errorf("mailrender: html %s/%s: %w", locale, name, err)
		}

		if set.byLocale[locale] == nil {
			set.byLocale[locale] = map[string]*compiled{}
		}
		set.byLocale[locale][name] = &compiled{subject: subject, text: text, html: html}
	}

	if len(set.byLocale) == 0 {
		return nil, fmt.Errorf("mailrender: no templates found")
	}
	return set, nil
}

// layoutPath matches "layouts/base.html.tmpl" and "layouts/en/base.html.tmpl".
func layoutPath(p string) (locale, kind string, ok bool) {
	if !strings.HasPrefix(p, "layouts/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(p, "layouts/")
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		locale = "_" // shared by every locale
	case 2:
		locale = parts[0]
		rest = parts[1]
	default:
		return "", "", false
	}
	switch {
	case strings.HasSuffix(rest, ".html.tmpl"):
		return locale, "html", true
	case strings.HasSuffix(rest, ".txt.tmpl"):
		return locale, "text", true
	}
	return "", "", false
}

// templatePath matches "en/identity.welcome.html.tmpl".
func templatePath(p string) (locale, name, kind string, ok bool) {
	if strings.HasPrefix(p, "layouts/") {
		return "", "", "", false
	}
	parts := strings.SplitN(p, "/", 2)
	if len(parts) != 2 {
		return "", "", "", false
	}
	locale, file := parts[0], parts[1]
	switch {
	case strings.HasSuffix(file, ".html.tmpl"):
		return locale, strings.TrimSuffix(file, ".html.tmpl"), "html", true
	case strings.HasSuffix(file, ".txt.tmpl"):
		return locale, strings.TrimSuffix(file, ".txt.tmpl"), "text", true
	case strings.HasSuffix(file, ".subject.tmpl"):
		return locale, strings.TrimSuffix(file, ".subject.tmpl"), "subject", true
	}
	return "", "", "", false
}

func renderText(t *texttemplate.Template, data any) (string, error) {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
