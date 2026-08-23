package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

type fakeProfileSource struct {
	fields map[string]string
	err    error
	asked  []string
}

func (f *fakeProfileSource) Profile(
	_ context.Context, subjectID string,
) (map[string]string, error) {
	f.asked = append(f.asked, subjectID)
	return f.fields, f.err
}

type fakeExportStore struct {
	putErr   error
	grantErr error

	putKeys  []blob.Key
	putBody  []byte
	putType  string
	granted  []blob.Key
	expiries []time.Duration
}

func (f *fakeExportStore) Put(
	_ context.Context, key blob.Key, body []byte, contentType string,
) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.putKeys = append(f.putKeys, key)
	f.putBody, f.putType = body, contentType
	return nil
}

func (f *fakeExportStore) GrantDownload(
	_ context.Context, key blob.Key, expiry time.Duration,
) (string, error) {
	if f.grantErr != nil {
		return "", f.grantErr
	}
	f.granted = append(f.granted, key)
	f.expiries = append(f.expiries, expiry)
	return "https://s3.example.test/" + key.String() + "?sig=x", nil
}

var exportNow = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

func newExports(t *testing.T, p *fakeProfileSource, st *fakeExportStore) *app.Exports {
	t.Helper()
	e, err := app.NewExports(app.ExportsDeps{
		Profile: p, Store: st,
		Prefix: func(s string) string { return "subj" + s },
		Now:    func() time.Time { return exportNow },
	})
	if err != nil {
		t.Fatalf("NewExports: %v", err)
	}
	return e
}

// THE BUNDLE CARRIES EVERY FIELD THE VAULT HOLDS.
//
// An export that silently omitted a field would answer Article 15 with a partial
// file that looks complete — the failure with no symptom, because the person
// cannot know what they were not given.
func TestTheBundleCarriesEveryField(t *testing.T) {
	profile := &fakeProfileSource{fields: map[string]string{
		"email": "a@example.test", "name": "Sam", "locale": "en", "timezone": "UTC",
	}}
	store := &fakeExportStore{}

	if _, err := newExports(t, profile, store).Produce(
		context.Background(), "subj_1"); err != nil {
		t.Fatal(err)
	}

	bundle, err := codec.Tolerant[app.Bundle](store.putBody)
	if err != nil {
		t.Fatalf("the stored bundle does not decode: %v", err)
	}
	if len(bundle.PersonalData) != 4 {
		t.Fatalf("the bundle carries %d fields, want 4; a person cannot know what they "+
			"were not given", len(bundle.PersonalData))
	}
	if bundle.PersonalData["email"] != "a@example.test" {
		t.Errorf("the email is %q", bundle.PersonalData["email"])
	}
	if bundle.SubjectID != "subj_1" {
		t.Errorf("the bundle names %q", bundle.SubjectID)
	}
	if bundle.FormatVersion != app.ExportFormatVersion {
		t.Errorf("format version %d", bundle.FormatVersion)
	}
	if !bundle.GeneratedAt.Equal(exportNow) {
		t.Errorf("generated at %v", bundle.GeneratedAt)
	}
	if store.putType != "application/json" {
		t.Errorf("stored as %q; Article 20 asks for a commonly used, machine-readable "+
			"format", store.putType)
	}
}

// AND IT SAYS WHAT IS RETAINED.
//
// Article 15(1) asks about the PROCESSING, not only the values. A file listing a
// name and an address while saying nothing about invoices retained under a
// statutory obligation is accurate and misleading — the same reason the erasure
// confirmation carries the list.
func TestTheBundleStatesWhatIsRetained(t *testing.T) {
	store := &fakeExportStore{}
	if _, err := newExports(t, &fakeProfileSource{}, store).Produce(
		context.Background(), "subj_1"); err != nil {
		t.Fatal(err)
	}

	bundle, err := codec.Tolerant[app.Bundle](store.putBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Retained) == 0 {
		t.Fatal("the bundle states nothing about what is retained; it lists values and " +
			"implies they are everything")
	}
	var mentionsInvoices bool
	for _, r := range bundle.Retained {
		if strings.Contains(strings.ToLower(r), "invoice") {
			mentionsInvoices = true
		}
	}
	if !mentionsInvoices {
		t.Errorf("the retained list does not mention invoices: %v. They survive under "+
			"Article 17(3)(b) and a bundle that implies otherwise is a misleading "+
			"statement about processing", bundle.Retained)
	}
}

// THE BUNDLE IS WRITTEN UNDER THE SUBJECT'S OWN PREFIX.
//
// This is what makes compliance.md §4 step 9 — "purge exported bundles on
// erasure" — a property of WHERE the bundle lives rather than a step somebody
// has to remember. The erasure deletes every object under a subject's prefixes;
// a bundle written anywhere else is the most concentrated personal data this
// system produces, surviving the erasure of the person it describes.
func TestTheBundleIsWrittenUnderTheSubjectsPrefix(t *testing.T) {
	store := &fakeExportStore{}
	if _, err := newExports(t, &fakeProfileSource{}, store).Produce(
		context.Background(), "subj_1"); err != nil {
		t.Fatal(err)
	}

	if len(store.putKeys) != 1 {
		t.Fatalf("stored %d objects", len(store.putKeys))
	}
	if got := store.putKeys[0].String(); !strings.HasPrefix(got, "subjsubj_1/") {
		t.Fatalf("the bundle was written to %q, outside the subject's namespace. An "+
			"erasure deletes by prefix, so this bundle survives the erasure of the "+
			"person it describes", got)
	}
}

// EACH EXPORT IS A NEW OBJECT.
//
// Objects here are immutable (ADR-013), and overwriting would replace a bundle
// somebody may still be downloading. Every version lives under the same prefix,
// so erasure still removes all of them.
func TestEachExportIsANewObject(t *testing.T) {
	store := &fakeExportStore{}
	e := newExports(t, &fakeProfileSource{}, store)

	for range 2 {
		if _, err := e.Produce(context.Background(), "subj_1"); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.putKeys) != 2 {
		t.Fatalf("stored %d objects", len(store.putKeys))
	}
	if store.putKeys[0] == store.putKeys[1] {
		t.Error("two exports wrote the same key; the second replaced a bundle somebody " +
			"may still be downloading")
	}
}

// THE DOWNLOAD LINK EXPIRES.
//
// It is a bearer capability: anybody holding the URL can fetch the most
// concentrated personal data this system produces.
func TestTheDownloadLinkExpires(t *testing.T) {
	store := &fakeExportStore{}
	res, err := newExports(t, &fakeProfileSource{}, store).Produce(
		context.Background(), "subj_1")
	if err != nil {
		t.Fatal(err)
	}

	if len(store.expiries) != 1 || store.expiries[0] <= 0 {
		t.Fatalf("granted with expiry %v; a link that does not expire is a durable "+
			"credential for everything known about a person", store.expiries)
	}
	if !res.ExpiresAt.After(exportNow) {
		t.Errorf("the reported expiry %v is not after now", res.ExpiresAt)
	}
	if res.DownloadURL == "" {
		t.Error("no download url was returned")
	}
}

// AN UNREADABLE VAULT FAILS THE EXPORT.
//
// Producing an empty bundle would hand somebody a file and tell them it is
// everything held about them.
func TestAnUnreadableVaultFailsTheExport(t *testing.T) {
	profile := &fakeProfileSource{err: errors.New("openbao: unreachable")}
	store := &fakeExportStore{}

	if _, err := newExports(t, profile, store).Produce(
		context.Background(), "subj_1"); err == nil {
		t.Fatal("an unreadable vault produced a bundle; the person is handed an empty " +
			"file and told it is everything held about them")
	}
	if len(store.putKeys) != 0 {
		t.Error("a bundle was stored despite the failed read")
	}
}

// A FAILED STORE FAILS THE EXPORT, AND NO LINK IS GRANTED.
func TestAFailedStoreGrantsNoLink(t *testing.T) {
	store := &fakeExportStore{putErr: errors.New("seaweedfs: down")}

	if _, err := newExports(t, &fakeProfileSource{}, store).Produce(
		context.Background(), "subj_1"); err == nil {
		t.Fatal("a failed store reported success")
	}
	if len(store.granted) != 0 {
		t.Error("a download was granted for an object that was never written")
	}
}

// AN EMPTY SUBJECT IS REFUSED BEFORE THE VAULT IS READ.
func TestAnExportNeedsASubject(t *testing.T) {
	profile := &fakeProfileSource{}

	if _, err := newExports(t, profile, &fakeExportStore{}).Produce(
		context.Background(), ""); err == nil {
		t.Fatal("an export with no subject was produced")
	}
	if len(profile.asked) != 0 {
		t.Error("the vault was read for an empty subject")
	}
}

// AN EMPTY PREFIX IS REFUSED.
//
// It would put the bundle at the bucket root, outside every subject's namespace
// and therefore outside what an erasure deletes.
func TestAnEmptyPrefixIsRefused(t *testing.T) {
	store := &fakeExportStore{}
	e, err := app.NewExports(app.ExportsDeps{
		Profile: &fakeProfileSource{}, Store: store,
		Prefix: func(string) string { return "" },
		Now:    func() time.Time { return exportNow },
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.Produce(context.Background(), "subj_1"); err == nil {
		t.Fatal("a bundle was written with no prefix; it sits at the bucket root and " +
			"survives every erasure")
	}
	if len(store.putKeys) != 0 {
		t.Error("it was stored anyway")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestExportsRefusesAnIncompleteWiring(t *testing.T) {
	full := app.ExportsDeps{
		Profile: &fakeProfileSource{}, Store: &fakeExportStore{},
		Prefix: func(s string) string { return "p" + s },
		Now:    func() time.Time { return exportNow },
	}
	if _, err := app.NewExports(full); err != nil {
		t.Fatalf("a complete wiring was refused: %v", err)
	}

	for name, drop := range map[string]func(*app.ExportsDeps){
		"profile": func(d *app.ExportsDeps) { d.Profile = nil },
		"store":   func(d *app.ExportsDeps) { d.Store = nil },
		"prefix":  func(d *app.ExportsDeps) { d.Prefix = nil },
		"clock":   func(d *app.ExportsDeps) { d.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := full
			drop(&deps)
			if _, err := app.NewExports(deps); err == nil {
				t.Errorf("a wiring with no %s was accepted", name)
			}
		})
	}
}
