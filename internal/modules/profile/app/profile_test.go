package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// TestUpdateSendsTheNameToTheVaultAndNotToTheLog is the ADR-002 assertion at
// the use-case level.
//
// It asserts BOTH halves, because either alone is satisfiable by a broken
// implementation: a version that wrote nothing anywhere would pass "not in the
// log", and one that wrote the name into the event as well would pass "in the
// vault".
func TestUpdateSendsTheNameToTheVaultAndNotToTheLog(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	const name = "Ada Lovelace"

	if _, err := h.updates.Update(context.Background(), app.UpdateCommand{
		SubjectID:      subject,
		DisplayName:    ptr(name),
		Locale:         ptr("en-GB"),
		Timezone:       ptr("Europe/London"),
		IdempotencyKey: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if got := h.vault.values[pii.FieldName]; got != name {
		t.Fatalf("the vault holds %q for the name, want %q — internal/platform/notify "+
			"resolves the name from here at delivery time, so a name that did not "+
			"arrive is mail addressed to nobody", got, name)
	}
	if got := h.vault.values[pii.FieldLocale]; got != "en-GB" {
		t.Fatalf("the vault holds %q for the locale, want en-GB", got)
	}
	if got := h.vault.values[pii.FieldTimezone]; got != "Europe/London" {
		t.Fatalf("the vault holds %q for the timezone, want Europe/London", got)
	}

	events := h.repo.recorded()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want exactly one", len(events))
	}
	// The strongest available statement: nothing anywhere in the payload's
	// rendering contains the name. A field added later that carried one would
	// fail here without anybody remembering to extend this test.
	if rendered := renderEvent(events[0]); strings.Contains(rendered, name) {
		t.Fatalf("the event payload contains the display name: %s\n\n"+
			"An event is permanent and replayable, so a name in one outlives every "+
			"erasure request the log will ever see (ADR-002).", rendered)
	}
	if events[0].DisplayName == nil || *events[0].DisplayName != contract.Set {
		t.Fatalf("DisplayName = %v, want the Set marker: the log must still record "+
			"THAT the name changed", events[0].DisplayName)
	}
}

// TestUpdateLeavesUnnamedFieldsAlone is the sparse contract at the use-case
// level: a command that names one field must produce an event that names one
// field, and must not touch the vault fields it did not name.
func TestUpdateLeavesUnnamedFieldsAlone(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.updates.Update(ctx, app.UpdateCommand{
		SubjectID: subject, DisplayName: ptr("Ada"), IdempotencyKey: "k1",
	}); err != nil {
		t.Fatalf("first Update: %v", err)
	}
	if _, err := h.updates.Update(ctx, app.UpdateCommand{
		SubjectID: subject, Timezone: ptr("Europe/Berlin"), IdempotencyKey: "k2",
	}); err != nil {
		t.Fatalf("second Update: %v", err)
	}

	if got := h.vault.values[pii.FieldName]; got != "Ada" {
		t.Fatalf("the name is %q after an update that named only the timezone, want Ada", got)
	}

	events := h.repo.recorded()
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want two", len(events))
	}
	second := events[1]
	if second.Timezone == nil {
		t.Fatal("the second event does not name the timezone the caller changed")
	}
	if second.DisplayName != nil {
		t.Fatalf("the second event names the display name (%v), which the caller did "+
			"not touch; the projection reads a non-nil marker as an instruction and "+
			"would overwrite the column", *second.DisplayName)
	}
	if second.Locale != nil || second.Avatar != nil {
		t.Fatalf("the second event names fields the caller did not touch: %+v", second)
	}
}

// TestUpdateRefusesAnotherSubjectsAvatarKey is the confirm path's authorization
// test, driven through the use case rather than the domain — so it also proves
// the check runs BEFORE the object store is contacted.
func TestUpdateRefusesAnotherSubjectsAvatarKey(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// An object that genuinely exists, uploaded by somebody else.
	theirKey, err := blob.NewKey(domain.AvatarPrefix(otherSubject))
	if err != nil {
		t.Fatalf("minting their key: %v", err)
	}
	h.store.put(theirKey.String(), "image/png", 1024)

	// If the store is ever consulted for a key outside the caller's namespace,
	// this endpoint has become an existence oracle for the whole bucket.
	h.store.verifyErr = errAnyVerify

	_, err = h.updates.Update(context.Background(), app.UpdateCommand{
		SubjectID: subject, AvatarObjectKey: ptr(theirKey.String()), IdempotencyKey: "k1",
	})
	if err == nil {
		t.Fatal("one subject recorded another subject's object key as their avatar")
	}
	if reason := errs.ReasonOf(err); reason != errs.ValidationFailed {
		t.Fatalf("reason = %s, want %s", reason, errs.ValidationFailed)
	}
	if strings.Contains(err.Error(), errAnyVerify.Error()) {
		t.Fatal("the object store was contacted for a key outside the caller's namespace; " +
			"the prefix check must run first, or the error distinguishes objects that " +
			"exist from ones that do not")
	}
	if n := len(h.repo.recorded()); n != 0 {
		t.Fatalf("recorded %d events for a refused update, want none", n)
	}
}

// TestUpdateRecordsWhatTheStoreSaysRatherThanWhatWasClaimed
func TestUpdateRecordsWhatTheStoreSaysRatherThanWhatWasClaimed(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	key, err := blob.NewKey(domain.AvatarPrefix(subject))
	if err != nil {
		t.Fatalf("minting a key: %v", err)
	}
	h.store.put(key.String(), "image/webp", 4096)

	if _, err := h.updates.Update(context.Background(), app.UpdateCommand{
		SubjectID: subject, AvatarObjectKey: ptr(key.String()), IdempotencyKey: "k1",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	events := h.repo.recorded()
	if len(events) != 1 || events[0].Avatar == nil {
		t.Fatalf("recorded %+v, want one event carrying an avatar change", events)
	}
	got := events[0].Avatar
	if got.Change != contract.Set || got.ObjectKey != key.String() ||
		got.ContentType != "image/webp" || got.SizeBytes != 4096 {
		t.Fatalf("Avatar = %+v; the content type and size must be the STORE's answer", got)
	}
}

// TestUpdateRefusesAnObjectTheStoreDescribesAsSomethingElse is the second half
// of "the store's word beats the uploader's": a policy that was not honoured, or
// an object replaced out of band, must not become an avatar.
func TestUpdateRefusesAnObjectTheStoreDescribesAsSomethingElse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		size        int64
		why         string
	}{
		{"html", "text/html", 512, "the object is a document, not an image"},
		{"svg", "image/svg+xml", 512, "SVG executes script from an origin the session is scoped to"},
		{"empty", "image/png", 0, "an abandoned upload renders as a broken image forever"},
		{"oversize", "image/png", domain.MaxAvatarBytes + 1, "the store did not honour the policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			key, err := blob.NewKey(domain.AvatarPrefix(subject))
			if err != nil {
				t.Fatalf("minting a key: %v", err)
			}
			h.store.put(key.String(), tt.contentType, tt.size)

			_, err = h.updates.Update(context.Background(), app.UpdateCommand{
				SubjectID: subject, AvatarObjectKey: ptr(key.String()), IdempotencyKey: "k1",
			})
			if err == nil {
				t.Fatalf("accepted a stored object the store calls %q at %d bytes (%s)",
					tt.contentType, tt.size, tt.why)
			}
			if n := len(h.repo.recorded()); n != 0 {
				t.Fatalf("recorded %d events for a refused update, want none", n)
			}
		})
	}
}

// TestUpdateClearsTheAvatarButRefusesToClearAVaultField is the cleared-vs-absent
// distinction where it is reachable, and the honest refusal where it is not.
func TestUpdateClearsTheAvatarButRefusesToClearAVaultField(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()

	key, err := blob.NewKey(domain.AvatarPrefix(subject))
	if err != nil {
		t.Fatalf("minting a key: %v", err)
	}
	h.store.put(key.String(), "image/png", 100)
	if _, err := h.updates.Update(ctx, app.UpdateCommand{
		SubjectID: subject, AvatarObjectKey: ptr(key.String()), IdempotencyKey: "k1",
	}); err != nil {
		t.Fatalf("setting the avatar: %v", err)
	}

	// Cleared: the EMPTY string, which is a value the request carried.
	if _, err := h.updates.Update(ctx, app.UpdateCommand{
		SubjectID: subject, AvatarObjectKey: ptr(""), IdempotencyKey: "k2",
	}); err != nil {
		t.Fatalf("removing the avatar: %v", err)
	}
	events := h.repo.recorded()
	if len(events) != 2 || events[1].Avatar == nil ||
		events[1].Avatar.Change != contract.Cleared {
		t.Fatalf("recorded %+v, want a second event carrying a Cleared avatar", events)
	}

	// A vault field, on the other hand, has no empty state to move to — and the
	// refusal is explicit rather than a save that quietly did nothing.
	for _, field := range []struct {
		name string
		cmd  app.UpdateCommand
	}{
		{"display name", app.UpdateCommand{SubjectID: subject, DisplayName: ptr(""), IdempotencyKey: "k3"}},
		{"locale", app.UpdateCommand{SubjectID: subject, Locale: ptr(""), IdempotencyKey: "k4"}},
		{"timezone", app.UpdateCommand{SubjectID: subject, Timezone: ptr(""), IdempotencyKey: "k5"}},
	} {
		_, err := h.updates.Update(ctx, field.cmd)
		if err == nil {
			t.Fatalf("clearing the %s was accepted; the PII vault destroys a subject's "+
				"KEY and cannot delete one field, so there is no operation to perform "+
				"and a silent no-op would look like a save that worked", field.name)
		}
		if reason := errs.ReasonOf(err); reason != errs.ValidationFailed {
			t.Fatalf("clearing the %s: reason = %s, want %s",
				field.name, reason, errs.ValidationFailed)
		}
	}
}

// TestUpdateWritesTheVaultBeforeTheLog pins the order the use case documents.
//
// A build with the two swapped would leave the log asserting a change the vault
// never received, and every email from then on would render the old name while
// the history said otherwise.
func TestUpdateWritesTheVaultBeforeTheLog(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.repo.conflict = true // the append fails

	_, err := h.updates.Update(context.Background(), app.UpdateCommand{
		SubjectID: subject, DisplayName: ptr("Ada"), IdempotencyKey: "k1",
	})
	if err == nil {
		t.Fatal("Update succeeded despite the append failing")
	}
	if h.vault.puts != 1 {
		t.Fatalf("the vault was written %d times; it must be written BEFORE the append, "+
			"so that a retry with the same idempotency key converges", h.vault.puts)
	}
	if n := len(h.repo.recorded()); n != 0 {
		t.Fatalf("recorded %d events despite the append failing", n)
	}
}

// TestUpdateReportsAConcurrentSaveAsConflict — the loser retries against the
// winner's state rather than being silently overwritten.
func TestUpdateReportsAConcurrentSaveAsConflict(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.repo.conflict = true

	_, err := h.updates.Update(context.Background(), app.UpdateCommand{
		SubjectID: subject, Locale: ptr("en"), IdempotencyKey: "k1",
	})
	if reason := errs.ReasonOf(err); reason != errs.Conflict {
		t.Fatalf("reason = %s, want %s: CONFLICT is the documented retry-this reason, "+
			"and anything else makes a client treat a losing save as a permanent failure",
			reason, errs.Conflict)
	}
}

func TestUpdateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  app.UpdateCommand
		why  string
	}{
		{
			name: "no subject",
			cmd:  app.UpdateCommand{DisplayName: ptr("Ada"), IdempotencyKey: "k"},
			why:  "the caller comes from the session; a use case that trusts its caller stops being checked",
		},
		{
			name: "no idempotency key",
			cmd:  app.UpdateCommand{SubjectID: subject, DisplayName: ptr("Ada")},
			why:  "without one, every retry derives fresh event ids and becomes a second change",
		},
		{
			name: "names no field",
			cmd:  app.UpdateCommand{SubjectID: subject, IdempotencyKey: "k"},
			why:  "an empty save is a client bug worth reporting, not an append of nothing",
		},
		{
			name: "an unusable locale",
			cmd:  app.UpdateCommand{SubjectID: subject, Locale: ptr("english"), IdempotencyKey: "k"},
			why:  "a tag nothing renders from makes the field free text",
		},
		{
			name: "a timezone that does not exist",
			cmd:  app.UpdateCommand{SubjectID: subject, Timezone: ptr("Europe/Berlim"), IdempotencyKey: "k"},
			why:  "it renders every timestamp in UTC forever while looking configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if _, err := h.updates.Update(context.Background(), tt.cmd); err == nil {
				t.Fatalf("Update was accepted, want a refusal (%s)", tt.why)
			}
			if h.vault.puts != 0 {
				t.Fatalf("a refused update wrote to the vault %d times; every refusal must "+
					"come before the first write", h.vault.puts)
			}
			if n := len(h.repo.recorded()); n != 0 {
				t.Fatalf("a refused update recorded %d events", n)
			}
		})
	}
}

// TestUpdateAppendsNothingWhenNothingChanged — a re-confirmed avatar key is the
// normal case for a retried client, and it must not add to the log.
func TestUpdateAppendsNothingWhenNothingChanged(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()
	key, err := blob.NewKey(domain.AvatarPrefix(subject))
	if err != nil {
		t.Fatalf("minting a key: %v", err)
	}
	h.store.put(key.String(), "image/png", 100)

	for i := range 3 {
		if _, err := h.updates.Update(ctx, app.UpdateCommand{
			SubjectID: subject, AvatarObjectKey: ptr(key.String()),
			IdempotencyKey: "k" + string(rune('0'+i)),
		}); err != nil {
			t.Fatalf("Update %d: %v", i, err)
		}
	}
	if n := len(h.repo.recorded()); n != 1 {
		t.Fatalf("recorded %d events for three confirmations of one key, want one: the "+
			"log is a history of changes, not of saves", n)
	}
}

var errAnyVerify = errStore("fake: the object store was contacted")

type errStore string

func (e errStore) Error() string { return string(e) }
