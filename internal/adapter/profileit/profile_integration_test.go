//go:build integration

package profileit_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	profileprojection "github.com/chronos/chronos-go/internal/modules/profile/projection"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	piipkg "github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// TestProfileSliceEndToEnd is the whole avatar path, with real bytes.
//
// It is the test that would have caught every "built and wired to nothing"
// failure this repository has had: a signed policy SeaweedFS actually accepts,
// an object it actually stores, a confirmation that becomes an event KurrentDB
// actually holds, a row the real projector actually writes, and a signed URL
// those same bytes actually come back down.
func TestProfileSliceEndToEnd(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)
	ctx := context.Background()
	start := time.Now().UTC()

	// ---- 1. the server hands out a target, and no bytes are involved --------
	grant, err := h.client.CreateAvatarUpload(ctx, withKey(connect.NewRequest(
		&profilev1.CreateAvatarUploadRequest{
			ContentType: "image/png", SizeBytes: int64(len(pngBytes)),
		}), "grant-"+subject))
	if err != nil {
		t.Fatalf("CreateAvatarUpload: %v", err)
	}
	key := grant.Msg.GetObjectKey()
	if !strings.HasPrefix(key, domain.AvatarPrefix(subject)+"/") {
		t.Fatalf("object key %q is not under this caller's own prefix; a key outside it "+
			"is one somebody else could confirm", key)
	}

	// ---- 2. the BROWSER uploads, over a connection the API is not part of ---
	fields := map[string]string{}
	for _, f := range grant.Msg.GetFields() {
		fields[f.GetKey()] = f.GetValue()
	}
	upload(t, grant.Msg.GetUploadUrl(), fields, pngBytes)

	// ---- 3. the server records the reference, having verified the object ----
	if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{
			DisplayName:     ptr("Ada Lovelace"),
			Locale:          ptr("en-GB"),
			Timezone:        ptr("Europe/London"),
			AvatarObjectKey: &key,
		}), "update-"+subject)); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	// ---- 4. the REAL projector turns the event into a row ------------------
	h.catchUp(t, subject, start)

	row, err := h.row(t, subject)
	if err != nil {
		t.Fatalf("reading profile_view: %v", err)
	}
	switch {
	case !row.exists:
		t.Fatal("the projector wrote no row")
	case row.avatarKey != key:
		t.Fatalf("avatar_object_key = %q, want %q", row.avatarKey, key)
	case row.avatarContentType != "image/png":
		t.Fatalf("avatar_content_type = %q, want image/png", row.avatarContentType)
	case row.avatarSize != int64(len(pngBytes)):
		t.Fatalf("avatar_size_bytes = %d, want %d", row.avatarSize, len(pngBytes))
	case !row.displayNameSet || !row.localeSet || !row.timezoneSet:
		t.Fatalf("the set-flags are %+v, want all three true", row)
	}

	// ---- 5. the read path resolves the vault and signs a URL ---------------
	got, err := h.client.GetProfile(ctx, connect.NewRequest(&profilev1.GetProfileRequest{}))
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.Msg.GetDisplayName() != "Ada Lovelace" {
		t.Fatalf("display name = %q; it is resolved from the PII vault at read time, and "+
			"an empty answer means the write side did not put it where notify reads it",
			got.Msg.GetDisplayName())
	}
	if got.Msg.GetLocale() != "en-GB" || got.Msg.GetTimezone() != "Europe/London" {
		t.Fatalf("locale/timezone = %q/%q", got.Msg.GetLocale(), got.Msg.GetTimezone())
	}
	avatar := got.Msg.GetAvatar()
	if avatar == nil {
		t.Fatal("the profile carries no avatar")
	}

	// ---- 6. and the URL really serves the bytes the browser uploaded -------
	if downloaded := download(t, avatar.GetUrl()); !bytes.Equal(downloaded, pngBytes) {
		t.Fatalf("the signed URL returned %d bytes, want the %d that were uploaded",
			len(downloaded), len(pngBytes))
	}
}

// TestTheNameReachesTheVaultAndNeverTheEventLog is ADR-002, asserted against
// the STORED BYTES rather than against a Go struct.
//
// A unit test can only say the payload's type has no field for a name. This
// says the encoded event in KurrentDB does not contain one — which also covers
// a codec that decided to serialize something the struct did not appear to
// carry.
func TestTheNameReachesTheVaultAndNeverTheEventLog(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)

	const name = "Grace Brewster Hopper"
	if _, err := h.client.UpdateProfile(context.Background(), withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{DisplayName: ptr(name), Locale: ptr("de-AT")},
	), "k-"+subject)); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	recorded := h.events(t, subject)
	if len(recorded) != 1 {
		t.Fatalf("the stream holds %d events, want one", len(recorded))
	}
	for _, e := range recorded {
		if bytes.Contains(e.Payload, []byte(name)) {
			t.Fatalf("the stored payload contains the display name:\n%s\n\n"+
				"An event is permanent and replayable, so a name in one outlives every "+
				"erasure request the log will ever see (ADR-002).", e.Payload)
		}
		if bytes.Contains(e.Metadata, []byte(name)) {
			t.Fatalf("the stored METADATA contains the display name:\n%s", e.Metadata)
		}
		// The locale is personal data too (internal/platform/pii), and it is in
		// the vault for the same reason.
		if bytes.Contains(e.Payload, []byte("de-AT")) {
			t.Fatalf("the stored payload contains the locale VALUE:\n%s\n\n"+
				"internal/platform/pii declares locale personal data, and "+
				"internal/platform/notify resolves it from the vault at delivery time. "+
				"A copy in the log is a copy erasure cannot destroy.", e.Payload)
		}
	}

	// And the value did arrive where notify reads it from.
	stored, err := h.vault.Get(context.Background(), piipkg.SubjectID(subject), piipkg.FieldName)
	if err != nil {
		t.Fatalf("reading the vault: %v", err)
	}
	if stored != name {
		t.Fatalf("the vault holds %q, want %q — this is the exact read "+
			"piivault.NewNotifyVault performs before every email", stored, name)
	}
}

// TestSparseUpdateLeavesTheOtherColumnsAlone is the sparse contract at the only
// level where it can actually go wrong in production: the SQL statement.
//
// Three updates, each naming one field. If the projection's COALESCE were
// dropped, the second would erase the avatar the first recorded and the third
// would erase both.
func TestSparseUpdateLeavesTheOtherColumnsAlone(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)
	ctx := context.Background()
	start := time.Now().UTC()

	key := h.uploadAnAvatar(t, subject)

	steps := []struct {
		name string
		req  *profilev1.UpdateProfileRequest
	}{
		{"the avatar alone", &profilev1.UpdateProfileRequest{AvatarObjectKey: &key}},
		{"the locale alone", &profilev1.UpdateProfileRequest{Locale: ptr("fr")}},
		{"the timezone alone", &profilev1.UpdateProfileRequest{Timezone: ptr("Europe/Paris")}},
	}
	for i, step := range steps {
		if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(step.req),
			"sparse-"+subject+"-"+step.name)); err != nil {
			t.Fatalf("update %d (%s): %v", i, step.name, err)
		}
	}

	h.catchUp(t, subject, start)
	// The projector may still be a step behind the last append; wait for the
	// column the LAST update set rather than for a timestamp.
	h.await(t, subject, func(r viewRow) bool { return r.timezoneSet })

	row, err := h.row(t, subject)
	if err != nil {
		t.Fatalf("reading profile_view: %v", err)
	}
	switch {
	case row.avatarKey != key:
		t.Fatalf("avatar_object_key = %q after two updates that did not mention it, want "+
			"%q — an absent field means UNCHANGED, and this is the column where a "+
			"missing COALESCE shows up as data loss", row.avatarKey, key)
	case row.avatarContentType == "" || row.avatarSize == 0:
		t.Fatalf("the avatar's other columns were cleared: %+v", row)
	case !row.localeSet:
		t.Fatalf("locale_set was cleared by an update that named only the timezone")
	case !row.timezoneSet:
		t.Fatalf("timezone_set was not written")
	case row.displayNameSet:
		t.Fatal("display_name_set is true, but no update ever named a display name")
	}
}

// TestRemovingAnAvatarIsDistinctFromNotMentioningIt is the other half, end to
// end: the same endpoint that leaves a field alone must be able to empty it.
func TestRemovingAnAvatarIsDistinctFromNotMentioningIt(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)
	ctx := context.Background()
	start := time.Now().UTC()

	key := h.uploadAnAvatar(t, subject)
	if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{AvatarObjectKey: &key}), "set-"+subject)); err != nil {
		t.Fatalf("setting the avatar: %v", err)
	}
	h.catchUp(t, subject, start)
	h.await(t, subject, func(r viewRow) bool { return r.avatarKey == key })

	// The empty string, explicitly sent.
	if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{AvatarObjectKey: ptr("")}),
		"clear-"+subject)); err != nil {
		t.Fatalf("removing the avatar: %v", err)
	}
	h.await(t, subject, func(r viewRow) bool { return r.avatarKey == "" })

	got, err := h.client.GetProfile(ctx, connect.NewRequest(&profilev1.GetProfileRequest{}))
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.Msg.GetAvatar() != nil {
		t.Fatal("the profile still carries an avatar after it was removed")
	}

	// Two events, and the second says Cleared rather than being absent.
	recorded := h.events(t, subject)
	if len(recorded) != 2 {
		t.Fatalf("the stream holds %d events, want two", len(recorded))
	}
	decoded, err := h.codec.Unmarshal(recorded[1].Type, recorded[1].Payload)
	if err != nil {
		t.Fatalf("decoding the second event: %v", err)
	}
	e, ok := decoded.(*contract.ProfileUpdated)
	if !ok {
		t.Fatalf("decoded %T", decoded)
	}
	if e.Avatar == nil || e.Avatar.Change != contract.Cleared {
		t.Fatalf("the removal recorded %+v, want a Cleared avatar change", e.Avatar)
	}
}

// TestOneSubjectCannotConfirmAnothersUpload is the confirm path's authorization
// property, against a real object that really exists.
//
// This is the case a token, a table or a secret would otherwise be needed for.
// The key is unguessable, but unguessability is not the control: the derived
// prefix is, and this proves it holds even when the attacker HAS the key.
func TestOneSubjectCannotConfirmAnothersUpload(t *testing.T) {
	victim := newSubject(t)
	attacker := newSubject(t)

	h.as(victim)
	key := h.uploadAnAvatar(t, victim)

	h.as(attacker)
	_, err := h.client.UpdateProfile(context.Background(), withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{AvatarObjectKey: &key}), "steal-"+attacker))
	if err == nil {
		t.Fatal("one account recorded another account's uploaded object as its own avatar")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
	if n := len(h.events(t, attacker)); n != 0 {
		t.Fatalf("the refused confirmation appended %d events", n)
	}
}

// TestConcurrentUpdatesAreNotLost is the concurrency proof, asserted against
// the EVENT LOG.
//
// Not the projection, deliberately (ADR-052): a read model can conceal a
// duplicate behind a unique index and stall the projector, so counting rows
// there can be satisfied by a table that is quietly wrong. The stream is the
// system of record, and it is what this reads.
//
// Every writer retries on CONFLICT, because CONFLICT is the documented "retry
// this" reason and the property under test is that a losing save is REFUSED
// rather than silently overwritten. If the aggregate saved with AnyRevision
// instead, no writer would ever see a conflict and the count would still be
// right — so the test also records how many conflicts happened and fails when
// none did.
func TestConcurrentUpdatesAreNotLost(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)
	ctx := context.Background()

	const writers = 8
	zones := []string{
		"Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Madrid",
		"America/New_York", "America/Chicago", "Asia/Tokyo", "Australia/Sydney",
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		conflicts int
		failures  []error
	)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Bounded retry. An unbounded loop under contention is how a test
			// that has actually deadlocked looks like a slow one.
			for attempt := range 40 {
				_, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{Timezone: ptr(zones[i])}),
					// A DISTINCT idempotency key per writer. A shared one would
					// make gate 5 collapse the eight calls into one and the test
					// would prove nothing about the aggregate.
					"race-"+subject+"-"+zones[i]))
				if err == nil {
					return
				}
				// CONFLICT maps to AlreadyExists in this server
				// (internal/server/connect.codeFor), which is where the wire
				// answer comes from — not from CONVENTIONS §5, which still says
				// Aborted. Asserted against the code the server actually sends.
				if connect.CodeOf(err) != connect.CodeAlreadyExists {
					mu.Lock()
					failures = append(failures, err)
					mu.Unlock()
					return
				}
				mu.Lock()
				conflicts++
				mu.Unlock()
				time.Sleep(time.Duration(attempt) * 5 * time.Millisecond)
			}
			mu.Lock()
			failures = append(failures, errors.New("gave up after 40 attempts"))
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(failures) > 0 {
		t.Fatalf("%d writers failed for reasons other than contention: %v",
			len(failures), failures)
	}

	recorded := h.events(t, subject)
	if len(recorded) != writers {
		t.Fatalf("the stream holds %d events, want %d — one per writer.\n\n"+
			"Fewer means a save was LOST: two writers loaded the same revision, both "+
			"appended, and one overwrote the other's decision. More means a retry "+
			"appended twice.", len(recorded), writers)
	}

	// The revisions are contiguous from zero, which is what says the appends
	// were serialised by the stream rather than interleaved by luck.
	for i, e := range recorded {
		if e.Revision != eventsourcing.Revision(i) {
			t.Fatalf("event %d is at revision %d; the stream is not contiguous", i, e.Revision)
		}
	}

	if conflicts == 0 {
		t.Fatal("not one writer was told CONFLICT across eight concurrent saves.\n\n" +
			"That is not luck at this concurrency — it means the append is not " +
			"pinned to the revision the aggregate was loaded at, so a losing save " +
			"would be silently overwritten rather than refused.")
	}
	t.Logf("%d writers, %d conflicts, %d events", writers, conflicts, len(recorded))
}

// TestTheProjectionRebuildsFromZero is the property CONVENTIONS §8 requires of
// every projection in this system, and the one ADR-052 showed can be broken by
// a single constraint.
//
// It TRUNCATES the table and replays from position zero through the real
// runner, then compares the rebuilt row against the one live consumption
// produced. Anything the log cannot reproduce shows up as a difference.
func TestTheProjectionRebuildsFromZero(t *testing.T) {
	subject := newSubject(t)
	h.as(subject)
	ctx := context.Background()
	start := time.Now().UTC()

	key := h.uploadAnAvatar(t, subject)
	if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{
			DisplayName: ptr("Ada"), Locale: ptr("en"), AvatarObjectKey: &key,
		}), "rebuild-a-"+subject)); err != nil {
		t.Fatalf("first update: %v", err)
	}
	if _, err := h.client.UpdateProfile(ctx, withKey(connect.NewRequest(
		&profilev1.UpdateProfileRequest{Timezone: ptr("Pacific/Auckland")}),
		"rebuild-b-"+subject)); err != nil {
		t.Fatalf("second update: %v", err)
	}

	h.catchUp(t, subject, start)
	h.await(t, subject, func(r viewRow) bool { return r.timezoneSet })

	before, err := h.row(t, subject)
	if err != nil {
		t.Fatalf("reading profile_view: %v", err)
	}

	h.rebuild(t, subject, before)

	after, err := h.row(t, subject)
	if err != nil {
		t.Fatalf("reading profile_view after the rebuild: %v", err)
	}
	if after != before {
		t.Fatalf("the rebuilt row differs from the live one:\n before %+v\n  after %+v\n\n"+
			"Every projected table must be reconstructable by replaying from position "+
			"zero. A difference means some column came from somewhere other than the log.",
			before, after)
	}
}

// TestAnUnauthenticatedCallerReachesNothing — the pipeline, not the handler,
// is what refuses.
func TestAnUnauthenticatedCallerReachesNothing(t *testing.T) {
	h.as("")
	t.Cleanup(func() { h.as(newSubject(t)) })

	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"GetProfile", func() error {
			_, err := h.client.GetProfile(context.Background(),
				connect.NewRequest(&profilev1.GetProfileRequest{}))
			return err
		}},
		{"UpdateProfile", func() error {
			_, err := h.client.UpdateProfile(context.Background(), withKey(connect.NewRequest(
				&profilev1.UpdateProfileRequest{DisplayName: ptr("Ada")}), "anon"))
			return err
		}},
		{"CreateAvatarUpload", func() error {
			_, err := h.client.CreateAvatarUpload(context.Background(), withKey(connect.NewRequest(
				&profilev1.CreateAvatarUploadRequest{ContentType: "image/png", SizeBytes: 10}),
				"anon"))
			return err
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.fn()
			if err == nil {
				t.Fatal("an unauthenticated caller was served")
			}
			if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers that talk to the real stack
// ---------------------------------------------------------------------------

// uploadAnAvatar mints a grant, POSTs the bytes to SeaweedFS as a browser
// would, and returns the key — without confirming it.
func (h *harness) uploadAnAvatar(t *testing.T, subject string) string {
	t.Helper()
	grant, err := h.client.CreateAvatarUpload(context.Background(), withKey(connect.NewRequest(
		&profilev1.CreateAvatarUploadRequest{
			ContentType: "image/png", SizeBytes: int64(len(pngBytes)),
		}), "upload-"+subject))
	if err != nil {
		t.Fatalf("CreateAvatarUpload: %v", err)
	}
	fields := map[string]string{}
	for _, f := range grant.Msg.GetFields() {
		fields[f.GetKey()] = f.GetValue()
	}
	upload(t, grant.Msg.GetUploadUrl(), fields, pngBytes)
	return grant.Msg.GetObjectKey()
}

// await runs the projector until a predicate holds for one subject's row.
func (h *harness) await(t *testing.T, subject string, ok func(viewRow) bool) {
	t.Helper()
	h.projectorOnce.Lock()
	defer h.projectorOnce.Unlock()

	runner := projection.NewRunner(profileprojection.NewProfile(h.codec), h.projectionDeps())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	deadline := time.After(45 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("the projector stopped early: %v", err)
		case <-deadline:
			row, _ := h.row(t, subject)
			t.Fatalf("the projection never satisfied the predicate; last row %+v", row)
		case <-time.After(100 * time.Millisecond):
			row, err := h.row(t, subject)
			if err != nil {
				t.Fatalf("reading profile_view: %v", err)
			}
			if row.exists && ok(row) {
				cancel()
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("projector shutdown: %v", err)
				}
				return
			}
		}
	}
}

// rebuild truncates `profile_view`, clears the checkpoint, and replays the
// whole log through the real runner's Rebuild path.
func (h *harness) rebuild(t *testing.T, subject string, want viewRow) {
	t.Helper()
	h.projectorOnce.Lock()

	runner := projection.NewRunner(profileprojection.NewProfile(h.codec), h.projectionDeps())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- runner.Rebuild(ctx) }()

	deadline := time.After(90 * time.Second)
	for {
		select {
		case err := <-done:
			cancel()
			h.projectorOnce.Unlock()
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("the rebuild failed: %v\n\nA rebuild that cannot complete means "+
					"the table is no longer reconstructable from position zero, which is "+
					"the failure ADR-052 records.", err)
			}
			return
		case <-deadline:
			cancel()
			<-done
			h.projectorOnce.Unlock()
			t.Fatal("the rebuild did not finish within the deadline")
		case <-time.After(200 * time.Millisecond):
			row, err := h.row(t, subject)
			if err != nil {
				t.Fatalf("reading profile_view: %v", err)
			}
			if row == want {
				cancel()
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("rebuild shutdown: %v", err)
				}
				h.projectorOnce.Unlock()
				return
			}
		}
	}
}
