// Package pii is the vault: the only place personal data exists.
//
// Everything else in the system holds a SubjectID — an opaque pseudonym — and
// resolves it here when it genuinely needs a name or an address. Events hold
// pseudonyms (ADR-002). Projections hold pseudonyms (compliance.md §1). Logs
// hold pseudonyms. That is what makes erasure a key deletion rather than a
// migration across every table that ever touched a user.
//
// This is also the ONE mutable system of record (ADR-013). Everything else in
// PostgreSQL is derived and rebuildable from the event log; this is not, because
// it is the one thing deliberately absent from the log.
package pii

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SubjectID is a pseudonym for a person.
//
// It appears in events, projections, logs and metrics. It identifies a record in
// this vault and nothing else: on its own it reveals no name, no address, and no
// membership.
type SubjectID string

func (s SubjectID) String() string { return string(s) }

// Field names one piece of personal data.
//
// A closed set rather than free strings, so the vault's whole surface is
// enumerable — "what do we hold about this person?" is answerable by reading
// this list, which is exactly what a subject access request asks.
type Field string

const (
	// FieldEmail is the primary address. Also the login identifier, which is
	// why it is here rather than in identity's own tables.
	FieldEmail Field = "email"

	// FieldName is the display name.
	FieldName Field = "name"

	// FieldPhone is used for SMS second factors.
	FieldPhone Field = "phone"

	// FieldLocale and FieldTimezone shape how a person is spoken to. Personal
	// data under GDPR even though they feel like preferences: combined with
	// other fields they narrow down who someone is.
	FieldLocale   Field = "locale"
	FieldTimezone Field = "timezone"
)

// AllFields is every field the vault stores. Used to answer a subject access
// request without a human enumerating them from memory.
var AllFields = []Field{FieldEmail, FieldName, FieldPhone, FieldLocale, FieldTimezone}

// Valid reports whether a field is one the vault knows.
func (f Field) Valid() bool {
	return slices.Contains(AllFields, f)
}

// Profile is everything the vault holds about one subject.
type Profile struct {
	SubjectID SubjectID
	Fields    map[Field]string
}

// Get returns a field, or the empty string. Convenience for callers that treat
// a missing optional field as absent rather than as an error.
func (p Profile) Get(f Field) string { return p.Fields[f] }

// Vault stores and retrieves personal data.
type Vault interface {
	// Put encrypts and stores one field.
	Put(ctx context.Context, id SubjectID, field Field, value string) error

	// PutAll stores several fields for one subject in one operation, so a
	// registration does not leave a half-populated profile behind if it fails
	// midway.
	PutAll(ctx context.Context, id SubjectID, values map[Field]string) error

	// Get decrypts one field. Returns ErrErased if the subject was erased, and
	// ErrNoValue if the field was never set.
	Get(ctx context.Context, id SubjectID, field Field) (string, error)

	// Profile decrypts everything held about a subject. This is what a
	// notification resolves before rendering, and what a subject access request
	// returns.
	Profile(ctx context.Context, id SubjectID) (Profile, error)

	// Erase destroys the subject's data key.
	//
	// Not a delete of the values: those rows stay, unreadable, because deleting
	// them would leave nothing to prove the erasure happened. What goes is the
	// key, and with it any possibility of reading them again (ADR-002).
	Erase(ctx context.Context, id SubjectID) error

	// Erased reports whether a subject has been erased, without attempting to
	// decrypt anything.
	Erased(ctx context.Context, id SubjectID) (bool, error)
}

var (
	// ErrErased means the subject exercised erasure. Callers must treat this as
	// a CORRECT outcome, not a failure: there is nothing to retry, and a
	// notification addressed to an erased subject is skipped rather than
	// retried forever (NOTIFICATIONS §4).
	ErrErased = errors.New("pii: subject has been erased")

	// ErrNoSubject means nothing is stored for that id.
	ErrNoSubject = errors.New("pii: no such subject")

	// ErrNoValue means the subject exists but that field was never set.
	ErrNoValue = errors.New("pii: field not set")

	// ErrInvalidField means the field is not one the vault knows. A closed set
	// keeps the vault's surface enumerable.
	ErrInvalidField = errors.New("pii: unknown field")
)

// Validate checks a value before it is encrypted.
//
// Length is bounded because a vault field is not a document store, and an
// unbounded value is an unbounded row in the one table that cannot be rebuilt.
func Validate(field Field, value string) error {
	if !field.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidField, field)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("pii: %s cannot be empty", field)
	}
	const maxLen = 512
	if len(value) > maxLen {
		return fmt.Errorf("pii: %s is %d bytes, over the %d-byte limit", field, len(value), maxLen)
	}
	return nil
}
