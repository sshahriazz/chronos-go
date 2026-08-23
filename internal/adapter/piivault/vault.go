// Package piivault stores personal data encrypted, in PostgreSQL, under keys
// held by OpenBao.
//
// The read path is deliberately expensive-looking: every Get unwraps the
// subject's data key before it can open anything. That is one round trip to
// OpenBao per subject per operation, and it is the price of the guarantee — a
// key cached indefinitely in this process is a key that survives its own
// destruction, and erasure would then be a lie until the next restart.
package piivault

import (
	"context"
	"errors"
	"fmt"
	"time"

	platformdb "github.com/chronos/chronos-go/gen/sqlc/platform"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/pii"
	pgxv5 "github.com/jackc/pgx/v5"
)

// Vault implements pii.Vault over PostgreSQL and a KeyRing.
type Vault struct {
	tx    db.SystemTX
	keys  crypto.KeyRing
	cache *KeyCache
}

var _ pii.Vault = (*Vault)(nil)

// Option configures a Vault.
type Option func(*Vault)

// WithKeyCache caches unwrapped data keys for a short time, invalidated across
// replicas on erasure.
//
// Optional, and its absence is the SLOW path rather than the unsafe one: with no
// cache every read unwraps at OpenBao, which is the behaviour this file's package
// comment describes. That asymmetry is deliberate — a missing cache costs
// latency, and only a misbehaving cache could cost a guarantee.
func WithKeyCache(c *KeyCache) Option {
	return func(v *Vault) { v.cache = c }
}

func New(tx db.SystemTX, keys crypto.KeyRing, opts ...Option) *Vault {
	v := &Vault{tx: tx, keys: keys}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// HasKeyCache reports whether key caching is wired.
//
// Exposed so the composition root can be asserted rather than assumed: an
// adapter built, tested and constructed by no binary is a failure this codebase
// has already had, and a cache that was never attached looks identical to one
// that is simply always missing.
func (v *Vault) HasKeyCache() bool { return v.cache != nil }

// Put stores one field.
func (v *Vault) Put(ctx context.Context, id pii.SubjectID, field pii.Field, value string) error {
	return v.PutAll(ctx, id, map[pii.Field]string{field: value})
}

// PutAll stores several fields in one transaction.
//
// One transaction, so a registration cannot leave a profile half-populated: an
// email stored without the name it was meant to accompany is a record nobody
// wrote deliberately.
func (v *Vault) PutAll(ctx context.Context, id pii.SubjectID, values map[pii.Field]string) error {
	if id == "" {
		return fmt.Errorf("pii: a subject id is required")
	}
	if len(values) == 0 {
		return nil
	}
	for field, value := range values {
		if err := pii.Validate(field, value); err != nil {
			return err
		}
	}

	dek, err := v.subjectKey(ctx, id)
	if err != nil {
		return err
	}
	defer crypto.Zero(dek)

	return v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		for field, value := range values {
			// The SUBJECT ID is authenticated alongside the ciphertext, so a
			// row copied into another subject fails to open rather than
			// decrypting into the wrong person's profile.
			sealed, err := crypto.Seal(dek, []byte(value), []byte(id))
			if err != nil {
				return fmt.Errorf("pii: sealing %s: %w", field, err)
			}
			if _, err := q.Exec(ctx, platformdb.PutValue, string(id), string(field), sealed); err != nil {
				return fmt.Errorf("pii: storing %s: %w", field, err)
			}
		}
		return nil
	})
}

// Forget removes one field, leaving the rest and the subject's key alone.
//
// # No key is touched, and that is the difference from Erase
//
// Erase destroys the data key, which makes every field for the subject
// permanently unreadable — that is what makes erasure a key deletion instead of
// a migration (ADR-002). This removes one ROW. The subject keeps their key,
// their other fields stay readable, and nothing is invalidated anywhere.
//
// It is idempotent: forgetting a field nothing holds is a DELETE that matches
// nothing, which is the right outcome for a caller retrying an append.
func (v *Vault) Forget(ctx context.Context, id pii.SubjectID, field pii.Field) error {
	if id == "" {
		return fmt.Errorf("pii: a subject id is required")
	}
	if !field.Valid() {
		return fmt.Errorf("%w: %q", pii.ErrInvalidField, field)
	}
	return v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, platformdb.DeleteValue, string(id), string(field)); err != nil {
			return fmt.Errorf("pii: forgetting %s: %w", field, err)
		}
		return nil
	})
}

// Get decrypts one field.
func (v *Vault) Get(ctx context.Context, id pii.SubjectID, field pii.Field) (string, error) {
	if !field.Valid() {
		return "", fmt.Errorf("%w: %q", pii.ErrInvalidField, field)
	}

	dek, err := v.existingKey(ctx, id)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(dek)

	var sealed []byte
	err = v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, platformdb.GetValue, string(id), string(field)).Scan(&sealed)
		if errors.Is(scanErr, pgxv5.ErrNoRows) {
			return pii.ErrNoValue
		}
		return scanErr
	})
	if err != nil {
		if errors.Is(err, pii.ErrNoValue) {
			return "", err
		}
		return "", fmt.Errorf("pii: reading %s: %w", field, err)
	}

	plain, err := crypto.Open(dek, sealed, []byte(id))
	if err != nil {
		return "", fmt.Errorf("pii: opening %s: %w", field, err)
	}
	return string(plain), nil
}

// Profile decrypts everything held about a subject.
//
// One key unwrap for the whole profile rather than one per field: this is what a
// notification calls before rendering, and per-field unwrapping would make one
// email cost five round trips to OpenBao.
func (v *Vault) Profile(ctx context.Context, id pii.SubjectID) (pii.Profile, error) {
	dek, err := v.existingKey(ctx, id)
	if err != nil {
		return pii.Profile{}, err
	}
	defer crypto.Zero(dek)

	profile := pii.Profile{SubjectID: id, Fields: map[pii.Field]string{}}
	err = v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, platformdb.ListValues, string(id))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var field string
			var sealed []byte
			if err := rows.Scan(&field, &sealed); err != nil {
				return err
			}
			plain, err := crypto.Open(dek, sealed, []byte(id))
			if err != nil {
				// One unreadable field must not hide the rest: a partially
				// corrupt profile is more useful than none, and the failure is
				// visible as an absent field.
				continue
			}
			profile.Fields[pii.Field(field)] = string(plain)
		}
		return rows.Err()
	})
	if err != nil {
		return pii.Profile{}, fmt.Errorf("pii: reading profile: %w", err)
	}
	return profile, nil
}

// Erase destroys the subject's data key.
//
// Idempotent: erasing twice is not an error, because a subject may exercise the
// right twice and the second request must not fail.
//
// What this does NOT do is delete the value rows. They stay, unreadable, so
// there is still evidence the records existed and were erased — which an audit
// needs and a DELETE would remove.
// Erasing also invalidates every cached copy of the key, here and in every other
// replica. That is not cleanup: a key cached in a process that has just been told
// to destroy it is a key that survives its own destruction, and the erasure is a
// lie for as long as it does. The invalidation failing is therefore reported as
// an error even though the durable erasure succeeded — the operation is
// idempotent, so retrying costs nothing, and swallowing it would leave the
// guarantee unmet with nobody aware.
func (v *Vault) Erase(ctx context.Context, id pii.SubjectID) error {
	if err := v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, platformdb.EraseSubjectKey, string(id)); err != nil {
			return fmt.Errorf("pii: erasing %s: %w", id, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if v.cache != nil {
		return v.cache.Invalidate(ctx, id)
	}
	return nil
}

// Erased reports whether a subject was erased, without decrypting anything.
func (v *Vault) Erased(ctx context.Context, id pii.SubjectID) (bool, error) {
	var erased bool
	err := v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var wrapped []byte
		var erasedAt *time.Time
		scanErr := q.QueryRow(ctx, platformdb.GetSubjectKey, string(id)).Scan(&wrapped, &erasedAt)
		if errors.Is(scanErr, pgxv5.ErrNoRows) {
			return pii.ErrNoSubject
		}
		erased = erasedAt != nil
		return scanErr
	})
	if err != nil {
		if errors.Is(err, pii.ErrNoSubject) {
			return false, err
		}
		return false, fmt.Errorf("pii: reading subject %s: %w", id, err)
	}
	return erased, nil
}

// subjectKey returns the subject's data key, creating one on first use.
func (v *Vault) subjectKey(ctx context.Context, id pii.SubjectID) ([]byte, error) {
	dek, err := v.existingKey(ctx, id)
	switch {
	case err == nil:
		return dek, nil
	case errors.Is(err, pii.ErrErased):
		// Writing to an erased subject would resurrect them under a fresh key,
		// quietly undoing the erasure.
		return nil, err
	case !errors.Is(err, pii.ErrNoSubject):
		return nil, err
	}

	fresh, err := crypto.NewDEK()
	if err != nil {
		return nil, err
	}
	wrapped, err := v.keys.Wrap(ctx, fresh)
	if err != nil {
		crypto.Zero(fresh)
		return nil, err
	}
	if err := v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, execErr := q.Exec(ctx, platformdb.CreateSubjectKey, string(id), []byte(wrapped))
		return execErr
	}); err != nil {
		crypto.Zero(fresh)
		return nil, fmt.Errorf("pii: storing subject key: %w", err)
	}

	// Another writer may have won the race; DO NOTHING means our insert was
	// discarded and theirs is authoritative. Re-read rather than assume ours.
	crypto.Zero(fresh)
	return v.existingKey(ctx, id)
}

// existingKey unwraps a stored data key.
//
// This is the one function the key cache short-circuits, and the placement is
// the point: caching here saves the PostgreSQL read and the OpenBao unwrap while
// leaving every sealed value to be fetched and opened as usual. Nothing personal
// is cached anywhere, by construction rather than by discipline.
func (v *Vault) existingKey(ctx context.Context, id pii.SubjectID) ([]byte, error) {
	if v.cache != nil {
		if dek, erased, ok := v.cache.get(id); ok {
			if erased {
				return nil, fmt.Errorf("%w: %s", pii.ErrErased, id)
			}
			return dek, nil
		}
	}

	var wrapped []byte
	var erased bool

	err := v.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var erasedAt *time.Time
		scanErr := q.QueryRow(ctx, platformdb.GetSubjectKey, string(id)).Scan(&wrapped, &erasedAt)
		if errors.Is(scanErr, pgxv5.ErrNoRows) {
			return pii.ErrNoSubject
		}
		erased = erasedAt != nil
		return scanErr
	})
	if err != nil {
		if errors.Is(err, pii.ErrNoSubject) {
			return nil, err
		}
		return nil, fmt.Errorf("pii: reading subject key: %w", err)
	}
	if erased || len(wrapped) == 0 {
		if v.cache != nil {
			// Terminal state, so caching it can never become wrong — and an
			// erased subject is exactly the one that otherwise costs a round trip
			// per delivery attempt, forever.
			v.cache.putErased(id)
		}
		return nil, fmt.Errorf("%w: %s", pii.ErrErased, id)
	}

	dek, err := v.keys.Unwrap(ctx, crypto.Wrapped(wrapped))
	if err != nil {
		if errors.Is(err, crypto.ErrKeyDestroyed) {
			// The KEK itself is gone: everything under it is unreadable, which
			// is erasure for every subject at once.
			if v.cache != nil {
				v.cache.putErased(id)
			}
			return nil, fmt.Errorf("%w: %s", pii.ErrErased, id)
		}
		return nil, err
	}
	if v.cache != nil {
		v.cache.put(id, dek)
	}
	return dek, nil
}
