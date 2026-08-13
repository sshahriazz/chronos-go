package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// SessionState is the lifecycle of one session.
type SessionState int

const (
	// SessionNone does not exist. Zero value, so an unloaded session is never
	// mistaken for a live one.
	SessionNone SessionState = iota
	SessionLive
	SessionRevoked
	SessionExpired
)

// Session is one authenticated device's access to one account.
//
// Its own aggregate, not a collection inside User, for a reason that shows up
// under load: "revoke this one session" would otherwise contend on the user
// stream with every password change, every method enrolment and every other
// session's creation. A person signing in on five devices would serialise five
// appends against one stream.
//
// The cost of the split is that "revoke all sessions" is a fan-out rather than
// one append. That is the correct trade: it is rare, and it is allowed to be
// slower than the operation that happens on every login.
type Session struct {
	eventsourcing.Base

	id        ids.SessionID
	subjectID string
	deviceID  string

	state SessionState
	aal   contract.AssuranceLevel

	idleExpiresAt     time.Time
	absoluteExpiresAt time.Time

	// elevatedUntil and elevatedScope carry a step-up. Both, together: an
	// elevation with a deadline but no scope is a standing key to every
	// dangerous operation for its duration.
	elevatedUntil time.Time
	elevatedScope string

	requiresCredentialRotation bool
}

// NewSession returns an empty Session for the repository to rebuild into.
func NewSession() *Session { return &Session{} }

func (s *Session) ID() ids.SessionID            { return s.id }
func (s *Session) SubjectID() string            { return s.subjectID }
func (s *Session) DeviceID() string             { return s.deviceID }
func (s *Session) State() SessionState          { return s.state }
func (s *Session) AAL() contract.AssuranceLevel { return s.aal }
func (s *Session) IdleExpiresAt() time.Time     { return s.idleExpiresAt }
func (s *Session) AbsoluteExpiresAt() time.Time { return s.absoluteExpiresAt }
func (s *Session) RequiresRotation() bool       { return s.requiresCredentialRotation }

// Apply is the pure transition.
func (s *Session) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.SessionCreated:
		s.id, _ = ids.Parse[ids.Session](ev.SessionID)
		s.subjectID = ev.SubjectID
		s.deviceID = ev.DeviceID
		s.aal = ev.AAL
		s.idleExpiresAt = ev.IdleExpiresAt
		s.absoluteExpiresAt = ev.AbsoluteExpiresAt
		s.requiresCredentialRotation = ev.RequiresCredentialRotation
		s.state = SessionLive

	case *contract.SessionElevated:
		s.aal = ev.AAL
		s.elevatedUntil = ev.ElevatedUntil
		s.elevatedScope = ev.Scope

	case *contract.SessionRevoked:
		s.state = SessionRevoked

	case *contract.SessionExpired:
		s.state = SessionExpired
	}
}

// Create opens the session.
//
// Both deadlines are parameters rather than computed here, because the domain
// has no clock and the policy that produces them is configuration. What the
// domain enforces is their RELATIONSHIP: an idle deadline beyond the absolute
// one is a session that never idles out, which is the bug that makes the
// absolute deadline the only one that ever fires.
func (s *Session) Create(
	id ids.SessionID,
	subjectID, deviceID string,
	aal contract.AssuranceLevel,
	idleExpiresAt, absoluteExpiresAt, at time.Time,
	requiresRotation bool,
) error {
	if s.state != SessionNone {
		return errs.Conflictf("this session already exists")
	}
	switch {
	case id.IsZero():
		return errs.ValidationFailedf("a session id is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	case !aal.Valid():
		// AAL0 and AAL3 both land here, for opposite reasons: nothing
		// authenticated, and nothing this system can currently establish
		// (IDENTITY-REVIEW C4). A session claiming either would be lying to
		// every min_aal comparison downstream.
		return errs.ValidationFailedf("a session must record an assurance level it actually reached")
	case !absoluteExpiresAt.After(at):
		return errs.ValidationFailedf("a session must expire in the future")
	case idleExpiresAt.After(absoluteExpiresAt):
		return errs.ValidationFailedf(
			"the idle deadline may not exceed the absolute one, or it would never fire")
	}
	eventsourcing.Record(s, &contract.SessionCreated{
		SessionID:                  id.String(),
		SubjectID:                  subjectID,
		DeviceID:                   deviceID,
		AAL:                        aal,
		IdleExpiresAt:              idleExpiresAt.UTC(),
		AbsoluteExpiresAt:          absoluteExpiresAt.UTC(),
		RequiresCredentialRotation: requiresRotation,
		CreatedAt:                  at.UTC(),
	})
	return nil
}

// Live reports whether the session may be used at this instant, as far as the
// LOG can tell.
//
// It checks the state and the absolute deadline — the two facts the event log
// actually holds — and deliberately does NOT check idle expiry.
//
// The idle deadline moves on every request. Recording that movement as an event
// would make every authenticated read a write to the log, so the current idle
// deadline lives in the session read model and is advanced there. This aggregate
// therefore cannot know it, and a method that pretended to would be answering
// from the deadline the session was CREATED with — permanently pinned to
// creation time, so it fires once and then never again for any session that
// outlives its first idle window.
//
// Callers that hold the current idle deadline use LiveAt. Everything else gets
// the absolute answer, which is the one that cannot be refreshed by an attacker
// keeping a stolen token warm.
func (s *Session) Live(now time.Time) bool {
	return s.state == SessionLive && now.Before(s.absoluteExpiresAt)
}

// LiveAt is Live plus the idle check, for a caller that has read the current
// idle deadline from the session read model.
//
// This is the authenticator's question. Both deadlines matter and they fail
// differently: idle expiry ends a session nobody is using, and the absolute one
// ends a session someone may well be using — which is the point, because the
// someone may not be the account holder.
func (s *Session) LiveAt(now, idleDeadline time.Time) bool {
	return s.Live(now) && now.Before(idleDeadline)
}

// InitialIdleDeadline is the idle deadline the session started with. The
// projector seeds the read model's column from it; after that the read model is
// the authority.
func (s *Session) InitialIdleDeadline() time.Time { return s.idleExpiresAt }

// ExpiredReason reports which deadline ended the session, given the current idle
// deadline from the read model.
//
// The absolute deadline is checked FIRST. A session past both should be recorded
// as an absolute expiry: that is the one worth surfacing, and reporting it as
// idle would bury it among the routine ones.
func (s *Session) ExpiredReason(now, idleDeadline time.Time) (absolute bool, expired bool) {
	if s.state != SessionLive {
		return false, false
	}
	switch {
	case !now.Before(s.absoluteExpiresAt):
		return true, true
	case !now.Before(idleDeadline):
		return false, true
	default:
		return false, false
	}
}

// Elevated reports whether a step-up covers this scope right now.
//
// Scope AND deadline, both checked. An elevation granted for "change password"
// must not authorise "create API key": a step-up is proof for one dangerous
// operation, not a mode the session enters.
func (s *Session) Elevated(scope string, now time.Time) bool {
	if !s.Live(now) {
		return false
	}
	if s.elevatedScope == "" || s.elevatedScope != scope {
		return false
	}
	return now.Before(s.elevatedUntil)
}

// Elevate records a completed step-up ceremony.
func (s *Session) Elevate(
	aal contract.AssuranceLevel, scope string, until, at time.Time,
) error {
	if s.state != SessionLive {
		return errs.Unauthenticatedf("this session is no longer live")
	}
	switch {
	case scope == "":
		return errs.ValidationFailedf("an elevation must name the operation it is for")
	case !aal.Valid():
		return errs.ValidationFailedf("an elevation must record an assurance level it actually reached")
	case !until.After(at):
		return errs.ValidationFailedf("an elevation must expire in the future")
	case until.After(s.absoluteExpiresAt):
		// An elevation cannot outlive the session it elevates. Without this a
		// step-up near the end of a session's life would leave a window in which
		// the elevation is valid and the session is not — and code that checked
		// only the elevation would honour it.
		return errs.ValidationFailedf("an elevation may not outlive its session")
	}
	eventsourcing.Record(s, &contract.SessionElevated{
		SessionID:     s.id.String(),
		SubjectID:     s.subjectID,
		AAL:           aal,
		Scope:         scope,
		ElevatedUntil: until.UTC(),
		ElevatedAt:    at.UTC(),
	})
	return nil
}

// Revoke ends the session deliberately.
//
// Idempotent: revoking an already-revoked session records nothing and succeeds.
// Making it an error would turn "revoke everything" — which races with the user
// signing out on one device — into a partial failure that leaves the caller
// unsure which sessions actually ended.
func (s *Session) Revoke(actorID, reason string, at time.Time) error {
	switch s.state {
	case SessionNone:
		return errs.NotFoundf("no such session")
	case SessionRevoked:
		return nil
	case SessionExpired:
		// Already over. Recording a revocation would produce a tombstone for a
		// session nothing can use, and the access projector would then have a
		// confirmation to wait for that no one will ever send.
		return nil
	}
	eventsourcing.Record(s, &contract.SessionRevoked{
		SessionID: s.id.String(),
		SubjectID: s.subjectID,
		ActorID:   actorID,
		Reason:    reason,
		RevokedAt: at.UTC(),
	})
	return nil
}

// Expire records a deadline having been reached.
//
// Called by the sweep, not by the request path: a request that finds an expired
// session refuses it and moves on. Appending an event from a read would make
// every unauthenticated poll a write.
//
// idleDeadline comes from the read model, because the log does not hold the
// current one — see Live.
func (s *Session) Expire(now, idleDeadline time.Time) error {
	absolute, expired := s.ExpiredReason(now, idleDeadline)
	if !expired {
		return errs.Conflictf("this session has not expired")
	}
	eventsourcing.Record(s, &contract.SessionExpired{
		SessionID: s.id.String(),
		SubjectID: s.subjectID,
		Absolute:  absolute,
		ExpiredAt: now.UTC(),
	})
	return nil
}
