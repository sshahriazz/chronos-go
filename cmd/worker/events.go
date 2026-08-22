package main

import (
	"strings"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/identity"
	identityevents "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgevents "github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profilecontract "github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspaceevents "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// This file is the whole answer to "what notifies whom, and where does it come
// from?".
//
// Two declarations, side by side on purpose:
//
//   - registerEvents says which events this binary can DECODE.
//   - notifications says, for each event the REPOSITORY defines, whether it
//     notifies and to whom.
//
// The difference between those two scopes is the bug this file was rewritten to
// fix. Until it was, registerEvents listed five notification-module types and
// the completeness test verified the catalogue against `codec.Types()` — the
// same five. It read as "every event has a notification decision" and meant
// "every event I remembered to register has one". Identity's twenty-nine event
// types were in neither list, so nine Sec-class alerts the catalogue is
// supposed to guarantee — password changed, second factor disabled, recovery
// codes used, account suspended — were absent with no test able to say so.
//
// events_test.go now derives the event universe from the SOURCE (see
// eventUniverse) rather than from this file, so forgetting a registration here
// fails the build instead of quietly shrinking what the guard checks.
func registerEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.NotificationCreated](codec)
	eventcodec.Register[contract.NotificationRead](codec)
	eventcodec.Register[contract.PushSubscribed](codec)
	eventcodec.Register[contract.PushSubscriptionExpired](codec)
	eventcodec.Register[contract.PushSent](codec)
	eventcodec.Register[contract.ChannelPreferenceSet](codec)

	// Identity registers its own types from the module's composition surface,
	// exactly as cmd/projector does. Listing them here instead would be a
	// second place to forget one — and forgetting one is silent: the reactor
	// cannot decode the event, so the notification is never sent, no error is
	// raised and no metric moves.
	identity.RegisterEvents(codec)
	profile.RegisterEvents(codec)
	organization.RegisterEvents(codec)
	workspace.RegisterEvents(codec)
}

// notifications declares what each event sends, and to whom.
//
// Every entry names four things and cannot omit any of them: the event (from
// the type parameter), the wording, the class that decides whether it is
// delivered at all, and the audience that decides who receives it.
//
// An event that should tell nobody is declared too, WITH A REASON. "No entry"
// is ambiguous between "decided against" and "nobody thought about it", and the
// second is the one that ships a security event nobody is ever told about.
//
// # Delivery is idempotent by construction, not by anything written here
//
// The reactor keys every delivery on `<event id>:<recipient index>`
// (notify/reactor.go). That key is the Temporal workflow id, so a redelivered
// event asks to start a run that already exists and is refused — which the
// reactor treats as success, because the work was already done. Below Temporal,
// the persistent subscription's own `reactor_processed` row deduplicates the
// event before React is called at all. Neither depends on the entry, so every
// entry added here inherits both.
func notifications() *notify.Catalogue {
	cat := notify.NewCatalogue()

	identityNotifications(cat)
	notificationModuleNotifications(cat)

	return cat
}

// identityNotifications is NOTIFICATIONS.md §5, expressed as code.
//
// The doc's tables are the specification; the deviations from them are all in
// one direction and all for the same reason — a catalogue entry sees ONE
// decoded event and nothing else. It cannot ask a read model whether a device
// is new, whether a threshold was crossed, or how many sessions a revocation
// ended. Where the doc qualifies an alert with a condition of that kind, the
// entry is attached to the event that already carries the condition as a fact,
// and the qualified event is declared silent pointing at it.
func identityNotifications(cat *notify.Catalogue) {
	// ---------------------------------------------------------------------
	// Somebody tried to register with an address this account already holds.
	//
	// SECURITY class. It is the only signal the address's owner ever gets that
	// somebody is trying to create an account with it — the wire answer to the
	// person attempting it is deliberately empty (identity.md §11), so this mail
	// is the entire disclosure, and it goes to the mailbox because controlling
	// the mailbox is what proves the right to know.
	//
	// It is also the returning user's way out of a dead end: before this existed
	// the screen said "check your email" and no mail was ever sent, which is the
	// branch a returning user hits most often.
	//
	// Only a VERIFIED claim produces it (see the event's own doc): mailing an
	// address whose claim nobody has proven is unsolicited mail to somebody who
	// never asked for it and never showed they can read it.
	cat.On[identityevents.DuplicateRegistrationAttempted](notify.Spec{
		Template: "identity.duplicate_registration_attempted",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.DuplicateRegistrationAttempted) map[string]any {
		// AttemptedAt and nothing else. The index is a keyed HMAC and the
		// attempting party is unauthenticated and unnamed — there is nothing
		// truthful to say about who tried, and inventing a hint would be worse
		// than silence.
		return map[string]any{"AttemptedAt": e.AttemptedAt}
	})

	// Profile — display name, locale, timezone, avatar (ADR-056)
	// ---------------------------------------------------------------------

	// SECURITY, not Activity, and the class is the whole decision.
	//
	// A display name and a picture are how colleagues recognise a person — in a
	// mention, in an invitation, in a member list. Somebody holding a stolen
	// session who changes them is impersonating the holder to everyone they work
	// with, and the holder is the only person who can notice. Security class is
	// what makes this alert unsuppressable by any preference (see
	// domain.AlwaysDeliveredClasses); as Activity it could be switched off, and an
	// attacker's first move would be to switch it off.
	//
	// The data names FIELDS, never values. A value here is personal data leaving
	// the vault and entering a template, which is the one thing ADR-002 forbids
	// this path from doing.
	cat.On[profilecontract.ProfileUpdated](notify.Spec{
		Template: "profile.profile_updated",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *profilecontract.ProfileUpdated) map[string]any {
		var changed []string
		if e.DisplayName != nil {
			changed = append(changed, "display name")
		}
		if e.Locale != nil {
			changed = append(changed, "language")
		}
		if e.Timezone != nil {
			changed = append(changed, "timezone")
		}
		if e.Avatar != nil {
			if e.Avatar.Change == profilecontract.Cleared {
				changed = append(changed, "picture removed")
			} else {
				changed = append(changed, "picture")
			}
		}
		return map[string]any{"Fields": strings.Join(changed, ", ")}
	})

	// Username reservation — the public handle (ADR-051)
	// ---------------------------------------------------------------------
	//
	// All three are Silent for the same reason the email-reservation trio below
	// is: they are the uniqueness mechanism, not facts a person acts on.

	cat.Silent[identityevents.UsernameReserved](
		"the uniqueness mechanism for the public handle (ADR-051), the same role " +
			"EmailReserved plays for an address. The account-side fact is " +
			"UsernameAssigned, and at signup that rides the same append as " +
			"EmailVerified, which is the entry that mails the person")
	cat.Silent[identityevents.UsernameAssigned](
		"claimed in the same request as the proof and the first password (ADR-051), so " +
			"it rides the append that EmailVerified already mails about. Telling somebody " +
			"the handle they just chose is circular. A LATER change of handle is a " +
			"different fact — an impersonation risk worth alerting on — and there is no " +
			"command that performs one yet; this becomes an On the day there is")
	cat.Silent[identityevents.UsernameTombstoned](
		"records that a handle may never be reissued, which is what stops an erased " +
			"person's mentions re-pointing at a stranger (ADR-051). Its cause is erasure, " +
			"so the subject it concerns has deliberately been made unreachable — there is " +
			"nobody left to notify, and the key that would resolve an address is destroyed")

	// Email reservation — internal to identity (ADR-044)
	// ---------------------------------------------------------------------

	cat.Silent[identityevents.EmailReserved](
		"the uniqueness mechanism, internal to identity (ADR-044). It records a claim on " +
			"an address nobody has proven yet; the account-side fact a person can act on " +
			"is UserRegistered, and NOTIFICATIONS §5 forbids mailing an unverified address")
	cat.Silent[identityevents.EmailReservationConfirmed](
		"bookkeeping that makes an address claim permanent. It rides the same proof as " +
			"EmailVerified, which is the entry that mails the person")
	cat.Silent[identityevents.EmailReleased](
		"a fact about an address, not about an account. Its routine cause is an unverified " +
			"reservation lapsing — mailing that address would be unsolicited mail to " +
			"someone who never asked (NOTIFICATIONS §5) — and its other two causes, an " +
			"address change and an erasure, notify from the account-side event")

	// ---------------------------------------------------------------------
	// Account lifecycle
	// ---------------------------------------------------------------------

	cat.Silent[identityevents.UserRegistered](
		"the verification mail is the notification a registration produces, and it is " +
			"triggered by EmailVerificationRequested, which rides the same append. An " +
			"entry here would mail the same person twice about one registration — and " +
			"the second copy could not carry a link, because a catalogue entry cannot " +
			"mint a token")
	cat.Silent[identityevents.EmailVerificationRequested](
		"delivered by the verification-mail reactor (cmd/worker/verification.go), on its " +
			"own subscription group, because the message's payload is a credential that " +
			"does not exist yet and cannot be derived from anything the event carries. A " +
			"catalogue entry would send a second, link-less copy of a mail whose entire " +
			"purpose is the link")

	// The welcome fires on VERIFICATION, not registration: mailing an
	// unverified address is unsolicited mail to someone who may not have asked
	// for it, and confirms to whoever typed the address that it exists
	// (NOTIFICATIONS §5).
	cat.On[identityevents.EmailVerified](notify.Spec{
		Template: "identity.welcome",
		Class:    notify.Transactional,
		Audience: notify.AudienceSubject,
	}, nil)

	cat.Silent[identityevents.UserActivated](
		"activation is the conjunction of two facts that each notify on their own — the " +
			"address was proven (EmailVerified) and a second factor was enrolled " +
			"(TotpEnabled). A third message repeating both is noise, and noise in a " +
			"security stream is what trains people to ignore the message that matters")

	// The ONLY signal that somebody scheduled this account for erasure.
	//
	// Notified rather than Silent because the request needs no session state the
	// holder can see: the account keeps working through the grace period, so
	// nothing in the product tells them. A compromised session could otherwise
	// queue a deletion and the owner would first learn when the account was gone.
	//
	// The template deliberately offers NO cancel link. NOTIFICATIONS §4 describes
	// one ("Deletion scheduled for date — cancel"), and nothing implements it:
	// there is no cancel command and no UserDeletionCancelled event (identity.md
	// §1.1). A link to a route that does not exist is worse than no link, so the
	// message names the two things that DO work and take effect immediately —
	// revoking every session and changing the password — and sends them to
	// support for the deletion itself.
	cat.On[identityevents.UserDeletionRequested](notify.Spec{
		Template: "identity.account_deletion_requested",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.UserDeletionRequested) map[string]any {
		return map[string]any{"ByAnotherParty": actedOnBehalf(e.ActorID, e.SubjectID)}
	})

	cat.On[identityevents.UserDeactivated](notify.Spec{
		Template: "identity.account_deactivated",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.UserDeactivated) map[string]any {
		return map[string]any{"ByAnotherParty": actedOnBehalf(e.ActorID, e.SubjectID)}
	})

	// Not in the doc's table, and deliberately added: deactivation is
	// reversible by the holder, so an attacker who has an account's credentials
	// can undo the very step a worried owner took. Telling nobody about the
	// reversal would make the deactivation alert the more useful half of a pair
	// whose other half is silent.
	cat.On[identityevents.UserReactivated](notify.Spec{
		Template: "identity.account_reactivated",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.UserReactivated) map[string]any {
		return map[string]any{"ByAnotherParty": actedOnBehalf(e.ActorID, e.SubjectID)}
	})

	// Reason is NOT passed to the template. It is an operator-entered string
	// with no constrained vocabulary, and a mail is the one place a note
	// written for an internal audit trail must not surface verbatim.
	cat.On[identityevents.UserSuspended](notify.Spec{
		Template: "identity.account_suspended",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	// ---------------------------------------------------------------------
	// Password
	// ---------------------------------------------------------------------

	// Found by this file's own completeness guard, minutes after it was fixed:
	// identity added this event while the catalogue was being written, and the
	// build failed naming it. That is the mechanism working — under the previous
	// guard, which verified against the five types the worker happened to
	// register, it would have arrived silently.
	cat.Silent[identityevents.PasswordResetRequested](
		"structurally identical to EmailVerificationRequested: the message IS a freshly " +
			"minted token, and a catalogue Data function sees only the decoded event — " +
			"which deliberately carries neither the token nor its digest, because a reset " +
			"token grants account access and a permanent replicated log is the last place " +
			"it may appear. Delivery therefore belongs to a minting reactor with its own " +
			"subscription group, as verification mail has (cmd/worker/verification.go); an " +
			"entry here could only send a reset mail with no link in it")

	cat.Silent[identityevents.PasswordSet](
		"identity emits this only from Registration.VerifyEmail — the sole caller of " +
			"domain.User.SetPassword, which the aggregate refuses on an unproven address " +
			"(IDENTITY-REVIEW C8). It therefore lands in the SAME append as EmailVerified, " +
			"every time, so the escalation NOTIFICATIONS §5 describes — a password " +
			"appearing on an established passwordless account — cannot happen yet. A " +
			"message saying 'a password was added' would arrive beside the welcome mail, " +
			"about the password the reader had just chosen. This entry must become an " +
			"On the day a federated account can add one")

	cat.On[identityevents.PasswordChanged](notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.PasswordChanged) map[string]any {
		// ViaReset changes the wording, not the decision to send: a change made
		// by someone who knew the old password and a change made through a
		// reset link read very differently to a person who did neither.
		return map[string]any{"ViaReset": e.ViaReset}
	})

	cat.Silent[identityevents.PasswordRehashed](
		"a transparent upgrade of the stored verifier on a successful login. Nothing the " +
			"account holder did, nothing about their credentials changed, and nothing " +
			"they could act on. It exists as evidence the rehash job runs, which is an " +
			"operator question answered by a metric rather than by mail")

	cat.On[identityevents.CredentialCompromiseDetected](notify.Spec{
		Template: "identity.credential_compromised",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.CredentialCompromiseDetected) map[string]any {
		// The corpus name, never the password and never the match. Source is a
		// provider identifier, which is why it is safe to render.
		return map[string]any{"Source": e.Source}
	})

	// ---------------------------------------------------------------------
	// Second factors
	// ---------------------------------------------------------------------

	cat.Silent[identityevents.TotpEnrollmentStarted](
		"a secret provisioned but not yet proven — the user is looking at the QR code as " +
			"this is written. An abandoned enrollment expires without ever having changed " +
			"the account, so the fact worth mailing is TotpEnabled")

	cat.On[identityevents.TotpEnabled](notify.Spec{
		Template: "identity.totp_enabled",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	// The highest-value alert in the catalogue (NOTIFICATIONS §5): disabling a
	// second factor is the step an attacker takes immediately after taking over
	// an account, and this mail is what tells the victim it happened.
	cat.On[identityevents.TotpDisabled](notify.Spec{
		Template: "identity.totp_disabled",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.TotpDisabled) map[string]any {
		return map[string]any{"ByAnotherParty": actedOnBehalf(e.ActorID, e.SubjectID)}
	})

	cat.On[identityevents.RecoveryCodesGenerated](notify.Spec{
		Template: "identity.recovery_codes_generated",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.RecoveryCodesGenerated) map[string]any {
		// The count, never a code. Regeneration replaces the whole set, so a
		// person who did not do this has lost every code they held.
		return map[string]any{"Count": e.Count}
	})

	// NOTIFICATIONS §5 lists "running low on recovery codes" as a separate
	// Activity message with no trigger event of its own. It is folded in here
	// instead of invented as a second mail: Remaining is on the event, so the
	// same message that reports the use can report how many are left — and one
	// message about one fact beats two.
	cat.On[identityevents.RecoveryCodeConsumed](notify.Spec{
		Template: "identity.recovery_code_used",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.RecoveryCodeConsumed) map[string]any {
		return map[string]any{"Remaining": e.Remaining, "Low": e.Remaining <= lowRecoveryCodes}
	})

	cat.On[identityevents.RecoveryCodesExhausted](notify.Spec{
		Template: "identity.recovery_codes_exhausted",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	// ---------------------------------------------------------------------
	// Authentication outcomes
	// ---------------------------------------------------------------------

	cat.Silent[identityevents.AuthenticationSucceeded](
		"NOTIFICATIONS §5 restricts the sign-in alert to a NEW device or country, and says " +
			"why: alerting on every login trains people to ignore the alert, which " +
			"destroys the value of the one that matters. This event is emitted on every " +
			"successful login and carries a DeviceID but no way to tell whether it is new " +
			"— that is a read-model question, and a catalogue entry sees one decoded event. " +
			"The new-device half of the condition is already a first-class fact: " +
			"DeviceRegistered, which identity emits the first time a client is seen under " +
			"an account, and which is where the alert is attached. The country half needs " +
			"a location the event does not carry")

	cat.Silent[identityevents.AuthenticationFailed](
		"NOTIFICATIONS §5 asks for an AGGREGATED alert when a threshold is crossed. One " +
			"refusal is not a threshold and a catalogue entry cannot count, so an entry " +
			"here would mail on every mistyped password — the exact noise the aggregation " +
			"exists to avoid. The crossing is already an event: AuthenticatorDisabled, " +
			"emitted when an authenticator locks out, carrying the failure count, and that " +
			"is where the alert is attached. This event also has an EMPTY SubjectID when " +
			"the identifier matched no account, so there is frequently nobody to notify")

	cat.Silent[identityevents.SecondFactorChallenged](
		"the person is mid-login, looking at the prompt this records. It exists so that an " +
			"abandoned login — first factor correct, second never supplied — is visible as " +
			"the credential-stuffing signal it is, which is a detection concern rather " +
			"than a message to the account holder")

	// This is NOTIFICATIONS §5's "repeated failed sign-in attempts", attached to
	// the event that means the threshold was actually crossed. Per
	// authenticator, never per account — locking the account on failed attempts
	// would hand any attacker a denial of service against any address.
	cat.On[identityevents.AuthenticatorDisabled](notify.Spec{
		Template: "identity.authenticator_disabled",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *identityevents.AuthenticatorDisabled) map[string]any {
		return map[string]any{"Failures": e.Failures}
	})

	// ---------------------------------------------------------------------
	// Sessions and devices
	// ---------------------------------------------------------------------

	cat.Silent[identityevents.SessionCreated](
		"one per login, so an entry here is the every-login alert §5 forbids. The " +
			"new-device signal it would be a proxy for is DeviceRegistered")
	cat.Silent[identityevents.SessionElevated](
		"a step-up ceremony the person completed themselves, seconds earlier, in the flow " +
			"that demanded it. The operation the elevation was granted FOR is what " +
			"notifies — disabling a second factor requires step-up, and TotpDisabled is " +
			"the mail that matters")
	cat.Silent[identityevents.SessionRevoked](
		"emitted once per session, and §5 asks for one message saying 'signed out of n " +
			"devices'. n is not derivable from a single event, so an entry here would send " +
			"one mail per device to someone who pressed 'sign out everywhere' once. The " +
			"causes that carry real risk already notify from their own event: a reset " +
			"through PasswordChanged, a compromise through CredentialCompromiseDetected. " +
			"Closing this properly needs an aggregate event identity does not yet emit")
	// ── organization ───────────────────────────────────────────────────────
	//
	// Every organization event is SILENT for now, and that is a deliberate
	// staging decision rather than a claim that none of them is worth a message.
	// Several plainly are — a suspension and a closure both end somebody's
	// access — but the audience for an organization event is the OWNER and the
	// ADMIN SET, and notify has AudienceSubject only. Sending to a set is
	// resolving a membership, which is `workspace`'s job and does not exist yet.
	//
	// Declaring them silent with the reason recorded is what keeps this
	// catalogue honest: the gate demands a decision per event, so the choice is
	// visible in review instead of being an event nobody considered. Each of
	// these becomes an `On` when there is a set to address.

	cat.Silent[orgevents.OrganizationCreated](
		"the creator is looking at the screen that created it, and the org is not usable " +
			"until the trial starts. The message worth sending is the welcome, and that " +
			"belongs to TrialStarted, which is the point the tenant actually works")
	cat.Silent[orgevents.OrganizationTrialStarted](
		"the welcome and the trial-end date belong here, and this becomes an On the moment " +
			"there is an owner address to resolve. It is silent today because the audience " +
			"is the owner and notify addresses a SUBJECT — which is the same thing here, " +
			"and will stop being so as soon as admins exist")
	cat.Silent[orgevents.OrganizationActivated](
		"Stripe already emails a receipt for the payment that caused it. A second message " +
			"saying the same thing is the duplicate-dunning mistake billing.md §5 case 5 " +
			"refuses for retries, applied to conversions")
	cat.Silent[orgevents.OrganizationPastDue](
		"Stripe Smart Retries owns the dunning schedule and sends the mail. Adding ours " +
			"double-messages a customer who is already anxious about a failed card " +
			"(billing.md §5 case 5)")
	cat.Silent[orgevents.OrganizationSuspended](
		"the one most likely to become an On, and it needs an audience first: suspension " +
			"ends access for every member, not just the owner. Sending it to the owner " +
			"alone would tell the one person who can fix it and nobody who is affected")
	cat.Silent[orgevents.OrganizationClosed](
		"closure is the owner's own deliberate act, and the export window it opens is what " +
			"needs communicating. That message has a deadline in it, so it belongs to the " +
			"closure saga's timer rather than to the instant of the event")
	cat.Silent[orgevents.OrgAdminAdded](
		"an authority change worth telling the RECIPIENT about — being made an admin is a " +
			"fact about them. It is silent only until the audience exists; the pattern to " +
			"copy is identity's, where a change to someone's own authority is Security class")
	// ── workspace ──────────────────────────────────────────────────────────
	//
	// Silent for the same reason organization's are: the audience for a
	// workspace event is its MEMBERS, and notify addresses a SUBJECT. Resolving
	// a membership is exactly what this module will provide and does not yet —
	// there are no members, only admins inside the aggregate. Each becomes an
	// `On` when there is a set to address.
	cat.Silent[workspaceevents.WorkspaceCreated](
		"the creator is looking at the screen that created it. The message worth sending is " +
			"to the OTHER members, and there are none until invitations exist")
	cat.Silent[workspaceevents.WorkspaceRenamed](
		"a display-name change. Worth a realtime nudge on the workspace channel rather than " +
			"mail, and that is the projector's publish, not a notification")
	cat.Silent[workspaceevents.WorkspaceArchived](
		"read-only from now on, which every member needs to know — and which needs a member " +
			"list to tell. Archiving is reversible and destroys nothing, so the urgency is " +
			"lower than a suspension")
	cat.Silent[workspaceevents.WorkspaceRestored](
		"the reverse, and the same audience problem")
	// Membership. These are the ones with a real audience — the person joining
	// or leaving is a SUBJECT, which notify can already address — and they are
	// silent only because there is no way in yet: an admin adds an existing
	// organization member, and telling somebody they were added to a workspace
	// they can already see is noise. They become `On` with invitations, where
	// the recipient is somebody who does not yet know the workspace exists.
	cat.Silent[workspaceevents.MemberJoined](
		"today this can only add somebody already in the organization, who can already see " +
			"the workspace list. The message that matters is the INVITATION, which is a " +
			"different event and does not exist yet")
	cat.Silent[workspaceevents.MemberRoleChanged](
		"a change in what somebody may do, which they should hear about — and which becomes " +
			"Security class alongside identity's own authority changes when the audience is " +
			"wired")
	cat.Silent[workspaceevents.MemberRemoved](
		"losing access silently is how somebody discovers it by being refused. It is also " +
			"the event whose seat accounting matters most, and the notification and the " +
			"seat are independent — the seat is returned whether or not any mail is sent")

	// Invitations. Unlike every other workspace event above, these have NO
	// audience problem: an invitation is issued to a SubjectID, which is exactly
	// what notify addresses, and the vault resolves it to an address at send
	// time. They are silent because the message itself does not exist yet — the
	// template, and the activity that renders a link carrying a live credential,
	// are the next step in this slice (WORKLIST 5g). InvitationIssued and
	// InvitationTokenRotated become `On` there, and they are the first workspace
	// events that will.
	// These two DO notify, and the catalogue is deliberately not where it
	// happens. Their payload is a live credential that does not exist when the
	// event is written — a Data function here receives only the decoded event,
	// and there is no way back from a digest — so the link has to be MINTED by
	// whoever sends the mail. That is workspace/reactor.InvitationMail, on its
	// own subscription group, exactly as identity's verification mail is.
	//
	// Recorded here as Silent-with-a-reason rather than omitted, because the
	// completeness gate's question is "does every event have a decision", and
	// "another component owns this one" is a decision.
	cat.Silent[workspaceevents.InvitationIssued](
		"handled by workspace-invitation-mail, which MINTS the link before sending it. A " +
			"catalogue entry cannot: its Data function sees only the decoded event, and " +
			"the event deliberately carries no token (ADR-002)")
	cat.Silent[workspaceevents.InvitationTokenRotated](
		"the same reactor and the same mail with a new link. Rate-limiting a resend " +
			"belongs at the command, not here — a notification decision cannot stop " +
			"somebody pressing the button")
	cat.Silent[workspaceevents.InvitationAccepted](
		"the acceptor is looking at the screen that accepted it. What is worth sending is " +
			"the INVITER's confirmation that their invitation was taken up, and that " +
			"audience is the workspace's admins rather than a subject")
	cat.Silent[workspaceevents.InvitationDeclined](
		"the same audience, and the more useful of the two: an inviter who is not told a " +
			"decline happened will chase somebody who has already said no")
	cat.Silent[workspaceevents.InvitationRevoked](
		"telling somebody an invitation they may never have opened has been withdrawn " +
			"invites a question nobody wants to answer. The seat is what matters here, and " +
			"the seat is returned whether or not any mail is sent")
	cat.Silent[workspaceevents.InvitationExpired](
		"a reminder BEFORE the deadline is the message worth sending, and that is the " +
			"workflow's timer rather than this event — by the time this fires the window " +
			"has already closed")
	cat.Silent[workspaceevents.InvitationUndeliverable](
		"the inviter must be told, or they resend forever — workspace.md §5 says so " +
			"explicitly. It stays silent only because the address it would report is " +
			"personal data, so the message has to name the invitation rather than quote " +
			"the address, and that template is 5g's")

	cat.Silent[workspaceevents.WorkspaceAdminAdded](
		"an authority change worth telling the RECIPIENT about, which is a subject notify " +
			"can already address. It stays silent only because the workspace has no member " +
			"list to place them in yet; this is the first of these to become an On")
	cat.Silent[workspaceevents.WorkspaceAdminRemoved](
		"the more important half: losing administration silently is how somebody discovers " +
			"it by being refused. Security class when it lands")

	// The four reservation events are the uniqueness MECHANISM, not facts a
	// person acts on — the same call identity's EmailReserved and
	// UsernameReserved trio gets, for the same reason. What a person hears about
	// is the organization, and that is OrganizationCreated's business.
	cat.Silent[orgevents.OwnerReservationHeld](
		"the one-organization-per-subject invariant, held on a stream named after the " +
			"subject. Telling somebody they now own the organization they just created is " +
			"circular")
	cat.Silent[orgevents.OwnerReservationReleased](
		"the same claim being freed when an organization closes. The closure is the fact, " +
			"and it has its own message")
	cat.Silent[orgevents.SlugReservationHeld](
		"slug uniqueness, claimed in the same atomic append as the organization itself")
	cat.Silent[orgevents.SlugReservationReleased](
		"a slug returning to the pool on closure")

	cat.Silent[orgevents.OrgAdminRemoved](
		"the same, and the more important half: losing administration silently is how " +
			"somebody discovers it by being refused. Security class when it lands")

	cat.Silent[identityevents.SessionExpired](
		"a deadline being reached. The contract's own comment says it: expiry is not a " +
			"security signal and revocation usually is, and collapsing the two would bury " +
			"every real revocation in routine noise")

	// NOTIFICATIONS §5's "new sign-in from device, city", attached to the event
	// that means the device is actually new.
	//
	// The mail names no device and no city. DeviceID is a pseudonym; the name,
	// platform, user agent and address are personal data held in the vault under
	// it (ADR-002), and the vault port resolves a SUBJECT, not a device. The
	// message therefore says that an unrecognised client signed in and sends the
	// reader to their own sessions page, which is the honest version of a
	// message that cannot see the detail.
	cat.On[identityevents.DeviceRegistered](notify.Spec{
		Template: "identity.new_device",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)
}

// notificationModuleNotifications covers the notification module's OWN events.
//
// They notify nobody. They are operational records of delivery — that a feed
// item was created, that a push was sent — and notifying about them would be a
// loop: a notification about a notification, which itself notifies
// (notification.md §10).
func notificationModuleNotifications(cat *notify.Catalogue) {
	cat.Silent[contract.NotificationCreated]("operational record of in-app delivery; notifying about it would recurse")
	cat.Silent[contract.NotificationRead]("the recipient read it; telling them so is circular")
	cat.Silent[contract.PushSubscribed]("the person just granted permission in the browser; they know")
	cat.Silent[contract.PushSubscriptionExpired]("a dead endpoint is an operational fact, surfaced in-app if it matters")
	cat.Silent[contract.PushSent]("operational record of push delivery")
	cat.Silent[contract.ChannelPreferenceSet](
		"the person just changed their own notification settings, so telling them so is " +
			"circular — the same reason PushSubscribed is silent. This is safe ONLY because " +
			"the preference surface cannot switch off a Security-class alert: that boundary " +
			"is enforced in app.Preferences and guarded from the other side by " +
			"TestAccountSafetyAlertsCannotBeSwitchedOff. If either is ever relaxed, an " +
			"attacker holding a session could silence the alerts and then act quietly, and " +
			"this entry becomes the last thing standing between them and a silent takeover — " +
			"at which point it must become an On")
}

// lowRecoveryCodes is when "you are running low" starts appearing in the mail
// that reports a code being used (NOTIFICATIONS §5).
const lowRecoveryCodes = 2

// actedOnBehalf reports whether somebody OTHER than the account holder did this.
//
// It returns a bool rather than the actor, and that is the point: ActorID is a
// pseudonym and would be meaningless in a mail, but "an administrator did this,
// not you" is the single most important thing the message can say. An empty
// actor reads as the holder — identity sets ActorID to the subject for
// self-service, and treating "unknown" as "someone else" would tell people an
// administrator touched their account whenever metadata was incomplete.
func actedOnBehalf(actorID, subjectID string) bool {
	return actorID != "" && actorID != subjectID
}

// audiences maps each role to the thing that can answer it.
//
// An audience with no resolver stays UNANSWERABLE and parks the notification,
// rather than being approximated. That is deliberate: notifying the wrong
// person is worse than notifying nobody, and a parked event is visible where a
// wrong recipient is not.
//
// AudienceOrgOwner and AudienceOrgAdmins are absent until the organization
// module lands with a read model that can answer them. Any catalogue entry using
// them parks until then — loudly, and by design.
func audiences(operator string) *notify.Registry {
	subject := notify.SubjectAudiences{Operator: operatorRecipients(operator)}
	return notify.NewRegistry().
		Register(notify.AudienceSubject, subject).
		Register(notify.AudienceActor, subject).
		Register(notify.AudienceOperator, subject)
}

// operatorRecipients is who receives Operator-class alerts — a stopped
// projection, a parked backlog. Never a tenant, and never carrying tenant
// personal data (NOTIFICATIONS §4).
func operatorRecipients(address string) []notify.Recipient {
	if address == "" {
		return nil
	}
	return []notify.Recipient{{Address: address, Locale: "en", Timezone: "UTC"}}
}

// notificationReactorName is the persistent subscription group and is
// PERMANENT. Renaming it creates a fresh group starting at the end of the log,
// silently abandoning anything the old one had not yet delivered (ADR-019).
const notificationReactorName = "notifications"
