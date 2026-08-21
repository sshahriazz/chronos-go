package main

import (
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	notificationpg "github.com/chronos/chronos-go/internal/modules/notification/adapter/postgres"
	notificationapi "github.com/chronos/chronos-go/internal/modules/notification/api"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// buildNotification assembles the notification service, or explains why it could
// not be built.
//
// The module's tables were filled by projectors for a long time before anything
// could read them: the feed, the push subscriptions and the per-person channel
// preferences all existed, were written on every delivery, and were reachable by
// no client at all. This function is what ends that, and it is the reason the
// composition-root test asserts the service is registered rather than merely
// constructible — a notification API wired into nothing looks identical from
// every unit test and delivers nothing.
//
// Failure is loud and NOT fatal, like every other wiring failure in this binary
// (ADR-010). The consequence is stated at the call site rather than here.
func (d *dependencies) buildNotification(
	cfg *config.Config, log *slog.Logger,
) (*notificationapi.Service, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: the feed, the push subscriptions and the " +
			"preferences are all projections, so there is no read side without it")
	}
	if d.store == nil {
		return nil, errors.New("no event store: marking a notification read, registering a " +
			"push endpoint and setting a preference are all appends, and a handler that " +
			"wrote the projection directly would be writing the answer instead of the fact")
	}

	tx := pgadapter.New(d.pool)

	// One read model serving both reader ports. They are the same rows reached by
	// the same transaction helper, and splitting them would be two access paths to
	// audit where the module has one.
	reads, err := notificationpg.NewReadModel(tx)
	if err != nil {
		return nil, fmt.Errorf("notification read model: %w", err)
	}

	// The SAME codec and upcaster registry the rest of this binary uses. A second
	// pair here would let an event be registered for writing and not for reading —
	// a command that appends something this process cannot load back.
	prefRepo := eventsourcing.NewRepository[*domain.Preferences](
		d.store, d.codec, d.upcasters, domain.Category, domain.NewPreferences)

	queries, err := app.NewQueries(app.QueriesDeps{
		Feed:        reads,
		Preferences: reads,
	})
	if err != nil {
		return nil, fmt.Errorf("notification queries: %w", err)
	}

	inbox, err := app.NewInbox(app.InboxDeps{
		Feed:    reads,
		Appends: d.store,
		Clock:   d.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("notification inbox: %w", err)
	}

	push, err := app.NewPushRegistry(app.PushRegistryDeps{
		Appends: d.store,
		Clock:   d.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("notification push registry: %w", err)
	}

	prefs, err := app.NewPreferences(app.PreferencesDeps{
		Repo:   prefRepo,
		Reader: reads,
		Clock:  d.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("notification preferences: %w", err)
	}

	// Rendered as NAMES, not as the values. notify.Class is a uint8, so a
	// []Class is a []byte and slog base64-encodes it — the field came out as
	// "AQI=", which is worse than omitting it: it looks like information.
	alwaysDelivered := make([]string, 0, len(domain.AlwaysDeliveredClasses()))
	for _, c := range domain.AlwaysDeliveredClasses() {
		alwaysDelivered = append(alwaysDelivered, c.String())
	}

	log.Info("notification service constructed",
		"governable_channels", domain.Governable(),
		// Named at startup because it is the boundary a reader of the settings
		// screen most needs to know: these classes are delivered whatever the
		// person has switched off, and the list is derived from the dispatcher's
		// own predicate rather than written out here.
		"always_delivered", alwaysDelivered)

	return notificationapi.New(notificationapi.Deps{
		Queries:     queries,
		Inbox:       inbox,
		Push:        push,
		Preferences: prefs,
	})
}
