// Package centrifugo delivers realtime messages over Centrifugo's gRPC API.
//
// The client is generated from Centrifugo's own api.proto, vendored under
// third_party/, so the call surface is theirs rather than something hand-rolled
// that drifts. They ship an official HTTP client (gocent) and no pre-generated
// Go gRPC client — gRPC clients are generated per language, and the proto is
// the published contract.
//
// BOTH were built and benchmarked against the running server before choosing,
// because ADR-037 is a default and not a reason:
//
//	                        gRPC          HTTP SDK
//	single, small payload   361 us        308 us      HTTP
//	single, 4 KB payload    392 us        488 us      gRPC — and 6 KB vs 34 KB allocated
//	concurrent publishers    67 us         66 us      tie
//	batch of five           ~500 us       ~800 us     gRPC
//	presence                354 us        292 us      HTTP
//
// The HTTP client wins only for small single calls against an idle server. This
// system is realtime-FIRST: fan-out to many channels, payloads that vary, and
// volume. gRPC wins the batch and large-payload cases, ties under concurrency,
// and allocates 5.6x less at 4 KB because gocent JSON- and base64-encodes the
// payload while gRPC carries bytes natively — which is GC pressure at rate.
//
// If realtime ever becomes low-volume small-message-only, the numbers above are
// what to re-measure against.
package centrifugo

import (
	"context"
	"errors"
	"fmt"
	"time"

	pb "github.com/chronos/chronos-go/gen/thirdparty/centrifugo"
	"github.com/chronos/chronos-go/internal/platform/realtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// Publisher sends messages and reads presence.
type Publisher struct {
	client pb.CentrifugoApiClient
	apiKey string
	obs    Observer
}

// Observer records outcomes. Optional.
type Observer interface {
	Published(namespace string)
	Failed(namespace string)
}

type noObserver struct{}

func (noObserver) Published(string) {}
func (noObserver) Failed(string)    {}

var (
	_ realtime.Publisher = (*Publisher)(nil)
	_ realtime.Presence  = (*Publisher)(nil)
)

// Dial builds a client.
//
// It does NOT connect: gRPC dials lazily and reconnects on its own, which lets
// a process start while Centrifugo is still coming up (ADR-010).
func Dial(endpoint string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Keepalive matters for a realtime-first system: the publish path is
		// bursty, and an idle HTTP/2 connection reaped by a proxy would cost a
		// reconnect on the first publish after a quiet period — exactly when a
		// user is waiting to see something appear.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("centrifugo: %w", err)
	}
	return conn, nil
}

func New(conn *grpc.ClientConn, apiKey string, obs Observer) *Publisher {
	if obs == nil {
		obs = noObserver{}
	}
	return &Publisher{client: pb.NewCentrifugoApiClient(conn), apiKey: apiKey, obs: obs}
}

// authed attaches the API key. Centrifugo authenticates server-API calls by
// metadata: `authorization: apikey <KEY>`.
func (p *Publisher) authed(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "apikey "+p.apiKey)
}

// Publish delivers one message.
//
// A failure is reported but must not fail whatever triggered it: realtime is
// best-effort by nature, and the projection remains the record a browser
// recovers from.
func (p *Publisher) Publish(ctx context.Context, msg realtime.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	resp, err := p.client.Publish(p.authed(ctx), &pb.PublishRequest{
		Channel: msg.Channel.String(),
		Data:    msg.Data,
		// Lets Centrifugo collapse a retried publish rather than showing the
		// same toast twice.
		IdempotencyKey: msg.IdempotencyKey,
	})
	if err != nil {
		p.obs.Failed(msg.Channel.Namespace())
		return fmt.Errorf("%w: publishing to %s: %w", realtime.ErrUnavailable, msg.Channel, err)
	}
	if resp.GetError() != nil {
		p.obs.Failed(msg.Channel.Namespace())
		return fmt.Errorf("centrifugo: publishing to %s: %s (code %d)",
			msg.Channel, resp.GetError().GetMessage(), resp.GetError().GetCode())
	}
	p.obs.Published(msg.Channel.Namespace())
	return nil
}

// PublishMany sends several messages in ONE round trip.
//
// The fan-out case, and the one gRPC wins by 1.6x: a projector touching several
// channels for one event would otherwise pay a round trip each, landing that
// latency directly on the projection batch.
func (p *Publisher) PublishMany(ctx context.Context, msgs []realtime.Message) error {
	if len(msgs) == 0 {
		return nil
	}
	commands := make([]*pb.Command, 0, len(msgs))
	for _, m := range msgs {
		if err := m.Validate(); err != nil {
			return err
		}
		commands = append(commands, &pb.Command{
			Publish: &pb.PublishRequest{
				Channel:        m.Channel.String(),
				Data:           m.Data,
				IdempotencyKey: m.IdempotencyKey,
			},
		})
	}

	// Parallel: independent publishes to different channels, and serialising
	// them would put the sum of their latencies on the critical path.
	resp, err := p.client.Batch(p.authed(ctx), &pb.BatchRequest{
		Commands: commands,
		Parallel: true,
	})
	if err != nil {
		for _, m := range msgs {
			p.obs.Failed(m.Channel.Namespace())
		}
		return fmt.Errorf("%w: publishing %d messages: %w", realtime.ErrUnavailable, len(msgs), err)
	}

	// Per-message replies: one bad channel must not read as all of them
	// failing, or a single malformed message looks like an outage.
	var firstErr error
	for i, r := range resp.GetReplies() {
		if i >= len(msgs) {
			break
		}
		if r.GetError() != nil {
			p.obs.Failed(msgs[i].Channel.Namespace())
			if firstErr == nil {
				firstErr = fmt.Errorf("centrifugo: publishing to %s: %s",
					msgs[i].Channel, r.GetError().GetMessage())
			}
			continue
		}
		p.obs.Published(msgs[i].Channel.Namespace())
	}
	return firstErr
}

// Online reports whether a subject has a live connection.
//
// What makes alert arbitration implementable (ADR-026): an Activity
// notification reaching somebody with the app open does not also need an email.
func (p *Publisher) Online(ctx context.Context, subjectID string) (bool, error) {
	n, err := p.Connections(ctx, subjectID)
	return n > 0, err
}

// Connections counts a subject's live connections — several tabs, several
// devices.
//
// PresenceStats rather than Presence: we want the COUNT, and fetching the full
// client list to take its length transfers every connection's metadata for a
// number we could ask for directly.
func (p *Publisher) Connections(ctx context.Context, subjectID string) (int, error) {
	ch := realtime.UserChannel(subjectID)
	resp, err := p.client.PresenceStats(p.authed(ctx), &pb.PresenceStatsRequest{
		Channel: ch.String(),
	})
	if err != nil {
		return 0, fmt.Errorf("%w: reading presence for %s: %w", realtime.ErrUnavailable, ch, err)
	}
	if resp.GetError() != nil {
		return 0, fmt.Errorf("centrifugo: reading presence for %s: %s",
			ch, resp.GetError().GetMessage())
	}
	return int(resp.GetResult().GetNumClients()), nil
}

// Info reports server details, used by the probe.
func (p *Publisher) Info(ctx context.Context) error {
	resp, err := p.client.Info(p.authed(ctx), &pb.InfoRequest{})
	if err != nil {
		return err
	}
	if resp.GetError() != nil {
		return errors.New(resp.GetError().GetMessage())
	}
	return nil
}
