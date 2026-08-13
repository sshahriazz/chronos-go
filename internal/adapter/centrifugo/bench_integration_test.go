//go:build integration

package centrifugo_test

import (
	"context"
	"os"
	"strings"
	"testing"

	pb "github.com/chronos/chronos-go/gen/thirdparty/centrifugo"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/realtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var sinkErr error

// gRPC or the official HTTP client?
//
// Decided on measurement, not on the ADR. Measured across payload sizes, under
// concurrency, and for presence as well as publish — because a single number at
// one size on an idle server is not a decision.

func grpcClient(b *testing.B) (pb.CentrifugoApiClient, context.Context) {
	b.Helper()
	conn, err := grpc.NewClient(envOrB("CENTRIFUGO_GRPC_ENDPOINT", "localhost:10000"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"authorization", "apikey "+os.Getenv("CENTRIFUGO_API_KEY"))
	return pb.NewCentrifugoApiClient(conn), ctx
}

func payload(size int) []byte {
	body, _ := codec.Marshal(map[string]any{
		"type": "notification.created",
		"id":   "01J8Z9ABCDEF",
		"pad":  strings.Repeat("x", size),
	})
	return body
}

// The shipped path. Kept so the choice recorded in publisher.go can be
// re-measured rather than taken on trust.

func BenchmarkPublish(b *testing.B) {
	c, ctx := grpcClient(b)
	ch := realtime.UserChannel("sub_bench").String()
	data := payload(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, sinkErr = c.Publish(ctx, &pb.PublishRequest{Channel: ch, Data: data})
		if sinkErr != nil {
			b.Fatal(sinkErr)
		}
	}
}

// The larger-payload case, where gRPC wins on both time and allocation.
func BenchmarkPublish4KB(b *testing.B) {
	c, ctx := grpcClient(b)
	ch := realtime.UserChannel("sub_bench").String()
	data := payload(4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, sinkErr = c.Publish(ctx, &pb.PublishRequest{Channel: ch, Data: data})
		if sinkErr != nil {
			b.Fatal(sinkErr)
		}
	}
}

// The fan-out case a realtime-first system produces constantly.
func BenchmarkPublishMany(b *testing.B) {
	c, ctx := grpcClient(b)
	data := payload(0)
	cmds := make([]*pb.Command, 0, 5)
	for i := range 5 {
		cmds = append(cmds, &pb.Command{Publish: &pb.PublishRequest{
			Channel: realtime.UserChannel("sub_b" + string(rune('a'+i))).String(), Data: data,
		}})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, sinkErr = c.Batch(ctx, &pb.BatchRequest{Commands: cmds, Parallel: true})
		if sinkErr != nil {
			b.Fatal(sinkErr)
		}
	}
}

// Concurrent publishers: a projector and the API at the same time.
func BenchmarkPublishParallel(b *testing.B) {
	c, ctx := grpcClient(b)
	ch := realtime.UserChannel("sub_bench").String()
	data := payload(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if _, err := c.Publish(ctx, &pb.PublishRequest{Channel: ch, Data: data}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkPresence(b *testing.B) {
	c, ctx := grpcClient(b)
	ch := realtime.UserChannel("sub_bench").String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, sinkErr = c.PresenceStats(ctx, &pb.PresenceStatsRequest{Channel: ch})
		if sinkErr != nil {
			b.Fatal(sinkErr)
		}
	}
}

func envOrB(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
