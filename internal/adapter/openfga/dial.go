package openfga

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Dial builds a client for the OpenFGA gRPC API.
//
// It does not connect: grpc.NewClient establishes lazily and re-establishes
// automatically, which is the behaviour ADR-010 wants — an authorization service
// that is down at startup must not stop the process, it must make every check
// deny.
//
// The pre-shared key travels as per-RPC credentials rather than a dial option
// header, so it is attached to every call including retries. Verified against
// the running server: without it, even reflection is refused with
// "missing bearer token" (OpenFGA error 1010), so an unauthenticated connection
// produces a probe that reports DOWN and a Guard that denies everything —
// correct, but for a reason that looks like an outage.
func Dial(endpoint, presharedKey string) (*grpc.ClientConn, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("openfga: an endpoint is required")
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Authorization is on the hot path of every request, so a connection that
		// has gone away silently must be discovered by us rather than by a user's
		// request timing out.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if presharedKey != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearer{key: presharedKey}))
	}

	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("openfga: building client for %s: %w", endpoint, err)
	}
	return conn, nil
}

// bearer attaches the pre-shared key.
//
// RequireTransportSecurity reports false because the development stack speaks
// plaintext on a private network. That is a deployment decision, not a code one:
// outside local the endpoint is expected to be TLS, and the key is a Secret in
// config so it never reaches a log.
type bearer struct{ key string }

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.key}, nil
}

func (bearer) RequireTransportSecurity() bool { return false }
