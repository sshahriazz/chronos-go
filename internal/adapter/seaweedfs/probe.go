package seaweedfs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/chronos/chronos-go/internal/server/health"
)

// Probe reports object storage reachability using the same S3 client the upload
// path uses, so it fails for the same reasons a real grant would.
//
// Degradable, not Critical — and that is a deliberate judgement rather than an
// oversight. Every other part of the product keeps working when storage is
// down: people sign in, permissions resolve, workspaces and members are read
// and written, billing runs. Only uploads and downloads stop.
//
// Marking it Critical would take the whole API out of the load balancer because
// avatars are unavailable, turning a partial outage into a total one. The
// failure is reported, it is visible on the status surface, and upload requests
// fail with a precise reason — which is what ADR-010 asks for.
type Probe struct {
	Client *s3.Client
	Bucket string
}

func (Probe) Name() string                    { return "seaweedfs" }
func (Probe) Criticality() health.Criticality { return health.Degradable }
func (Probe) Impact() string {
	return "File upload and download are unavailable. Everything else is unaffected."
}

// Check performs a real bucket head.
//
// An actual operation rather than a TCP ping: it exercises the endpoint,
// credentials, signature and bucket policy together. A store that accepts a
// connection but rejects our credentials is a state a ping calls healthy, and
// is exactly the state a rotated secret produces.
func (p Probe) Check(ctx context.Context) error {
	if p.Client == nil {
		return fmt.Errorf("client not initialised")
	}
	if p.Bucket == "" {
		return fmt.Errorf("no bucket configured")
	}
	if _, err := p.Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(p.Bucket),
	}); err != nil {
		return err
	}
	return nil
}

// Probe returns a health probe for this store, so the composition root does not
// have to reach inside for the client.
func (s *Store) Probe() Probe {
	return Probe{Client: s.client, Bucket: s.cfg.Bucket}
}
