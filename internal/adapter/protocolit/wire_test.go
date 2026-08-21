//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// wireError is the Connect protocol's error envelope, as a hand-written client
// would parse it.
//
// Declared here rather than reused from connectrpc because the point of the raw
// HTTP cases is to test the WIRE, and parsing it with the library that produced
// it would make the two agree by construction. `debug` is connect-go's rendering
// of a detail whose descriptor it holds — it is what a client without protobuf
// descriptors reads, and it is the only place `reason` appears in plain text.
type wireError struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Details []wireDetail `json:"details"`
}

type wireDetail struct {
	Type  string          `json:"type"`
	Value string          `json:"value"`
	Debug wireErrorDetail `json:"debug"`
}

// wireErrorDetail is chronos.errors.v1.ErrorDetail in its protobuf-JSON form.
type wireErrorDetail struct {
	Reason   string            `json:"reason"`
	Metadata map[string]string `json:"metadata"`
}

// decodeWireError parses an error body TOLERANTLY.
//
// Tolerant, not strict: this is somebody else's document — connect-go's, and a
// future version of the protocol may add members — and ADR-047 says that is
// exactly the case `codec.Tolerant` exists for. A strict decode here would turn
// "connect added a field" into "the error contract is broken", which is the
// opposite of what these tests are trying to measure.
func decodeWireError(body string) (wireError, error) {
	return codec.Tolerant[wireError]([]byte(body))
}

// rawPost issues an HTTP/JSON POST by hand: no connect client, no generated
// stub, nothing that shares an assumption with the server.
//
// contentType and body are parameters rather than fixed, because half the cases
// in malformed_test.go are about sending the wrong one.
func rawPost(
	ctx context.Context, procedure, contentType, body, bearer, key string, extra http.Header,
) (int, string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, h.baseURL+procedure, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Connect-Protocol-Version", "1")
	if bearer != "" {
		req.Header.Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	if key != "" {
		req.Header.Set(interceptor.IdempotencyHeader, key)
	}
	for name, values := range extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	resp, err := clientFor(false).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), err
}

// describeRaw renders a raw HTTP answer the way a failure message should: the
// status, the Connect code, and the reason a client is supposed to branch on.
func describeRaw(status int, body string) string {
	if status >= 200 && status < 300 {
		return fmt.Sprintf("status=%d body=%s", status, strings.TrimSpace(body))
	}
	env, err := decodeWireError(body)
	if err != nil {
		return fmt.Sprintf("status=%d body=%q (not a Connect error envelope: %v)",
			status, strings.TrimSpace(body), err)
	}
	return fmt.Sprintf("status=%d code=%s reason=%s message=%q",
		status, env.Code, reasonFromJSON(body), env.Message)
}
