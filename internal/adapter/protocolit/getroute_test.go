//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// getURL builds the Connect GET form exactly as proto/openapi.base.yaml
// documents it:
//
//	GET /chronos.system.v1.SystemService/GetStatus?encoding=json&message=%7B%7D&connect=v1
//
// | message     | The request message, JSON-encoded |
// | encoding    | `json` (or `proto`)               |
// | base64      | `1` — and only `1` — if `message` is base64url-encoded |
// | compression | Optional content encoding of `message` |
// | connect     | Protocol version, `v1`            |
func getURL(procedure, message string, extra url.Values) string {
	q := url.Values{}
	q.Set("encoding", "json")
	q.Set("message", message)
	q.Set("connect", "v1")
	for k, vs := range extra {
		q[k] = vs
	}
	return h.baseURL + procedure + "?" + q.Encode()
}

// getJSON issues the documented GET and returns the status and the body.
func getJSON(ctx context.Context, rawURL, bearer string) (int, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	// The OpenAPI spec marks Connect-Protocol-Version a REQUIRED header on the
	// GET operations, so a generated client sends it. Sent here for the same
	// reason: the question is whether the route the spec publishes works, and
	// the spec publishes this header.
	req.Header.Set("Connect-Protocol-Version", "1")
	if bearer != "" {
		req.Header.Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	resp, err := clientFor(false).Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header, err
}

// TestEveryDocumentedGetRouteWorks is the question this package was built to
// answer.
//
// buf.gen.openapi.yaml passes `allow-get`, so docs/api/chronos-openapi.yaml
// carries a `get:` operation for all nine NO_SIDE_EFFECTS RPCs — with the
// `message`, `encoding`, `base64`, `compression` and `connect` query parameters
// spelled out per operation. Nothing had ever called one. A published route that
// 404s or mis-decodes is a lie every generated client inherits, and the OpenAPI
// gate cannot catch it: `checkopenapi` compares the spec against the PROTO, and
// both would agree while the server answered neither.
//
// The URL here is built from the spec's own documented parameter set, not from
// connect-go's client, so this measures the CONTRACT rather than the library's
// agreement with itself.
func TestEveryDocumentedGetRouteWorks(t *testing.T) {
	bearer := h.activeBearer(t)

	for _, rc := range reads() {
		t.Run(rc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			token := bearer
			if rc.public {
				token = ""
			}
			status, body, header, err := getJSON(ctx, getURL(rc.procedure, rc.message, nil), token)
			if err != nil {
				t.Fatalf("GET %s: %v", rc.procedure, err)
			}
			if status != http.StatusOK {
				t.Fatalf("BUG: the OpenAPI spec publishes GET %s and the server answered "+
					"%d %s\nbody: %s", rc.procedure, status, http.StatusText(status),
					strings.TrimSpace(body))
			}
			if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("GET %s answered Content-Type %q; the spec documents "+
					"application/json for every 200", rc.procedure, ct)
			}
			t.Logf("GET %s -> 200 %s", rc.procedure, strings.TrimSpace(body))
		})
	}
}

// TestAGetRouteEnforcesTheSameGatesAsThePost is the security half of the same
// question.
//
// A GET route is a cacheable, link-shaped, referrer-leaking surface, and it is
// created by a codegen flag rather than by anyone writing a handler. If the gate
// pipeline only ran on POST, every authenticated read would be readable by
// anyone who could reach the port — and the ADR-021 pipeline is a Connect
// INTERCEPTOR, which is method-agnostic by construction, so the expected answer
// is that it does. Expected is not verified.
func TestAGetRouteEnforcesTheSameGatesAsThePost(t *testing.T) {
	for _, rc := range reads() {
		if rc.public {
			continue
		}
		t.Run(rc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			status, body, _, err := getJSON(ctx, getURL(rc.procedure, rc.message, nil), "")
			if err != nil {
				t.Fatalf("GET %s: %v", rc.procedure, err)
			}
			if status == http.StatusOK {
				t.Fatalf("BUG: GET %s answered 200 to a caller carrying NO bearer token. "+
					"The POST form of the same method is authenticated; a GET route created "+
					"by a codegen flag has bypassed the authn gate.\nbody: %s",
					rc.procedure, strings.TrimSpace(body))
			}
			if status != http.StatusUnauthorized {
				t.Errorf("GET %s without a token answered %d; Connect maps UNAUTHENTICATED "+
					"to 401\nbody: %s", rc.procedure, status, strings.TrimSpace(body))
			}
			if reason := reasonFromJSON(body); reason != string(errs.Unauthenticated) {
				t.Errorf("GET %s without a token carried reason %q, want %q; a client on the "+
					"GET route has to be able to branch on the same reason as one on the POST "+
					"route (CONVENTIONS §5.1)\nbody: %s",
					rc.procedure, reason, errs.Unauthenticated, strings.TrimSpace(body))
			}
		})
	}
}

// TestTheGetRouteQueryParametersBehaveAsDocumented checks each parameter the
// spec publishes, one at a time.
//
// Each subtest names the document it is quoting. Where the server's behaviour
// and the document disagree, the DOCUMENT is what the test asserts, because the
// document is what a generated client is built from.
func TestTheGetRouteQueryParametersBehaveAsDocumented(t *testing.T) {
	bearer := h.activeBearer(t)
	const procedure = "/chronos.identity.v1.IdentityService/GetUser"

	t.Run("base64=true is refused, and the spec no longer implies otherwise", func(t *testing.T) {
		// This subtest found the defect and now guards the fix, so it is worth
		// being precise about what changed. The spec used to declare:
		//
		//	base64:
		//	  type: boolean
		//	  description: Specifies if the message query param is base64 encoded
		//
		// A boolean in a query string is `true`, and connect-go compares the value
		// against the literal string "1":
		//
		//	queryValueReader(msg, query.Get(connectUnaryBase64QueryParameter) == "1")
		//
		// so `true` was not merely unsupported, it was silently OFF — the still
		// encoded message reached the parser as literal JSON and the error blamed
		// the payload. The document promised a call the server refuses.
		//
		// The document now declares `type: string` with `enum: ["1"]`, so the two
		// agree, and the assertion flips with them: `base64=true` SHOULD fail, and
		// a client generated from the current spec cannot send it.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		// "{}" base64url-encoded, unpadded.
		encoded := "e30"
		status, body, _, err := getJSON(ctx, getURL(procedure, encoded, url.Values{
			"base64": {"true"},
		}), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status == http.StatusOK {
			t.Errorf("`base64=true` was ACCEPTED (%d). connect-go decodes only on the literal "+
				"\"1\", so either the library changed its comparison or something is decoding "+
				"the message before it gets there. Whichever it is, the published enum of "+
				"[\"1\"] has stopped describing the server.\nbody: %s",
				status, strings.TrimSpace(body))
		}
	})

	t.Run("base64=1, which is what the server accepts", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		status, body, _, err := getJSON(ctx, getURL(procedure, "e30", url.Values{
			"base64": {"1"},
		}), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("base64=1 with a base64url message answered %d\nbody: %s",
				status, strings.TrimSpace(body))
		}
	})

	t.Run("no connect=v1, which the spec marks optional", func(t *testing.T) {
		// The `connect` parameter carries no `required: true` in the spec, while
		// `Connect-Protocol-Version` (a header) does. On a GET, connect-go reads
		// the QUERY parameter and ignores the header entirely — so the spec has
		// the requirement on the wrong one of the two.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		q := url.Values{"encoding": {"json"}, "message": {"{}"}}
		status, body, _, err := getJSON(ctx, h.baseURL+procedure+"?"+q.Encode(), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("the spec marks `connect` optional and `Connect-Protocol-Version` "+
				"required; omitting the query parameter while sending the header answered "+
				"%d\nbody: %s", status, strings.TrimSpace(body))
		}
	})

	t.Run("connect=v2 is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		status, body, _, err := getJSON(ctx, getURL(procedure, "{}", url.Values{
			"connect": {"v2"},
		}), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status == http.StatusOK {
			t.Errorf("`connect` is an enum of exactly [v1] in the spec, and v2 was accepted")
		}
		t.Logf("connect=v2 -> %d %s", status, strings.TrimSpace(body))
	})

	t.Run("encoding is required", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		q := url.Values{"message": {"{}"}, "connect": {"v1"}}
		status, body, _, err := getJSON(ctx, h.baseURL+procedure+"?"+q.Encode(), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status == http.StatusOK {
			t.Errorf("the spec marks `encoding` required: true, and omitting it was accepted")
		}
		t.Logf("no encoding -> %d %s", status, strings.TrimSpace(body))
	})

	t.Run("message is required", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		q := url.Values{"encoding": {"json"}, "connect": {"v1"}}
		status, body, _, err := getJSON(ctx, h.baseURL+procedure+"?"+q.Encode(), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status == http.StatusOK {
			t.Errorf("`message` was omitted and the request was accepted; the spec documents " +
				"it as the request message and connect-go requires it")
		}
		t.Logf("no message -> %d %s", status, strings.TrimSpace(body))
	})

	t.Run("encoding=proto with a JSON message is refused", func(t *testing.T) {
		// The enum is [proto, json]. A client that picks `proto` and sends JSON
		// must be refused rather than silently decoding into a zero message —
		// GetUserRequest is EMPTY, so a tolerant decode would answer 200 with the
		// caller's whole account and nothing would ever report the mismatch.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		status, body, _, err := getJSON(ctx, getURL(
			"/chronos.identity.v1.IdentityService/ListSessions",
			`{"pageSize":10}`, url.Values{"encoding": {"proto"}}), bearer)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if status == http.StatusOK {
			t.Errorf("BUG: encoding=proto with a JSON body answered 200; a mis-encoded "+
				"request decoded into something\nbody: %s", strings.TrimSpace(body))
		}
		t.Logf("encoding=proto + JSON -> %d %s", status, strings.TrimSpace(body))
	})
}

// TestAMutatingRPCHasNoGetRoute is the other half of `allow-get`.
//
// The flag exposes NO_SIDE_EFFECTS methods as GET. A mutation reached by GET
// would be executable from an <img> tag, so the absence of the route is a
// security property rather than a tidiness one — and it is worth an assertion
// precisely because nobody wrote the routes and nobody would notice if the flag
// started emitting them.
func TestAMutatingRPCHasNoGetRoute(t *testing.T) {
	bearer := h.activeBearer(t)

	// EVERY mutation, not the two-entry `mutations()` set this used to walk. The
	// property is about ROUTING, so it holds regardless of whether the body would
	// have been accepted: a mutation must not answer a GET with 200, and eighteen
	// of the twenty were previously unasserted.
	for _, mc := range mutatingProcedures() {
		t.Run(mc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			rawURL := getURL(mc.path, mc.body, nil) +
				"&" + url.Values{"idempotency": {newIdempotencyKey()}}.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
			req.Header.Set(interceptor.IdempotencyHeader, newIdempotencyKey())
			resp, err := clientFor(false).Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", mc.path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == http.StatusOK {
				t.Fatalf("BUG: %s is a MUTATION and answered a GET with 200. It is now "+
					"reachable from an <img src> and from any cache warmer that follows "+
					"links.\nbody: %s", mc.path, strings.TrimSpace(string(body)))
			}
			t.Logf("GET %s -> %d %s (mutations are POST-only)",
				mc.path, resp.StatusCode, strings.TrimSpace(string(body)))
		})
	}
}

// reasonFromJSON pulls `reason` out of a Connect error body.
//
// It reads the `debug` member of the detail rather than base64-decoding
// `value`, because `debug` is what connect-go emits for a detail whose
// descriptor it holds, and it is the member a hand-written client — the whole
// audience for the HTTP/JSON protocol — would actually read.
func reasonFromJSON(body string) string {
	env, err := decodeWireError(body)
	if err != nil {
		return fmt.Sprintf("<unparseable error body: %v>", err)
	}
	for _, d := range env.Details {
		if !strings.HasSuffix(d.Type, "chronos.errors.v1.ErrorDetail") {
			continue
		}
		if d.Debug.Reason != "" {
			return d.Debug.Reason
		}
	}
	return "<no chronos.errors.v1.ErrorDetail>"
}
