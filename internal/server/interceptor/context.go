package interceptor

import "context"

// principalKey is unexported and of a private type, so nothing outside this
// package can put a Principal into a context.
//
// That is the point: every later gate reads the caller from here, and a value
// any package could write is a value a handler could forge. The only way in is
// withPrincipal, which only the authn gate calls.
type principalKey struct{}

// withPrincipal attaches the authenticated caller. Called by the pipeline, once,
// immediately after authn.
func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom reads the authenticated caller.
//
// The second return is false when there is none, and every caller must treat
// that as a refusal rather than as an anonymous request. A public method never
// reaches code that calls this, so "no principal" here means the pipeline was
// bypassed.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
