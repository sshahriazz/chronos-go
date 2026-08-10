package centrifugo

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/realtime"
	"github.com/golang-jwt/jwt/v5"
)

// TokenMinter issues Centrifugo connection and subscription tokens.
//
// THE authorisation seam. No namespace in the Centrifugo config grants clients
// the right to subscribe, so a browser can reach a channel only if we have
// minted a token for it — and we mint one only after an OpenFGA check. That
// keeps the permission decision in one place instead of duplicating it into
// realtime infrastructure that cannot see our authorisation model.
type TokenMinter struct {
	secret []byte
	clock  clock.Clock
}

var _ realtime.TokenMinter = (*TokenMinter)(nil)

func NewTokenMinter(hmacSecret string, clk clock.Clock) *TokenMinter {
	if clk == nil {
		clk = clock.System{}
	}
	return &TokenMinter{secret: []byte(hmacSecret), clock: clk}
}

// Connection identifies a user to Centrifugo.
//
// The subject is the PSEUDONYM (ADR-002). Centrifugo stores it, logs it and
// exposes it in presence — an email address here would leak into infrastructure
// that has no business holding one.
func (m *TokenMinter) Connection(_ context.Context, subjectID string, ttl time.Duration) (string, error) {
	if subjectID == "" {
		return "", fmt.Errorf("centrifugo: a subject is required to mint a connection token")
	}
	if ttl <= 0 {
		ttl = realtime.DefaultTokenTTL
	}
	now := m.clock.Now()
	return m.sign(jwt.MapClaims{
		"sub": subjectID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
}

// Subscription authorises ONE channel.
//
// One channel per token, never a wildcard: a token good for "user:*" is a token
// good for everyone's notifications, and it only takes one leak.
func (m *TokenMinter) Subscription(
	_ context.Context, subjectID string, ch realtime.Channel, ttl time.Duration,
) (string, error) {
	if !ch.Valid() {
		return "", fmt.Errorf("%w: %q", realtime.ErrInvalidChannel, ch)
	}
	if subjectID == "" {
		return "", fmt.Errorf("centrifugo: a subject is required to mint a subscription token")
	}
	if ttl <= 0 {
		ttl = realtime.DefaultTokenTTL
	}
	now := m.clock.Now()
	return m.sign(jwt.MapClaims{
		"sub": subjectID,
		// Centrifugo checks that the channel in the token matches the one being
		// subscribed to, so a token for one channel cannot open another.
		"channel": ch.String(),
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
	})
}

func (m *TokenMinter) sign(claims jwt.MapClaims) (string, error) {
	if len(m.secret) == 0 {
		// An unsigned token would be accepted by nobody and is worse than an
		// error: it fails at the browser, far from the cause.
		return "", fmt.Errorf("centrifugo: no HMAC secret configured for token signing")
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("centrifugo: signing token: %w", err)
	}
	return token, nil
}
