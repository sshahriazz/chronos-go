package main

import "strings"

// pushTitles is the short wording a push notification carries.
//
// SEPARATE from the email templates, and deliberately so. A push renders on a
// lock screen a stranger can read, so it must say what happened without saying
// who it happened to: "Your password was changed" is fine, "Sam Larsson changed
// your password" is not (notification.md §4).
//
// A template with no entry here is SKIPPED rather than pushed with a generic
// title. Chrome requires userVisibleOnly, so a push that shows nothing risks the
// browser revoking permission for the whole origin — one bad notification costs
// every future one.
type pushTitles struct{}

var pushWording = map[string]struct{ title, body string }{
	"identity.password_changed": {
		title: "Your password was changed",
		body:  "If this wasn't you, secure your account now.",
	},
	"identity.welcome": {
		title: "Welcome to Chronos",
		body:  "Confirm your email address to finish setting up.",
	},
}

func (pushTitles) Push(template string, _ map[string]any) (string, string, bool) {
	w, ok := pushWording[strings.TrimSpace(template)]
	if !ok {
		return "", "", false
	}
	return w.title, w.body, true
}
