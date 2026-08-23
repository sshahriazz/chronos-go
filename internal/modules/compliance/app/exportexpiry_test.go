package app_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/blob"
)

// THE EXPORT'S LINK LIFETIME FITS THE OBJECT STORE'S CEILING.
//
// # The bug this exists for, which shipped
//
// The export asked for an hour and `blob.Limits.MaxExpiry` defaults to fifteen
// minutes, so `GrantDownload` refused and EVERY ready export answered its poll
// with `internal`. The person was told their data was ready and could not fetch
// it.
//
// Nothing caught it, and the reason is worth recording: the use case's tests
// used a fake store that granted whatever it was asked for, the handler's tests
// used a fake use case, and the two numbers live in packages that do not import
// each other. Only a request driven through the real store could see it — which
// is what found it.
//
// This is the cheap half of that lesson: the two constants are compared here, so
// raising one without the other fails at test time rather than at the moment
// somebody polls for their data.
func TestTheExportExpiryFitsTheStoresCeiling(t *testing.T) {
	limits, err := blob.Limits{}.Defaults()
	if err != nil {
		t.Fatalf("the object store's default limits do not validate: %v", err)
	}
	if app.DefaultExportExpiry > limits.MaxExpiry {
		t.Fatalf("an export link is asked to live %s and the object store refuses anything "+
			"over %s. GrantDownload returns an error, the poll answers `internal`, and "+
			"the person is told their data is ready and cannot fetch it",
			app.DefaultExportExpiry, limits.MaxExpiry)
	}
	if app.DefaultExportExpiry <= 0 {
		t.Fatal("an export link with no lifetime is one that never works")
	}
}
