package eventsourcing

import (
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Envelope is one event as a consumer sees it: the recorded facts, decoded
// metadata, and the payload still encoded.
//
// Projectors and reactors both receive this. They differ in what they are
// allowed to DO with an event, not in what an event is.
//
// The payload stays encoded and is decoded once, only when a handler for the
// type exists. A consumer filtered by stream prefix is routinely offered events
// it does not handle, and decoding those is work done to throw away.
type Envelope struct {
	ID       ids.EventID
	Type     string
	Stream   StreamID
	Revision Revision
	Position Position
	Meta     Metadata
	Payload  []byte

	// Live reports whether the consumer had caught up to the head of the log
	// when this arrived.
	//
	// It exists for side effects that are only meaningful in the present. A
	// realtime publish is the example: replaying history during a rebuild would
	// fire a toast for every notification a user ever received, all at once.
	// Rows are replayed; announcements are not.
	Live bool
}
