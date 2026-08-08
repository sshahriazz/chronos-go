package connect

import (
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// jsonCodec is protobuf-JSON that ALWAYS emits default values.
//
// protojson omits zero values by default, so `false`, `0` and `""` disappear
// from the response entirely. A client writing `if (res.ready === false)` then
// sees `undefined` and takes the wrong branch — and it only misbehaves in the
// failure case, which is exactly when it matters.
//
// Emitting defaults makes the JSON shape stable and self-describing at the cost
// of a few bytes. For an API whose consumers are browsers, that is the right
// trade.
type jsonCodec struct{ name string }

func (c *jsonCodec) Name() string { return c.name }

func (c *jsonCodec) Marshal(msg any) ([]byte, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil, errNotProto(msg)
	}
	return protojson.MarshalOptions{
		EmitDefaultValues: true,
		UseProtoNames:     false, // camelCase: idiomatic for JSON consumers
	}.Marshal(m)
}

func (c *jsonCodec) Unmarshal(data []byte, msg any) error {
	m, ok := msg.(proto.Message)
	if !ok {
		return errNotProto(msg)
	}
	// Tolerate fields a client sends that this build does not know about, so a
	// newer client does not break against an older server.
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, m)
}

func errNotProto(msg any) error {
	return connect.NewError(connect.CodeInternal,
		&notProtoError{got: msg})
}

type notProtoError struct{ got any }

func (e *notProtoError) Error() string { return "codec: expected a protobuf message" }

// JSONOptions returns the handler options that install the codec above for both
// the "json" and "json; charset=utf-8" content types Connect negotiates.
func JSONOptions() []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithCodec(&jsonCodec{name: "json"}),
	}
}
