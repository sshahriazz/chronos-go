package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// This file is a JSON encoder, and it exists instead of encoding/json for one
// reason: the output is a COMMITTED artifact that Grafana provisions, and a
// re-generation that reorders keys or re-escapes a character produces a diff of
// several thousand lines in which a real change cannot be seen.
//
// Two properties the standard library will not give:
//
//  1. **Key order is authored, not sorted.** A Grafana panel reads best as
//     type/title/description/datasource/gridPos/..., which is neither
//     alphabetical nor a struct this package wants to declare seven times.
//     [obj] is an ordered list of members and is emitted in that order.
//
//  2. **Non-ASCII is escaped.** Every `—` in a panel title becomes `—`.
//     encoding/json emits it as raw UTF-8; the generator this replaces emitted
//     the escape, and the committed files carry it.
//
// The shape is otherwise exactly Python's `json.dumps(obj, indent=2)`:
// two-space indent, `": "` between a key and its value, `,` with no trailing
// space, and `{}` / `[]` for the empty cases.

// obj is a JSON object whose members keep the order they were written in.
type obj []member

// member is one key/value pair of an [obj].
type member struct {
	Key   string
	Value any
}

// arr is a JSON array.
type arr []any

// encode renders v as JSON with a two-space indent and a trailing newline.
//
// Accepts obj, arr, string, int, bool and nil. Anything else is a programming
// error in this package and panics rather than being emitted as a guess — this
// runs at build time, and a silently-wrong dashboard is the failure the whole
// tool exists to prevent.
func encode(v any) []byte {
	var b strings.Builder
	writeValue(&b, v, 0)
	b.WriteByte('\n')
	return []byte(b.String())
}

func writeValue(b *strings.Builder, v any, depth int) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(t))
	case string:
		writeString(b, t)
	case obj:
		writeObject(b, t, depth)
	case arr:
		writeArray(b, t, depth)
	default:
		panic(fmt.Sprintf("gendashboards: cannot encode %T", v))
	}
}

func writeObject(b *strings.Builder, o obj, depth int) {
	if len(o) == 0 {
		b.WriteString("{}")
		return
	}
	b.WriteString("{\n")
	for i, m := range o {
		if i > 0 {
			b.WriteString(",\n")
		}
		writeIndent(b, depth+1)
		writeString(b, m.Key)
		b.WriteString(": ")
		writeValue(b, m.Value, depth+1)
	}
	b.WriteByte('\n')
	writeIndent(b, depth)
	b.WriteByte('}')
}

func writeArray(b *strings.Builder, a arr, depth int) {
	if len(a) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteString("[\n")
	for i, v := range a {
		if i > 0 {
			b.WriteString(",\n")
		}
		writeIndent(b, depth+1)
		writeValue(b, v, depth+1)
	}
	b.WriteByte('\n')
	writeIndent(b, depth)
	b.WriteByte(']')
}

func writeIndent(b *strings.Builder, depth int) {
	for range depth {
		b.WriteString("  ")
	}
}

// writeString emits an ASCII-only JSON string.
//
// Printable ASCII (0x20..0x7E) passes through except for `"` and `\`. Everything
// else — control characters, DEL, and every non-ASCII rune — becomes an escape,
// with runes outside the BMP written as a surrogate pair. `<`, `>` and `&` are
// NOT escaped; encoding/json escapes them by default and Grafana's JSON does not
// carry them escaped.
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				b.WriteByte(byte(r))
			case r == utf8.RuneError:
				// A lone invalid byte. Emit the replacement character rather
				// than the raw byte so the output stays valid JSON.
				fmt.Fprintf(b, `\u%04x`, 0xfffd)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}
