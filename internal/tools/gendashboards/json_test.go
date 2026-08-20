package main

import "testing"

func TestEncode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "scalars",
			in:   arr{1, "x", true, false, nil},
			want: "[\n  1,\n  \"x\",\n  true,\n  false,\n  null\n]\n",
		},
		{
			// The property encoding/json cannot give: members come out in the
			// order they were written, not sorted. A sorted encoder would make
			// every regeneration a whole-file diff.
			name: "member order is authored, not sorted",
			in:   obj{{"z", 1}, {"a", 2}, {"m", 3}},
			want: "{\n  \"z\": 1,\n  \"a\": 2,\n  \"m\": 3\n}\n",
		},
		{
			name: "empty object and array stay on one line",
			in:   obj{{"o", obj{}}, {"a", arr{}}},
			want: "{\n  \"o\": {},\n  \"a\": []\n}\n",
		},
		{
			name: "nesting indents by two spaces per level",
			in:   obj{{"a", obj{{"b", arr{obj{{"c", 1}}}}}}},
			want: "{\n  \"a\": {\n    \"b\": [\n      {\n        \"c\": 1\n      }\n    ]\n  }\n}\n",
		},
		{
			// Every panel title in this repo carries an em dash. It MUST be
			// escaped: the committed dashboards are pure ASCII, and emitting raw
			// UTF-8 would rewrite all seven files on the next generation.
			name: "non-ascii is escaped",
			in:   "Chronos — Stack Overview",
			want: "\"Chronos \\u2014 Stack Overview\"\n",
		},
		{
			name: "astral plane becomes a surrogate pair",
			in:   "\U0001F600",
			want: "\"\\ud83d\\ude00\"\n",
		},
		{
			name: "quote and backslash are escaped",
			in:   `he said "a\b"`,
			want: "\"he said \\\"a\\\\b\\\"\"\n",
		},
		{
			name: "the named control escapes",
			in:   "\b\f\n\r\t",
			want: `"\b\f\n\r\t"` + "\n",
		},
		{
			name: "other control characters and DEL become \\u escapes",
			in:   "\x00\x1f\x7f",
			want: "\"" + `\u0000\u001f\u007f` + "\"\n",
		},
		{
			// encoding/json escapes these three by default. Grafana's JSON does
			// not carry them escaped, and a PromQL expression using `!=` would
			// change shape if it did.
			name: "html metacharacters are NOT escaped",
			in:   `a<b>c&d`,
			want: "\"a<b>c&d\"\n",
		},
		{
			name: "a real panel query survives verbatim",
			in:   `sum(rate(grpc_server_handled_total{job="openfga",grpc_code!="OK"}[5m]))`,
			want: "\"sum(rate(grpc_server_handled_total{job=\\\"openfga\\\",grpc_code!=\\\"OK\\\"}[5m]))\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := string(encode(tt.in)); got != tt.want {
				t.Errorf("encode() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestEncodeRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()

	// A guess here would be a silently-wrong dashboard, which is the failure the
	// whole tool exists to prevent, so an unsupported type must stop the build.
	defer func() {
		if recover() == nil {
			t.Fatal("encode() accepted a float64; it must panic on any type it cannot render exactly")
		}
	}()
	encode(1.5)
}
