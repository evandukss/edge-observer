package contentcoding

import (
	"slices"
	"testing"
)

func codings(l List) []Coding {
	var out []Coding
	for i := range l.Len() {
		out = append(out, l.At(i))
	}
	return out
}

func TestParseListAdmitsOneCodingAtMost(t *testing.T) {
	for _, c := range []struct {
		name    string
		values  []string
		verdict Verdict
		want    []Coding
	}{
		{"absent", nil, Supported, nil},
		{"empty value", []string{""}, Supported, nil},
		{"only commas and spaces", []string{" , ,\t,"}, Supported, nil},
		{"identity alone", []string{"identity"}, Supported, nil},
		{"identity repeated across fields", []string{"identity", "IDENTITY, identity"}, Supported, nil},
		{"each coding", []string{"gzip"}, Supported, []Coding{Gzip}},
		{"x-gzip is gzip", []string{"x-gzip"}, Supported, []Coding{Gzip}},
		{"deflate", []string{"deflate"}, Supported, []Coding{Deflate}},
		{"br", []string{"br"}, Supported, []Coding{Brotli}},
		{"zstd", []string{"zstd"}, Supported, []Coding{Zstd}},
		{"case is ignored", []string{"GZip"}, Supported, []Coding{Gzip}},
		{"case is ignored in the alias", []string{"X-GZIP"}, Supported, []Coding{Gzip}},
		{"identity around one coding", []string{"identity, gzip", "identity", "IDENTITY"}, Supported, []Coding{Gzip}},
		{"two codings in one field", []string{"gzip, br"}, Unsupported, nil},
		{"two codings across fields", []string{"gzip", "br"}, Unsupported, nil},
		{"a duplicate counts", []string{"gzip", "gzip"}, Unsupported, nil},
		{"an alias counts", []string{"gzip, x-gzip"}, Unsupported, nil},
		{"identity does not make two into one", []string{"gzip, identity", "identity, zstd"}, Unsupported, nil},
		{"many codings", []string{"gzip, br, zstd, deflate"}, Unsupported, nil},
		{"unknown coding", []string{"compress"}, Unsupported, nil},
		{"unknown beside known", []string{"gzip", "x-compress"}, Unsupported, nil},
		{"star is a token, not a coding", []string{"*"}, Unsupported, nil},
		{"parameter is malformed", []string{"gzip;q=1"}, Malformed, nil},
		{"space inside an element", []string{"gz ip"}, Malformed, nil},
		{"quoted string", []string{`"gzip"`}, Malformed, nil},
		{"malformed beats unsupported", []string{"compress", "gzip/1"}, Malformed, nil},
		{"malformed beats too many", []string{"gzip, gzip, gzip, gzip", "a@b"}, Malformed, nil},
		{"control byte", []string{"gzip\x01"}, Malformed, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, v := ParseList(c.values)
			if v != c.verdict {
				t.Fatalf("verdict %d, want %d", v, c.verdict)
			}
			if got := codings(l); !slices.Equal(got, c.want) {
				t.Fatalf("codings %v, want %v", got, c.want)
			}
		})
	}
}

func TestVerdictAndOutcomeReasons(t *testing.T) {
	if Unsupported.Reason() != "content_coding_unsupported" || Supported.Reason() != "" || Malformed.Reason() != "" {
		t.Fatal("verdict reasons")
	}
	for o, want := range map[Outcome]string{
		Decoded: "", Identity: "", Refused: "",
		DecodingFailed: "content_decoding_failed", DecodedTooLarge: "content_decoded_too_large",
		DecodingTooCostly: "content_decoding_too_costly",
	} {
		if o.Reason() != want {
			t.Fatalf("outcome %d reason %q, want %q", o, o.Reason(), want)
		}
	}
	if Gzip.String() != "gzip" || Deflate.String() != "deflate" || Brotli.String() != "br" || Zstd.String() != "zstd" {
		t.Fatal("coding names")
	}
}
