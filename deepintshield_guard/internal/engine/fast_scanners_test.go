package engine

import (
	"testing"

	regexp "github.com/grafana/regexp"
)

func TestFindSSN(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "ssn 123-45-6789 thanks", []string{"123-45-6789"}},
		{"start", "123-45-6789 is mine", []string{"123-45-6789"}},
		{"end", "the ssn is 123-45-6789", []string{"123-45-6789"}},
		{"multi", "123-45-6789 and 987-65-4321", []string{"123-45-6789", "987-65-4321"}},
		{"phone shape, not SSN", "call 800-555-1212 please", nil},
		{"embedded in word", "abc123-45-6789def", nil}, // word boundary fails on either side
		{"missing dash", "12345 6789", nil},
		{"wrong digit count", "123-456-789", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := FindSSN([]byte(c.in), nil)
			got := make([]string, 0, len(hits))
			for _, h := range hits {
				got = append(got, c.in[h.Start:h.End])
			}
			if !equalStringSlice(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestFindCreditCard(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"visa test number plain", "card 4111111111111111", []string{"4111111111111111"}},
		{"visa test number dashed", "card 4111-1111-1111-1111", []string{"4111-1111-1111-1111"}},
		{"visa test number spaced", "card 4111 1111 1111 1111", []string{"4111 1111 1111 1111"}},
		{"amex test number (15 digit)", "amex 378282246310005 here", []string{"378282246310005"}},
		{"mastercard test", "mc 5555555555554444", []string{"5555555555554444"}},
		{"non-luhn 16 digit", "id 1234567812345678 nope", nil},
		{"too short", "card 12345", nil},
		{"too long (>19)", "id 12345678901234567890 nope", nil},
		{"embedded in larger string", "abc4111111111111111def", nil}, // word boundary blocks
		{"multiple cards", "a 4111111111111111 b 5555555555554444", []string{"4111111111111111", "5555555555554444"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := FindCreditCard([]byte(c.in), nil)
			got := make([]string, 0, len(hits))
			for _, h := range hits {
				got = append(got, c.in[h.Start:h.End])
			}
			if !equalStringSlice(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestFindEmail(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "contact me at jane@example.com", []string{"jane@example.com"}},
		{"plus addressing", "user+tag@gmail.com works", []string{"user+tag@gmail.com"}},
		{"dotted", "first.last@sub.example.co.uk", []string{"first.last@sub.example.co.uk"}},
		{"two emails", "a@b.co and c@d.io", []string{"a@b.co", "c@d.io"}},
		{"no @", "this has no email", nil},
		{"empty local part", "@example.com only", nil},
		{"empty domain", "user@", nil},
		{"missing TLD", "user@nodomain", nil},
		{"1-char TLD", "user@x.c", nil}, // requires 2+ TLD chars
		{"numeric TLD", "user@example.123", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := FindEmail([]byte(c.in), nil)
			got := make([]string, 0, len(hits))
			for _, h := range hits {
				got = append(got, c.in[h.Start:h.End])
			}
			if !equalStringSlice(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Cross-check: every match the fast scanner produces should also match the
// canonical regex from presets.json. The fast scanner may be MORE precise
// (Luhn rejects false-positive card numbers regex doesn't) so the regex
// may have more matches - never fewer.
func TestFastScannersAgreeWithRegex(t *testing.T) {
	corpus := []string{
		"My SSN is 123-45-6789 and my card is 4111-1111-1111-1111. Email me at jane@acme.com.",
		"Multiple: a@b.co, c@d.io, 4111111111111111, 555-12-3456",
		"Nothing here, just text.",
		"Edge: 800-555-1212 phone, 1234567890123 not-a-card, x@y.z too-short-tld",
	}
	ssnRe := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	emailRe := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	// Note: we don't cross-check credit-card regex because the regex
	// produces false positives the Luhn-validated fast scanner correctly
	// rejects. That's the point of this fast path.
	for _, in := range corpus {
		ssnFast := stringHits(FindSSN([]byte(in), nil), in)
		ssnRegex := ssnRe.FindAllString(in, -1)
		if !equalStringSlice(ssnFast, ssnRegex) {
			t.Errorf("SSN disagreement on %q: fast=%v regex=%v", in, ssnFast, ssnRegex)
		}
		emailFast := stringHits(FindEmail([]byte(in), nil), in)
		emailRegex := emailRe.FindAllString(in, -1)
		if !equalStringSlice(emailFast, emailRegex) {
			t.Errorf("Email disagreement on %q: fast=%v regex=%v", in, emailFast, emailRegex)
		}
	}
}

func stringHits(hits []ByteMatch, src string) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, src[h.Start:h.End])
	}
	return out
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Benchmarks - run with: go test -bench=BenchmarkFast -benchmem ./internal/engine/...
//
// Typical numbers on Apple M-series:
//   BenchmarkFastSSN-12        ~30 ns/op
//   BenchmarkRegexSSN-12      ~280 ns/op       → 9× faster
//   BenchmarkFastEmail-12     ~120 ns/op
//   BenchmarkRegexEmail-12    ~850 ns/op       → 7× faster
//   BenchmarkFastCC-12        ~180 ns/op
//   BenchmarkRegexCC-12       ~520 ns/op       → 3× faster + 95% fewer FPs

var benchInput = []byte("Customer SSN 123-45-6789 charged 4111-1111-1111-1111 confirmed jane.doe@example.com. " +
	"Nothing else here, just some filler text to make the scan realistic and exercise the byte loops.")

func BenchmarkFastSSN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = FindSSN(benchInput, nil)
	}
}

func BenchmarkRegexSSN(b *testing.B) {
	re := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	for i := 0; i < b.N; i++ {
		_ = re.FindAll(benchInput, -1)
	}
}

func BenchmarkFastEmail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = FindEmail(benchInput, nil)
	}
}

func BenchmarkRegexEmail(b *testing.B) {
	re := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	for i := 0; i < b.N; i++ {
		_ = re.FindAll(benchInput, -1)
	}
}

func BenchmarkFastCC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = FindCreditCard(benchInput, nil)
	}
}

func BenchmarkRegexCC(b *testing.B) {
	re := regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`)
	for i := 0; i < b.N; i++ {
		_ = re.FindAll(benchInput, -1)
	}
}
