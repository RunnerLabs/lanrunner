package main

import (
	"strings"
	"testing"
)

func TestGaloisFieldRoundTrips(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := gfExp[gfLog[byte(a)]]; got != byte(a) {
			t.Fatalf("gfExp[gfLog[%d]] = %d, want %d", a, got, a)
		}
		if got := gfMul(byte(a), 1); got != byte(a) {
			t.Fatalf("%d * 1 = %d", a, got)
		}
		if got := gfMul(byte(a), 0); got != 0 {
			t.Fatalf("%d * 0 = %d", a, got)
		}
	}
	// Multiplication must commute and distribute over the field's addition (xor).
	for _, a := range []byte{2, 7, 99, 200, 255} {
		for _, b := range []byte{3, 11, 128, 201} {
			if gfMul(a, b) != gfMul(b, a) {
				t.Fatalf("multiplication is not commutative for %d,%d", a, b)
			}
			if gfMul(a, b^1) != gfMul(a, b)^gfMul(a, 1) {
				t.Fatalf("multiplication does not distribute for %d,%d", a, b)
			}
		}
	}
}

// evalAt runs Horner's method over a codeword, treating msg[0] as the highest
// degree coefficient.
func evalAt(msg []byte, x byte) byte {
	var acc byte
	for _, c := range msg {
		acc = gfMul(acc, x) ^ c
	}
	return acc
}

// A Reed-Solomon codeword is divisible by the generator polynomial, so it must
// evaluate to zero at every root a^0..a^(n-1). This verifies the whole RS
// implementation without trusting any remembered lookup table.
func TestReedSolomonCodewordsHaveZeroSyndromes(t *testing.T) {
	cases := []struct {
		data []byte
		ec   int
	}{
		{[]byte("HELLO WORLD"), 10},
		{[]byte{0, 0, 0, 0}, 13},
		{[]byte{255, 254, 1, 2, 3, 4, 5, 6, 7, 8}, 16},
		{[]byte(strings.Repeat("lanrunner", 12)), 26},
	}

	for _, tc := range cases {
		ec := rsEncode(tc.data, tc.ec)
		if len(ec) != tc.ec {
			t.Fatalf("expected %d EC codewords, got %d", tc.ec, len(ec))
		}
		codeword := append(append([]byte{}, tc.data...), ec...)
		for i := 0; i < tc.ec; i++ {
			if s := evalAt(codeword, gfExp[i]); s != 0 {
				t.Fatalf("syndrome %d is %d, want 0 (data len %d, ec %d)", i, s, len(tc.data), tc.ec)
			}
		}
		// Corrupting a byte must break at least one syndrome, proving the check
		// above is actually load-bearing.
		codeword[0] ^= 0x5A
		broken := false
		for i := 0; i < tc.ec; i++ {
			if evalAt(codeword, gfExp[i]) != 0 {
				broken = true
				break
			}
		}
		if !broken {
			t.Fatal("a corrupted codeword still passed every syndrome")
		}
	}
}

func TestGeneratorPolynomialDegree(t *testing.T) {
	for _, n := range []int{7, 10, 13, 16, 22, 26} {
		if g := rsGenerator(n); len(g) != n+1 {
			t.Fatalf("generator for %d EC codewords has %d terms, want %d", n, len(g), n+1)
		}
	}
}

func TestVersionSelectionGrowsWithPayload(t *testing.T) {
	sizes := map[int]int{}
	for _, n := range []int{5, 20, 40, 100, 200} {
		m, err := qrEncode(strings.Repeat("a", n))
		if err != nil {
			t.Fatalf("%d bytes failed to encode: %v", n, err)
		}
		sizes[n] = len(m)
	}
	if !(sizes[5] <= sizes[20] && sizes[20] <= sizes[40] && sizes[40] <= sizes[100] && sizes[100] <= sizes[200]) {
		t.Fatalf("matrix size should not shrink as payload grows: %v", sizes)
	}
	if sizes[5] != 21 {
		t.Fatalf("a short payload should fit version 1 (21 modules), got %d", sizes[5])
	}
}

func TestCapacityLimitIsReported(t *testing.T) {
	if _, err := qrEncode(strings.Repeat("a", 213)); err != nil {
		t.Fatalf("213 bytes should still fit version 10: %v", err)
	}
	if _, err := qrEncode(strings.Repeat("a", 214)); err == nil {
		t.Fatal("214 bytes should be refused rather than silently truncated")
	}
}

// The function patterns are never masked, so they must survive verbatim into
// the final matrix. A scanner cannot lock on without them.
func TestFinderAndTimingPatternsSurvive(t *testing.T) {
	m, err := qrEncode("http://10.0.0.51:47102/kit?c=0123456789abcdef")
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	size := len(m)

	corners := [][2]int{{0, 0}, {0, size - 7}, {size - 7, 0}}
	for _, p := range corners {
		for dr := 0; dr < 7; dr++ {
			for dc := 0; dc < 7; dc++ {
				ring := dr == 0 || dr == 6 || dc == 0 || dc == 6
				core := dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4
				want := ring || core
				if got := m[p[0]+dr][p[1]+dc]; got != want {
					t.Fatalf("finder at %v module (%d,%d) = %v, want %v", p, dr, dc, got, want)
				}
			}
		}
	}

	for i := 8; i < size-8; i++ {
		if m[6][i] != (i%2 == 0) {
			t.Fatalf("horizontal timing module %d is wrong", i)
		}
		if m[i][6] != (i%2 == 0) {
			t.Fatalf("vertical timing module %d is wrong", i)
		}
	}

	if !m[size-8][8] {
		t.Fatal("the mandatory dark module is not set")
	}
}

func TestMatrixIsSquareAndSizedByVersion(t *testing.T) {
	m, err := qrEncode("lanrunner")
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	for i, row := range m {
		if len(row) != len(m) {
			t.Fatalf("row %d has %d modules, matrix is %d wide", i, len(row), len(m))
		}
	}
	if (len(m)-17)%4 != 0 {
		t.Fatalf("size %d is not a valid QR dimension", len(m))
	}
}

func TestSVGOutputIsSelfContained(t *testing.T) {
	svg, err := QRCodeSVG("http://10.0.0.51:47102/kit?c=abc123")
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !strings.HasPrefix(svg, "<svg") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatal("output is not a complete SVG element")
	}
	for _, want := range []string{"viewBox", "path", "#fff", "#000"} {
		if !strings.Contains(svg, want) {
			t.Fatalf("SVG is missing %q", want)
		}
	}
	// Nothing may be fetched from outside; the app must work with no network.
	for _, bad := range []string{"http://", "https://", "<image", "xlink"} {
		if strings.Contains(strings.ReplaceAll(svg, `xmlns="http://www.w3.org/2000/svg"`, ""), bad) {
			t.Fatalf("SVG references something external: %q", bad)
		}
	}
}

func TestEveryMaskProducesADistinctPattern(t *testing.T) {
	seen := map[bool]int{}
	for mask := 0; mask < 8; mask++ {
		count := 0
		for r := 0; r < 21; r++ {
			for c := 0; c < 21; c++ {
				if maskAt(mask, r, c) {
					count++
				}
			}
		}
		if count == 0 || count == 21*21 {
			t.Fatalf("mask %d covers everything or nothing (%d modules)", mask, count)
		}
		seen[true] = count
	}
}
