package main

// A small QR encoder, byte mode, error correction level M, versions 1 to 10.
//
// Lan Runner ships as one binary with no module downloads, because the machines
// it targets may never have touched the internet. That rules out a QR library,
// so the encoder lives here. Ten versions carry 213 bytes, which is far more
// than the handoff URLs this is used for.
//
// Level M corrects roughly 15% of modules. That is the usual choice for a code
// displayed on screen and scanned from a phone a few inches away.

import (
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------- GF(256)

// Galois field arithmetic for Reed-Solomon, over the QR primitive polynomial
// x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator builds the degree-n generator polynomial, the product of
// (x - a^i) for i in 0..n-1.
func rsGenerator(n int) []byte {
	g := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g
}

// rsEncode returns the n error-correction codewords for data.
func rsEncode(data []byte, n int) []byte {
	g := rsGenerator(n)
	rem := make([]byte, n)
	for _, d := range data {
		factor := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for i, c := range g[1:] {
			rem[i] ^= gfMul(c, factor)
		}
	}
	return rem
}

// ---------------------------------------------------------------- version data

// qrVersion describes one version at error correction level M.
type qrVersion struct {
	totalCodewords int
	ecPerBlock     int
	group1Blocks   int
	group1Data     int
	group2Blocks   int
	group2Data     int
	alignment      []int
}

// Versions 1 to 10 at level M, from the tables in ISO/IEC 18004.
var qrVersions = map[int]qrVersion{
	1:  {26, 10, 1, 16, 0, 0, nil},
	2:  {44, 16, 1, 28, 0, 0, []int{6, 18}},
	3:  {70, 26, 1, 44, 0, 0, []int{6, 22}},
	4:  {100, 18, 2, 32, 0, 0, []int{6, 26}},
	5:  {134, 24, 2, 43, 0, 0, []int{6, 30}},
	6:  {172, 16, 4, 27, 0, 0, []int{6, 34}},
	7:  {196, 18, 4, 31, 0, 0, []int{6, 22, 38}},
	8:  {242, 22, 2, 38, 2, 39, []int{6, 24, 42}},
	9:  {292, 22, 3, 36, 2, 37, []int{6, 26, 46}},
	10: {346, 26, 4, 43, 1, 44, []int{6, 28, 50}},
}

// Format information for level M, one per mask, already including its BCH
// error correction and the 0x5412 mask that the spec applies.
var qrFormatM = [8]uint32{
	0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
}

// Version information, only present from version 7 upwards.
var qrVersionInfo = map[int]uint32{
	7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3,
}

func (v qrVersion) dataCodewords() int {
	return v.group1Blocks*v.group1Data + v.group2Blocks*v.group2Data
}

// byteCapacity is how many raw bytes fit, after the mode nibble and the
// character count field.
func (v qrVersion) byteCapacity(version int) int {
	countBits := 8
	if version >= 10 {
		countBits = 16
	}
	return (v.dataCodewords()*8 - 4 - countBits) / 8
}

// ---------------------------------------------------------------- bit buffer

type bitBuffer struct {
	bits []bool
}

func (b *bitBuffer) append(value uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, value&(1<<uint(i)) != 0)
	}
}

func (b *bitBuffer) bytes() []byte {
	out := make([]byte, (len(b.bits)+7)/8)
	for i, set := range b.bits {
		if set {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}

// ---------------------------------------------------------------- encoding

// qrEncode turns text into a module matrix. true means a dark module.
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)

	version := 0
	for v := 1; v <= 10; v++ {
		if len(data) <= qrVersions[v].byteCapacity(v) {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("%d bytes is more than this encoder carries (max %d)",
			len(data), qrVersions[10].byteCapacity(10))
	}
	spec := qrVersions[version]

	countBits := 8
	if version >= 10 {
		countBits = 16
	}

	var buf bitBuffer
	buf.append(0b0100, 4) // byte mode
	buf.append(uint32(len(data)), countBits)
	for _, d := range data {
		buf.append(uint32(d), 8)
	}

	capacityBits := spec.dataCodewords() * 8
	for i := 0; i < 4 && len(buf.bits) < capacityBits; i++ {
		buf.bits = append(buf.bits, false) // terminator
	}
	for len(buf.bits)%8 != 0 {
		buf.bits = append(buf.bits, false)
	}
	padded := buf.bytes()
	for i := 0; len(padded) < spec.dataCodewords(); i++ {
		if i%2 == 0 {
			padded = append(padded, 0xEC)
		} else {
			padded = append(padded, 0x11)
		}
	}

	// Split into blocks, error-correct each, then interleave.
	type block struct{ data, ec []byte }
	var blocks []block
	offset := 0
	for i := 0; i < spec.group1Blocks; i++ {
		d := padded[offset : offset+spec.group1Data]
		offset += spec.group1Data
		blocks = append(blocks, block{d, rsEncode(d, spec.ecPerBlock)})
	}
	for i := 0; i < spec.group2Blocks; i++ {
		d := padded[offset : offset+spec.group2Data]
		offset += spec.group2Data
		blocks = append(blocks, block{d, rsEncode(d, spec.ecPerBlock)})
	}

	maxData := spec.group1Data
	if spec.group2Data > maxData {
		maxData = spec.group2Data
	}
	final := make([]byte, 0, spec.totalCodewords)
	for i := 0; i < maxData; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				final = append(final, b.data[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, b := range blocks {
			final = append(final, b.ec[i])
		}
	}

	return buildMatrix(version, spec, final)
}

// ---------------------------------------------------------------- matrix

// functionPatterns lays down everything that is fixed by the specification
// rather than carried by the payload, and reports which modules it claimed so
// data placement and masking can skip them.
func functionPatterns(version int, spec qrVersion, size int) (modules, reserved [][]bool) {
	modules = make([][]bool, size)
	reserved = make([][]bool, size)
	for i := range modules {
		modules[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}

	set := func(r, c int, dark bool) {
		modules[r][c] = dark
		reserved[r][c] = true
	}

	// Finder patterns and their separators.
	for _, p := range [][2]int{{0, 0}, {0, size - 7}, {size - 7, 0}} {
		for dr := -1; dr <= 7; dr++ {
			for dc := -1; dc <= 7; dc++ {
				r, c := p[0]+dr, p[1]+dc
				if r < 0 || r >= size || c < 0 || c >= size {
					continue
				}
				inRing := dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 &&
					(dr == 0 || dr == 6 || dc == 0 || dc == 6)
				inCore := dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4
				set(r, c, inRing || inCore)
			}
		}
	}

	// Timing patterns.
	for i := 8; i < size-8; i++ {
		if !reserved[6][i] {
			set(6, i, i%2 == 0)
		}
		if !reserved[i][6] {
			set(i, 6, i%2 == 0)
		}
	}

	// Alignment patterns, skipping any that would collide with a finder.
	for _, ar := range spec.alignment {
		for _, ac := range spec.alignment {
			if reserved[ar][ac] {
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
					set(ar+dr, ac+dc, dark)
				}
			}
		}
	}

	// The dark module, always set.
	set(size-8, 8, true)

	// Reserve the format areas so data placement skips them.
	for i := 0; i < 9; i++ {
		if !reserved[8][i] {
			set(8, i, false)
		}
		if !reserved[i][8] {
			set(i, 8, false)
		}
	}
	for i := 0; i < 8; i++ {
		if !reserved[8][size-1-i] {
			set(8, size-1-i, false)
		}
		if !reserved[size-1-i][8] {
			set(size-1-i, 8, false)
		}
	}

	// Version information, versions 7 and up.
	if info, ok := qrVersionInfo[version]; ok {
		for i := 0; i < 18; i++ {
			dark := info&(1<<uint(i)) != 0
			r, c := i/3, size-11+i%3
			set(r, c, dark)
			set(c, r, dark)
		}
	}

	return modules, reserved
}

func buildMatrix(version int, spec qrVersion, codewords []byte) ([][]bool, error) {
	size := version*4 + 17
	modules, reserved := functionPatterns(version, spec, size)

	// Place data in the upward-then-downward zigzag, two columns at a time.
	bitIndex := 0
	totalBits := len(codewords) * 8
	upward := true
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right-- // the vertical timing pattern column is skipped entirely
		}
		for i := 0; i < size; i++ {
			row := i
			if upward {
				row = size - 1 - i
			}
			for _, col := range []int{right, right - 1} {
				if reserved[row][col] {
					continue
				}
				dark := false
				if bitIndex < totalBits {
					dark = codewords[bitIndex/8]&(1<<uint(7-bitIndex%8)) != 0
				}
				modules[row][col] = dark
				bitIndex++
			}
		}
		upward = !upward
	}

	// Try every mask and keep the one the spec scores best.
	best := -1
	var bestMatrix [][]bool
	for mask := 0; mask < 8; mask++ {
		candidate := applyMask(modules, reserved, mask, size)
		placeFormat(candidate, mask, size)
		score := penalty(candidate, size)
		if best == -1 || score < best {
			best, bestMatrix = score, candidate
		}
	}
	if bestMatrix == nil {
		return nil, errors.New("no usable mask")
	}
	return bestMatrix, nil
}

func maskAt(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	default:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
}

func applyMask(src, reserved [][]bool, mask, size int) [][]bool {
	out := make([][]bool, size)
	for r := 0; r < size; r++ {
		out[r] = make([]bool, size)
		copy(out[r], src[r])
		for c := 0; c < size; c++ {
			if !reserved[r][c] && maskAt(mask, r, c) {
				out[r][c] = !out[r][c]
			}
		}
	}
	return out
}

func placeFormat(m [][]bool, mask, size int) {
	bits := qrFormatM[mask]
	for i := 0; i < 15; i++ {
		dark := bits&(1<<uint(i)) != 0

		// Copy around the top-left finder.
		switch {
		case i < 6:
			m[8][i] = dark
		case i == 6:
			m[8][7] = dark
		case i == 7:
			m[8][8] = dark
		case i == 8:
			m[7][8] = dark
		default:
			m[14-i][8] = dark
		}

		// Duplicate copy split between the other two finders.
		if i < 8 {
			m[8][size-1-i] = dark
		} else {
			m[size-15+i][8] = dark
		}
	}
	m[size-8][8] = true // dark module
}

// penalty scores a masked matrix by the four rules in the spec. Lower is
// better; the rules discourage patterns that confuse scanners.
func penalty(m [][]bool, size int) int {
	score := 0

	// Rule 1: runs of five or more same-coloured modules in a line.
	for i := 0; i < size; i++ {
		runRow, runCol := 1, 1
		for j := 1; j < size; j++ {
			if m[i][j] == m[i][j-1] {
				runRow++
			} else {
				if runRow >= 5 {
					score += runRow - 2
				}
				runRow = 1
			}
			if m[j][i] == m[j-1][i] {
				runCol++
			} else {
				if runCol >= 5 {
					score += runCol - 2
				}
				runCol = 1
			}
		}
		if runRow >= 5 {
			score += runRow - 2
		}
		if runCol >= 5 {
			score += runCol - 2
		}
	}

	// Rule 2: solid 2x2 blocks.
	for r := 0; r < size-1; r++ {
		for c := 0; c < size-1; c++ {
			if m[r][c] == m[r][c+1] && m[r][c] == m[r+1][c] && m[r][c] == m[r+1][c+1] {
				score += 3
			}
		}
	}

	// Rule 3: the finder-like 1:1:3:1:1 sequence with four light modules beside it.
	patternA := []bool{true, false, true, true, true, false, true, false, false, false, false}
	patternB := []bool{false, false, false, false, true, false, true, true, true, false, true}
	matches := func(get func(int) bool, start int, want []bool) bool {
		for k, w := range want {
			if get(start+k) != w {
				return false
			}
		}
		return true
	}
	for i := 0; i < size; i++ {
		row := func(j int) bool { return m[i][j] }
		col := func(j int) bool { return m[j][i] }
		for j := 0; j+11 <= size; j++ {
			if matches(row, j, patternA) || matches(row, j, patternB) {
				score += 40
			}
			if matches(col, j, patternA) || matches(col, j, patternB) {
				score += 40
			}
		}
	}

	// Rule 4: drift away from an even balance of dark and light.
	dark := 0
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if m[r][c] {
				dark++
			}
		}
	}
	percent := dark * 100 / (size * size)
	deviation := percent - 50
	if deviation < 0 {
		deviation = -deviation
	}
	score += (deviation / 5) * 10

	return score
}

// ---------------------------------------------------------------- rendering

// qrSVG renders a matrix as a standalone SVG. One path holds every dark
// module, which keeps the markup small enough to inline comfortably.
func qrSVG(matrix [][]bool, quiet int) string {
	size := len(matrix)
	total := size + quiet*2

	var path strings.Builder
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if matrix[r][c] {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", c+quiet, r+quiet)
			}
		}
	}

	return fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" role="img" aria-label="QR code">`+
			`<rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`,
		total, total, total*8, total*8, total, total, path.String())
}

// QRCodeSVG is the one call the rest of the program makes.
func QRCodeSVG(text string) (string, error) {
	m, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	return qrSVG(m, 4), nil
}
