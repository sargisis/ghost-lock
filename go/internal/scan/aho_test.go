package scan

import (
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"glock/internal/ioc"
)

// naiveScan — прежний алгоритм (strings.Index на каждую иглу), эталон для сверки.
//
// naiveScan — the previous algorithm (strings.Index per needle), the reference.
func naiveScan(s *Scanner, text string) []string {
	lowered := strings.ToLower(text)
	var out []string
	for _, n := range s.needles {
		idx := 0
		for {
			pos := strings.Index(lowered[idx:], n.Value)
			if pos < 0 {
				break
			}
			pos += idx
			end := pos + len(n.Value)
			idx = pos + 1
			if n.WordBound {
				if (pos > 0 && isAlnum(lowered[pos-1])) || (end < len(lowered) && isAlnum(lowered[end])) {
					continue
				}
			}
			if n.DomainBound && !domainBoundOK(lowered, pos, end) {
				continue
			}
			ls := strings.LastIndexByte(lowered[:pos], '\n') + 1
			le := strings.IndexByte(lowered[end:], '\n')
			if le < 0 {
				le = len(lowered)
			} else {
				le += end
			}
			if s.gated(collapseSpace(lowered[ls:le])) {
				continue
			}
			out = append(out, n.Section+"|"+n.Entry.Value)
			break
		}
	}
	return out
}

func keys(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Type+"|"+f.Value)
	}
	return out
}

func TestAhoMatchesNaiveOnRealDB(t *testing.T) {
	db, err := ioc.Load("../../../ghost_lock/ioc/indicators.json")
	if err != nil {
		t.Skip("реальная база недоступна:", err)
	}
	sc, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	noise := []string{" ", "\n", ".", "/", "a", "x", "-", "\x00", "Pegasus.framework", "(pegasus + 12)"}
	for round := 0; round < 200; round++ {
		var b strings.Builder
		for i := 0; i < 60; i++ {
			if rng.Intn(3) == 0 {
				n := sc.needles[rng.Intn(len(sc.needles))].Value
				if rng.Intn(2) == 0 {
					n = strings.ToUpper(n)
				}
				b.WriteString(n)
			} else {
				b.WriteString(noise[rng.Intn(len(noise))])
			}
		}
		text := b.String()
		got, want := keys(sc.scanText(text, "t")), naiveScan(sc, text)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: aho=%v naive=%v\ntext=%q", round, got, want, text)
		}
	}
}

func TestAhoOverlappingAndNested(t *testing.T) {
	a := newAho([]string{"he", "she", "his", "hers", "e"})
	var got [][2]int
	a.each("ushers", func(idx int32, end int) bool {
		got = append(got, [2]int{int(idx), end})
		return true
	})
	// she@4, he@4, e@4, hers@6
	want := [][2]int{{1, 4}, {0, 4}, {4, 4}, {3, 6}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func BenchmarkScanTextRealDB(b *testing.B) {
	db, err := ioc.Load("../../../ghost_lock/ioc/indicators.json")
	if err != nil {
		b.Skip(err)
	}
	sc, _ := New(db)
	data, _ := os.ReadFile("../../../ghost_lock/ioc/indicators.json")
	text := strings.Repeat(string(data), 4)
	b.SetBytes(int64(len(text)))
	for i := 0; i < b.N; i++ {
		sc.scanText(text, "bench")
	}
}
