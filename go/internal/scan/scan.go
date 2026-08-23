package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"glock/internal/ioc"
)

const MaxFileBytes = 8 << 20

type Finding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Weight   int    `json:"weight"`
	Source   string `json:"source"`
	Location string `json:"location"`
	Context  string `json:"context"`
}

type Stats struct {
	FilesScanned int     `json:"files"`
	FilesSkipped int     `json:"skipped"`
	BytesRead    int64   `json:"bytes"`
	Seconds      float64 `json:"seconds"`
}

type Result struct {
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}

type Scanner struct {
	db        *ioc.DB
	needles   []ioc.Needle
	allowlist []*regexp.Regexp
}

func New(db *ioc.DB) (*Scanner, error) {
	var regs []*regexp.Regexp
	for _, raw := range db.Allowlist {
		re, err := regexp.Compile("(?i)" + raw)
		if err == nil {
			regs = append(regs, re)
		}
	}
	return &Scanner{db: db, needles: db.Needles(), allowlist: regs}, nil
}

func isAlnum(b byte) bool {
	switch {
	case b >= '0' && b <= '9', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return true
	case b >= 0x80:
		return true
	}
	return false
}

func collapseSpace(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\r' {
			if prevSpace {
				continue
			}
			prevSpace = true
			b.WriteByte(' ')
		} else {
			prevSpace = false
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Scanner) gated(line string) bool {
	for _, re := range s.allowlist {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func (s *Scanner) source(n ioc.Needle, ls int, lowered string) string {
	src := n.Entry.Source
	if strings.TrimSpace(src) == "" {
		src = "unknown"
	}
	return fmt.Sprintf("%s (строка %d)", src, strings.Count(lowered[:ls], "\n")+1)
}

func (s *Scanner) scanText(text, location string) []Finding {
	lowered := strings.ToLower(text)
	var out []Finding

	for _, n := range s.needles {
		idx := 0
		for hops := 0; hops < 10000; hops++ {
			pos := strings.Index(lowered[idx:], n.Value)
			if pos < 0 {
				break
			}
			pos += idx
			end := pos + len(n.Value)

			if n.WordBound {
				beforeOK := pos == 0 || !isAlnum(lowered[pos-1])
				afterOK := end >= len(lowered) || !isAlnum(lowered[end])
				if !beforeOK || !afterOK {
					next := strings.Index(lowered[end:], n.Value)
					if next < 0 {
						break
					}
					idx = end + next
					continue
				}
			}

			ls := strings.LastIndexByte(lowered[:pos], '\n') + 1
			le := strings.IndexByte(lowered[end:], '\n')
			if le < 0 {
				le = len(lowered)
			} else {
				le += end
			}
			line := collapseSpace(lowered[ls:le])

			if s.gated(line) {
				next := strings.Index(lowered[end:], n.Value)
				if next < 0 {
					break
				}
				idx = end + next
				continue
			}

			ctxStart := pos - 80
			if ctxStart < ls {
				ctxStart = ls
			}
			ctxEnd := pos + len(n.Value) + 80
			if ctxEnd > le {
				ctxEnd = le
			}
			context := collapseSpace(strings.ReplaceAll(lowered[ctxStart:ctxEnd], "\x00", ""))

			out = append(out, Finding{
				Type:     n.Section,
				Value:    n.Entry.Value,
				Weight:   n.Entry.Weight,
				Source:   s.source(n, ls, lowered),
				Location: location,
				Context:  context,
			})
			break
		}
	}
	return out
}

func (s *Scanner) ScanDir(root string, workers int) Result {
	start := time.Now()
	res := Result{Findings: []Finding{}}

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				st, err := os.Stat(path)
				if err != nil || st.IsDir() || st.Size() > MaxFileBytes {
					mu.Lock()
					res.Stats.FilesSkipped++
					mu.Unlock()
					continue
				}
				data, err := os.ReadFile(path)
				if err != nil {
					mu.Lock()
					res.Stats.FilesSkipped++
					mu.Unlock()
					continue
				}
				found := s.scanText(string(data), path)

				mu.Lock()
				res.Stats.FilesScanned++
				res.Stats.BytesRead += int64(len(data))
				res.Findings = append(res.Findings, found...)
				mu.Unlock()
			}
		}()
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		jobs <- path
		return nil
	})
	close(jobs)
	wg.Wait()

	res.Stats.Seconds = time.Since(start).Seconds()
	return res
}
