package scan

import (
	"os"
	"path/filepath"
	"testing"

	"glock/internal/ioc"
)

const testIOC = `{
  "domains": [
    {"value": "mobilesms.io", "weight": 10, "source": "CL"},
    {"value": "sync-services.net", "weight": 10, "source": "CL"}
  ],
  "jailbreak_artifacts": [
    {"value": "/Applications/Cydia.app", "weight": 8, "source": "jb"}
  ],
  "spyware_strings": [
    {"value": "pegasus", "weight": 4, "source": "heuristic"}
  ],
  "stalkerware_profiles": [],
  "spyware_bundles": [
    {"value": "com.mspy.", "weight": 10, "source": "mspy"}
  ],
  "allowlist": ["/system/library/privateframeworks/pegasus\\.framework", "\\(pegasus \\+ \\d+\\)"]
}`

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	path := filepath.Join(t.TempDir(), "indicators.json")
	if err := os.WriteFile(path, []byte(testIOC), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := ioc.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestDetectsC2Domains(t *testing.T) {
	sc := newScanner(t)
	f := sc.scanText("GET http://mobilesms.io/api/v1 token=abc\nprocess sync-services.net [99]", "a.log")
	if len(f) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(f), f)
	}
	if f[0].Weight != 10 || f[0].Type != "domains" {
		t.Fatalf("bad finding: %+v", f[0])
	}
}

func TestAllowlistSuppressesAppleFramework(t *testing.T) {
	sc := newScanner(t)
	text := "/System/Library/PrivateFrameworks/Pegasus.framework/Pegasus pegasus\n1 ??? (Pegasus + 225680)\n"
	if f := sc.scanText(text, "fw.ips"); len(f) != 0 {
		t.Fatalf("allowlist failed: %+v", f)
	}
}

func TestRealPegasusStillFlags(t *testing.T) {
	sc := newScanner(t)
	f := sc.scanText("pegasus implant beacon detected", "bad.ips")
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func TestJailbreakArtifact(t *testing.T) {
	sc := newScanner(t)
	f := sc.scanText("dyld loaded /Applications/Cydia.app via MobileSubstrate", "jb.log")
	if len(f) != 1 || f[0].Value != "/Applications/Cydia.app" {
		t.Fatalf("got %+v", f)
	}
}

func TestWordBoundary(t *testing.T) {
	sc := newScanner(t)
	if f := sc.scanText("pegasusair flight crashed", "wb.ips"); len(f) != 0 {
		t.Fatalf("word-boundary broken: %+v", f)
	}
}

func TestFirstOccurrenceGatedSecondFlagged(t *testing.T) {
	sc := newScanner(t)
	text := "/System/.../Pegasus.framework ok\npegasus alone here\n"
	f := sc.scanText(text, "two.ips")
	if len(f) != 1 {
		t.Fatalf("want exactly 1 finding from line 2, got %d", len(f))
	}
}

func TestScanDirEndToEnd(t *testing.T) {
	sc := newScanner(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "evil.ips"), []byte("http://mobilesms.io/x"), 0o600)
	os.WriteFile(filepath.Join(root, "clean.ips"), []byte("normal safari crash"), 0o600)
	os.WriteFile(filepath.Join(root, "big.ips"), make([]byte, MaxFileBytes+1), 0o600)

	res := sc.ScanDir(root, 4)
	if res.Stats.FilesScanned != 2 {
		t.Fatalf("want 2 scanned, got %d", res.Stats.FilesScanned)
	}
	if res.Stats.FilesSkipped != 1 {
		t.Fatalf("want 1 skipped, got %d", res.Stats.FilesSkipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
}

func BenchmarkScan1MB(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "ind.json")
	os.WriteFile(dbPath, []byte(testIOC), 0o600)
	db, _ := ioc.Load(dbPath)
	sc, _ := New(db)
	text := string(make([]byte, 1<<20))
	
	for b.Loop() {
		sc.scanText(text, "bench")
	}
}
