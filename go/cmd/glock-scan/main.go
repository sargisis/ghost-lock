// glock-scan: быстрый IOC-скан папки логов, результат — JSON в stdout.
//
// glock-scan: fast IOC scan of a log directory; prints JSON to stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"glock/internal/ioc"
	"glock/internal/scan"
)

func main() {
	iocsPath := flag.String("iocs", "../ioc/indicators.json", "путь к indicators.json / path to indicators.json")
	dir := flag.String("dir", "", "папка с логами для скана / folder with logs to scan")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "использование: glock-scan -iocs indicators.json -dir <папка логов>")
		os.Exit(2)
	}

	db, err := ioc.Load(*iocsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	sc, err := scan.New(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	res := sc.ScanDir(*dir, runtime.NumCPU())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
