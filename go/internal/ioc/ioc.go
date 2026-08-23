package ioc

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Entry struct {
	Value  string `json:"value"`
	Weight int    `json:"weight"`
	Source string `json:"source"`
}

type DB struct {
	Domains         []Entry  `json:"domains"`
	Jailbreak       []Entry  `json:"jailbreak_artifacts"`
	SpywareStrings  []Entry  `json:"spyware_strings"`
	StalkerwareProf []Entry  `json:"stalkerware_profiles"`
	SpywareBundles  []Entry  `json:"spyware_bundles"`
	Allowlist       []string `json:"allowlist"`
}

func Load(path string) (*DB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var db DB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &db, nil
}

func normalize(e Entry) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(e.Value))
	return v, v != ""
}

type Needle struct {
	Value     string
	Entry     Entry
	Section   string
	WordBound bool
}

func (d *DB) Needles() []Needle {
	type sec struct {
		name string
		list []Entry
		wb   bool
	}
	sections := []sec{
		{"domains", d.Domains, false},
		{"jailbreak_artifacts", d.Jailbreak, false},
		{"spyware_strings", d.SpywareStrings, true},
		{"stalkerware_profiles", d.StalkerwareProf, false},
		{"spyware_bundles", d.SpywareBundles, false},
	}

	var out []Needle
	for _, s := range sections {
		for _, e := range s.list {
			v, ok := normalize(e)
			if !ok {
				continue
			}
			out = append(out, Needle{
				Value:     v,
				Entry:     e,
				Section:   s.name,
				WordBound: s.wb && len(strings.Fields(v)) == 1,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Value) > len(out[j].Value) })
	return out
}
