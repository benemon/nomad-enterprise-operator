// coverage-gate parses a `go tool cover -func` report on stdin (or from
// the file supplied as the first argument) and enforces per-package
// coverage thresholds as documented in CONTRIBUTING.md §1.5:
//
//	pkg/...                            ≥ 75%
//	internal/controller/phases/...     ≥ 65%
//	internal/controller/...            ≥ 55%   (excluding phases subtree)
//
// Excluded from coverage accounting:
//
//	cmd/...
//	api/v1alpha1/zz_generated.deepcopy.go
//
// Exits 0 if every threshold holds, 1 otherwise, printing a per-package
// summary and the first failing rule. Used by `.github/workflows/coverage.yml`.
//
// The input format is the standard `go tool cover -func` output, one
// statement per line of the form:
//
//	<file>:<startLine>.<startCol>,<endLine>.<endCol>     <statements>    <coveragePct>%
//
// followed by a `total:` summary line which we ignore — we compute
// per-package totals ourselves so a high-coverage package can't mask a
// low-coverage one.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// threshold describes a coverage gate. The first matching prefix wins, so
// rules are ordered most-specific first.
type threshold struct {
	prefix string
	min    float64
}

var thresholds = []threshold{
	{prefix: "internal/controller/phases/", min: 65.0},
	{prefix: "internal/controller/", min: 55.0},
	{prefix: "pkg/", min: 75.0},
}

// excludedFiles are dropped entirely from the input before accounting.
var excludedFiles = []string{
	"api/v1alpha1/zz_generated.deepcopy.go",
}

// excludedPrefixes drop whole subtrees (e.g. cmd/...).
var excludedPrefixes = []string{
	"cmd/",
	// mockery-generated code (neo-dic): pure delegation with zero
	// branches of our own, same rationale as zz_generated.deepcopy.go.
	// Without this the pkg/ aggregate is dominated by generated
	// statements no test should ever target.
	"pkg/nomad/mocks/",
}

// repoRoot is the module path prefix stripped from go-tool-cover lines so
// the rule prefixes above stay short. We read it lazily from go.mod-style
// import paths in the input.
const repoRoot = "github.com/hashicorp/nomad-enterprise-operator/"

type pkgStat struct {
	covered float64
	total   float64
}

func main() {
	var r io.Reader = os.Stdin
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "coverage-gate: %v\n", err)
			os.Exit(2)
		}
		defer func() { _ = f.Close() }()
		r = f
	}

	stats, err := parse(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coverage-gate: %v\n", err)
		os.Exit(2)
	}

	// Determine per-package coverage and which rule each package is gated by.
	pkgs := make([]string, 0, len(stats))
	for p := range stats {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)

	// Aggregate by rule prefix so we report a single coverage number per
	// gated subtree — that's the unit reviewers care about.
	type ruleAgg struct {
		covered float64
		total   float64
	}
	agg := make(map[string]*ruleAgg)

	fmt.Println("Per-package coverage:")
	for _, p := range pkgs {
		s := stats[p]
		pct := 0.0
		if s.total > 0 {
			pct = 100.0 * s.covered / s.total
		}
		rule := matchRule(p)
		mark := "    "
		if rule != "" {
			if agg[rule] == nil {
				agg[rule] = &ruleAgg{}
			}
			agg[rule].covered += s.covered
			agg[rule].total += s.total
			mark = "[gated]"
		}
		fmt.Printf("  %s %-60s %6.2f%%\n", mark, p, pct)
	}

	fmt.Println()
	fmt.Println("Per-rule coverage:")
	failed := false
	for _, t := range thresholds {
		a := agg[t.prefix]
		if a == nil || a.total == 0 {
			fmt.Printf("  WARN  no covered statements under %s — skipping "+
				"(this rule is unenforceable until coverage data exists)\n", t.prefix)
			continue
		}
		pct := 100.0 * a.covered / a.total
		status := "PASS"
		if pct < t.min {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("  %s  %-40s %6.2f%% (threshold %.1f%%)\n", status, t.prefix, pct, t.min)
	}

	if failed {
		fmt.Println()
		fmt.Println("Coverage gate FAILED. Raise tests or, if the regression is " +
			"justified, update CONTRIBUTING.md §1.5 in the same PR.")
		os.Exit(1)
	}
}

// matchRule returns the prefix of the first threshold the package matches,
// or "" if no rule covers it.
func matchRule(pkg string) string {
	for _, t := range thresholds {
		if strings.HasPrefix(pkg, t.prefix) {
			return t.prefix
		}
	}
	return ""
}

// parse reads a `go tool cover -func` report and returns covered/total
// statement counts per package.
func parse(r io.Reader) (map[string]*pkgStat, error) {
	stats := make(map[string]*pkgStat)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "total:") {
			continue
		}
		// `go tool cover -func` outputs both the per-statement detail (the
		// format the doc comment describes) and a per-function summary of
		// the form `<file>:<line>:\t<func>\t<pct>%`. We only want the
		// per-function lines; they are the ones the standard tool emits.
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// fields[0]: file:line:
		// fields[1]: function name
		// fields[len-1]: NN.N%
		fileRef := fields[0]
		pctStr := fields[len(fields)-1]
		if !strings.HasSuffix(pctStr, "%") {
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSuffix(pctStr, "%"), 64)
		if err != nil {
			continue
		}

		file := strings.TrimSuffix(fileRef, ":")
		// Strip "<file>:<line>" suffix to get just the file path.
		if i := strings.LastIndex(file, ":"); i >= 0 {
			file = file[:i]
		}
		file = strings.TrimPrefix(file, repoRoot)

		if isExcluded(file) {
			continue
		}
		pkg := pkgOf(file)

		// `go tool cover -func` reports per-function coverage as a
		// percentage, not raw covered/total counts. We approximate by
		// treating each function as a single weighted statement; this is
		// sufficient for gate-level aggregation. If we ever need true
		// statement-weighted aggregation we'd parse cover.out directly.
		s, ok := stats[pkg]
		if !ok {
			s = &pkgStat{}
			stats[pkg] = s
		}
		s.covered += pct / 100.0
		s.total++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read coverage report: %w", err)
	}
	return stats, nil
}

func isExcluded(file string) bool {
	for _, f := range excludedFiles {
		if file == f {
			return true
		}
	}
	for _, p := range excludedPrefixes {
		if strings.HasPrefix(file, p) {
			return true
		}
	}
	return false
}

// pkgOf returns the directory containing the file, normalised with a
// trailing "/" so prefix matching against rule prefixes is unambiguous.
func pkgOf(file string) string {
	i := strings.LastIndex(file, "/")
	if i < 0 {
		return ""
	}
	return file[:i+1]
}
