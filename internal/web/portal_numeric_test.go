package web

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// unitsAreFractional lists the fields whose input carries different units from
// the Go type behind it, so the type alone does not decide whether the box may
// hold a fraction.
//
// Both are int64 byte counts edited as gigabytes, and their handlers multiply.
// Rounding those boxes turns anything under half a gigabyte into 0, and 0 is
// how a quota is disabled - so where the units and the type disagree, the units
// win. Nothing else in the configuration is edited in converted units; adding
// one means adding it here.
var unitsAreFractional = map[string]bool{
	"limit_bytes":   true,
	"ceiling_bytes": true,
}

// Every number input in the portal rounds unless the value behind it may hold a
// fraction, and this is the only thing holding that rule.
//
// It is a rule about roughly thirty call sites in a file with no test framework
// of its own, and it fails in two directions that are both silent for a while.
// A float field that loses its opt-out turns a typed 0.4 into 0: on a quality
// weight that stops the selector counting latency, and model.Normalise only
// repairs the Quality group when *every* weight is zero, so a single zeroed one
// survives the load with nothing in the portal saying so. An int field that
// gains one lets a decimal through, and Go's decoder then refuses the whole PUT
// with "cannot unmarshal number 90.5", blocking every unrelated edit in the
// form until somebody finds the field.
//
// The list of float fields comes from model.Config by reflection rather than
// from a copy kept here, so a new one is covered the day it is added.
func TestEveryFractionalPortalInputOptsOutOfRounding(t *testing.T) {
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read the portal script: %v", err)
	}
	src := string(js)

	fractional := map[string]bool{}
	for tag := range unitsAreFractional {
		fractional[tag] = true
	}
	for _, tag := range floatTags(reflect.TypeOf(model.Config{}), map[reflect.Type]bool{}) {
		fractional[tag] = true
	}

	calls := numCalls(src)
	// A floor, because every failure this test has is a failure to look. The
	// scan is a text scan over a file with no parser behind it, so a rename of
	// the helper, an asset pipeline that minifies, or a paren the balancer
	// mis-scopes all end with it matching nothing and reporting ok - and both
	// CLAUDE.md and app.js name this test as the only thing holding the rule.
	// Verified by renaming num( to numField( throughout: without this the suite
	// stayed green with all thirty-odd inputs unchecked.
	if len(calls) < 30 {
		t.Fatalf("found %d number inputs in the portal; there are more than that, so the scan is broken "+
			"and every assertion below is passing without looking at anything", len(calls))
	}

	matched := map[string]bool{}
	for _, call := range calls {
		tag, ok := boundTag(call, fractional)
		if !ok {
			// A call bound to something that is not a fractional field. It must
			// not opt out: that is the direction that refuses the save.
			if strings.Contains(call, "float: true") {
				t.Errorf("a number input opts out of rounding but is not bound to a fractional field, "+
					"so a decimal typed into it fails the whole save:\n\t%s", oneLine(call))
			}
			continue
		}
		matched[tag] = true
		if !strings.Contains(call, "float: true") {
			t.Errorf("the input for %q rounds, and that field holds fractions: a typed 0.4 becomes 0:\n\t%s",
				tag, oneLine(call))
		}
	}

	// And the other half of the same floor: every fractional field has to have
	// been found. A binding the scan cannot see is not a pass, it is a field
	// nobody is checking, which is how the five probe inputs went unguarded -
	// they are built through a wrapper, so the call this scan sees is the
	// wrapper's own and carries neither the assignment nor the options.
	for tag := range fractional {
		if !matched[tag] {
			t.Errorf("no number input was found bound to %q; either the field lost its input or the scan "+
				"cannot see it, and both mean it is unchecked", tag)
		}
	}
}

// floatTags returns the json names of every float64 field reachable in a config.
func floatTags(rt reflect.Type, seen map[reflect.Type]bool) []string {
	if seen[rt] {
		return nil
	}
	seen[rt] = true
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.Struct:
			out = append(out, floatTags(ft, seen)...)
		case reflect.Float64:
			if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag != "" && tag != "-" {
				out = append(out, tag)
			}
		}
	}
	return out
}

// numCalls returns the source of every call that builds a number input, parens
// balanced, so an options object on a later line belongs to the call it was
// written under.
//
// Two names, not one. `num(` is the helper, and `probeField(` is a wrapper
// around it: the wrapper's own num( call carries a variable for its options and
// a setter closure rather than an assignment, so scanning only num( sees the
// wrapper once and the five probe inputs never - which is exactly what happened,
// and adding float: true to the window_size input left this test green.
//
// The definitions of both are skipped by name. The previous version claimed to
// skip `function num(` and did not, because the character before it is a space:
// the guard only rejected identifiers *ending* in num, such as enum(. It was
// harmless because the definition line contains neither a binding nor the
// literal, which is not a reason to leave a scanner reporting a call that is not
// one.
func numCalls(src string) []string {
	var out []string
	for _, name := range []string{"num(", "probeField("} {
		for i := 0; ; {
			j := strings.Index(src[i:], name)
			if j < 0 {
				break
			}
			j += i
			i = j + len(name)
			if j > 0 && isWord(src[j-1]) {
				continue
			}
			if isDefinition(src, j) {
				continue
			}
			if k, ok := matchParen(src, j+len(name)-1); ok {
				out = append(out, src[j:k+1])
				i = k + 1
			}
		}
	}
	return out
}

// isDefinition reports whether the identifier at i is being declared rather
// than called: `function num(`, `const probeField = (`, or a bare `= (`.
func isDefinition(src string, i int) bool {
	head := src[max(0, i-40):i]
	return strings.Contains(head, "function ") ||
		strings.HasSuffix(strings.TrimSpace(head), "=") ||
		strings.Contains(head, "const ") || strings.Contains(head, "let ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// matchParen finds the ')' closing the '(' at open, ignoring parens inside
// string literals.
//
// Without that, one unbalanced paren in a label or a help string - 'Rate
// (packets/sec', or a ':-)' in prose - runs the search past the end of its call
// and swallows every call after it into one blob. boundTag would then match a
// tag from one call against a `float: true` belonging to another, and the
// dangerous direction is the quiet one: several inputs drop out of the scan
// while the test still reports ok. The floor assertion above is the backstop;
// this is the thing that stops it being needed.
func matchParen(src string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(src); i++ {
		switch c := src[i]; c {
		case '\'', '"', '`':
			j, ok := skipString(src, i)
			if !ok {
				return 0, false
			}
			i = j
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// skipString returns the index of the quote closing the one at i.
func skipString(src string, i int) (int, bool) {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case q:
			return j, true
		case '\n':
			if q != '`' {
				// An unterminated quote on one line is not a string this
				// scanner can reason about; say so rather than guess.
				return 0, false
			}
		}
	}
	return 0, false
}

func isWord(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// boundTag reports which fractional field a call assigns to, if any. It matches
// on the assignment rather than anywhere in the call, so a placeholder or a
// label mentioning a name is not mistaken for a binding.
// It iterates in sorted order rather than over the map, because Go randomises
// map iteration: a call binding two fractional fields would otherwise name a
// different one on each run, and a failure message that changes between runs is
// a failure message nobody trusts.
func boundTag(call string, fractional map[string]bool) (string, bool) {
	tags := make([]string, 0, len(fractional))
	for tag := range fractional {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if strings.Contains(call, "."+tag+" =") {
			return tag, true
		}
	}
	return "", false
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
