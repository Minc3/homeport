package web

import (
	"reflect"
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

	for _, call := range numCalls(src) {
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
		if !strings.Contains(call, "float: true") {
			t.Errorf("the input for %q rounds, and that field holds fractions: a typed 0.4 becomes 0:\n\t%s",
				tag, oneLine(call))
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

// numCalls returns the source of every num(...) call, parens balanced, so an
// options object on a later line belongs to the call it was written under.
func numCalls(src string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(src[i:], "num(")
		if j < 0 {
			return out
		}
		j += i
		// Skip `function num(` and any identifier ending in "num".
		if j > 0 && (isWord(src[j-1])) {
			i = j + 4
			continue
		}
		depth, k := 0, j+3
		for ; k < len(src); k++ {
			switch src[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if k >= len(src) {
			return out
		}
		out = append(out, src[j:k+1])
		i = k + 1
	}
}

func isWord(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// boundTag reports which fractional field a call assigns to, if any. It matches
// on the assignment rather than anywhere in the call, so a placeholder or a
// label mentioning a name is not mistaken for a binding.
func boundTag(call string, fractional map[string]bool) (string, bool) {
	for tag := range fractional {
		if strings.Contains(call, "."+tag+" =") {
			return tag, true
		}
	}
	return "", false
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
