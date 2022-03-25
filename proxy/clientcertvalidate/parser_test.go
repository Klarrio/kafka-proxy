package clientcertvalidate

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func compareStringArrays(this, that []string) bool {
	if len(this) != len(that) {
		return false
	}
	for index := range this {
		if this[index] != that[index] {
			return false
		}
	}
	return true
}

func compareSortedStringArrays(this, that []string) bool {
	sort.Strings(this)
	sort.Strings(that)
	if len(this) != len(that) {
		return false
	}
	for index := range this {
		if this[index] != that[index] {
			return false
		}
	}
	return true
}

// Prefix tests:

func TestNoPrefixSubjectParser(t *testing.T) {
	input := "/CN=[aaa,[],2,3]/OU=[bbb]/O=[ccc]/S=[ddd]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: invalid prefix:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidPrefixSubjectParser(t *testing.T) {
	input := "t:/CN=[aaa,[],2,3]/OU=[bbb]/O=[ccc]/S=[ddd]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: invalid prefix:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestUnsupportedFieldNameSubjectParser(t *testing.T) {
	input := "s:/UNSUPPORTED=[aaa,2,3]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: unsupported field:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidPatternParser(t *testing.T) {
	input := "r:/CN=[?Z^aaa.{1}\\z$]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "invalid pattern: field") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

// String subjects:

func TestValidStringSubjectParser(t *testing.T) {
	input := "s:/CN=[aaa,1,2,3]/OU=[bbb,4,5]/O=[ccc,6]/S=[ddd,7,8]"
	parser := NewSubjectParser(input)
	certSsubject, parseErr := parser.Parse()
	if parseErr != nil {
		t.Fatal("expected string to parse but got error: ", parseErr)
	}

	expected := map[string][]string{
		"CN": []string{"aaa", "1", "2", "3"},
		"OU": []string{"bbb", "4", "5"},
		"O":  []string{"ccc", "6"},
		"S":  []string{"ddd", "7", "8"},
	}

	for k, v := range expected {
		received, ok := certSsubject.KVs()[k]
		if !ok {
			t.Fatalf("expected key '%s' in parsed output", k)
		}
		if !compareSortedStringArrays(received, v) {
			t.Fatalf("values for key '%s' invalid, expected: %v, received: %v", k, v, received)
		}
	}

}

func TestNestedParensParseAsValueParser(t *testing.T) {
	input := "s:/CN=[aaa,[],2,3]/OU=[bbb,{123},5]/O=[ccc,[{1,2}],6,{7,8}]/S=[ddd]"
	parser := NewSubjectParser(input)
	certSsubject, parseErr := parser.Parse()

	if parseErr != nil {
		t.Fatal("expected string to parse but got error: ", parseErr)
	}

	expected := map[string][]string{
		"CN": []string{"aaa", "[]", "2", "3"},
		"OU": []string{"bbb", "{123}", "5"},
		"O":  []string{"ccc", "[{1,2}]", "6", "{7,8}"},
		"S":  []string{"ddd"},
	}

	for k, v := range expected {
		received, ok := certSsubject.KVs()[k]
		if !ok {
			t.Fatalf("expected key '%s' in parsed output", k)
		}
		if !compareSortedStringArrays(received, v) {
			t.Fatalf("values for key '%s' invalid, expected: %v, received: %v", k, v, received)
		}
	}
}

func TestUnbalancedEscapedValueParser(t *testing.T) {
	input := "s:/CN=[aaa,\\],2,3]/OU=[bbb,\\},5]/O=[ccc,\\}\\,\\],6,7\\,8\\}]/S=[ddd]"
	parser := NewSubjectParser(input)
	certSsubject, parseErr := parser.Parse()

	if parseErr != nil {
		t.Fatal("expected string to parse but got error: ", parseErr)
	}

	expected := map[string][]string{
		"CN": []string{"aaa", "\\]", "2", "3"},
		"OU": []string{"bbb", "\\}", "5"},
		"O":  []string{"ccc", "\\}\\,\\]", "6", "7\\,8\\}"},
		"S":  []string{"ddd"},
	}

	for k, v := range expected {
		received, ok := certSsubject.KVs()[k]
		if !ok {
			t.Fatalf("expected key '%s' in parsed output", k)
		}
		if !compareSortedStringArrays(received, v) {
			t.Fatalf("values for key '%s' invalid, expected: %v, received: %v", k, v, received)
		}
	}
}

func TestInvalidUnterminatedKeyStringSubjectParser(t *testing.T) {
	input := "s:/CN/OU=[bbb]/O=[ccc]/S=[ddd]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: invalid field:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidNoKeyStringSubjectParser(t *testing.T) {
	input := "s:/CN=[aaa]//O=[ccc]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: invalid field:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidUntInvalidKeyStringSubjectParser(t *testing.T) {
	input := "s:/CNlowercase=[a]/OU=[bbb]/O=[ccc]/S=[ddd]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: invalid field:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidUnenclosedValueStringSubjectParser(t *testing.T) {
	input := "s:/CN=a/OU=[bbb]/O=[ccc]/S=[ddd]"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: unexpected input:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestInvalidUnterminatedValueStringSubjectParser(t *testing.T) {
	input := "s:/CN=[a]/OU=[bbb"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: value insufficient input:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

// Pattern subjects

func TestValidPatternSubjectParser(t *testing.T) {
	// not that [[]] makes sense but that is left to the regex compile
	input := "r:/CN=[aaa.*,1,2,3]/OU=[bbb[a-z]{1,},4,5]/O=[eee,ccc[1-9]{1,10},6]/S=[ddd?[[]],7,8]"
	parser := NewSubjectParser(input)
	certSsubject, parseErr := parser.Parse()
	if parseErr != nil {
		t.Fatal("expected string to parse but got error: ", parseErr)
	}

	expected := map[string][]string{
		"CN": []string{"aaa.*", "1", "2", "3"},
		"OU": []string{"bbb[a-z]{1,}", "4", "5"},
		"O":  []string{"eee", "ccc[1-9]{1,10}", "6"},
		"S":  []string{"ddd?[[]]", "7", "8"},
	}

	for k, v := range expected {
		received, ok := certSsubject.KVs()[k]
		if !ok {
			t.Fatalf("expected key '%s' in parsed output", k)
		}
		if !compareStringArrays(received, v) {
			t.Fatalf("values for key '%s' invalid, expected: %v, received: %v", k, v, received)
		}
	}
}

func TestPatternWithEscapesSubjectParser(t *testing.T) {
	// not that [[]] makes sense but that is left to the regex compile
	input := "r:/CN=[aaa.*,1,2,3]/OU=[bbb[a-z]{1,}\\{\\,\\},4,5]/O=[eee,ccc[1-9]{1,10},6]/S=[ddd?[[\\]]],7,8]"
	parser := NewSubjectParser(input)
	certSsubject, parseErr := parser.Parse()
	if parseErr != nil {
		t.Fatal("expected string to parse but got error: ", parseErr)
	}

	expected := map[string][]string{
		"CN": []string{"aaa.*", "1", "2", "3"},
		"OU": []string{"bbb[a-z]{1,}\\{\\,\\}", "4", "5"},
		"O":  []string{"eee", "ccc[1-9]{1,10}", "6"},
		"S":  []string{"ddd?[[\\]]]", "7", "8"},
	}

	for k, v := range expected {
		received, ok := certSsubject.KVs()[k]
		if !ok {
			t.Fatalf("expected key '%s' in parsed output", k)
		}
		if !compareStringArrays(received, v) {
			t.Fatalf("values for key '%s' invalid, expected: %v, received: %v", k, v, received)
		}
	}
}

func TestInvalidUnterminatedValuePatternSubjectParser(t *testing.T) {
	input := "r:/CN=[a]/OU=[bbb[1-2].*"
	parser := NewSubjectParser(input)
	_, parseErr := parser.Parse()
	if parseErr == nil {
		t.Fatal("expected string not to parse but it parsed")
	}
	if !strings.HasPrefix(parseErr.Error(), "parser: value insufficient input:") {
		t.Fatalf("expected different error type %v", parseErr)
	}
}

func TestLiteralPatterns(t *testing.T) {
	testcases := map[string][]string{
		`\[`:                    {`[`},
		`\]`:                    {`]`},
		`\,`:                    {`,`},
		`\\`:                    {`\`},
		`{`:                     {`{`}, // there is no reason why you should ever escape {}
		`}`:                     {`}`},
		`value\, with\, commas`: {`value, with, commas`},
		`\[\,},{\\\]`:           {`[,}`, `{\]`},
	}

	for pattern, expected := range testcases {
		input := fmt.Sprintf("s:/CN=[a]/O=[%s]", pattern)
		parser := NewSubjectParser(input)
		subject, err := parser.Parse()
		if err != nil {
			t.Errorf("failed to parse pattern '%s': %v", pattern, err)
		}
		values := subject.KVs()["O"]
		if !compareStringArrays(expected, values) {
			t.Errorf("when parsing pattern '%s', expected %#v got %#v", pattern, expected, values)
		}
	}
}

func TestRegexPatterns(t *testing.T) {
	testcases := map[string]struct {
		matching []string
		failing  []string
	}{
		`^\\\[`:     {matching: []string{"[", "[whatever"}, failing: []string{"", "whatever", "\\", "\\["}},
		`^\[\[\]`:   {matching: []string{"[", "[whatever"}, failing: []string{"", "whatever", "\\"}},
		`^\[\\\[\]`: {matching: []string{"[", "[whatever"}, failing: []string{"", "whatever", "\\"}},
		`\,`:        {matching: []string{",", "a,b,c", "\\,"}, failing: []string{"", "whatever", "\\"}},
		`a{3\,}`:    {matching: []string{"baaaaaaaab", "aaa", "a aa aaaa aa a"}, failing: []string{"", "whatever", "\\"}}, // the rule is: commas should be escaped
		`a\,b$`:     {matching: []string{"a,b", "aaa a,b"}, failing: []string{"", "a,b ", "whatever"}},                    // the rule is: commas should be escaped
	}
	for pattern, tests := range testcases {
		input := fmt.Sprintf("r:/CN=[a]/O=[%s]", pattern)
		parser := NewSubjectParser(input)
		subject, err := parser.Parse()
		if err != nil {
			t.Errorf("failed to parse pattern '%s': %v", pattern, err)
		}
		re := subject.RegexpKVs()["O"][0]
		for _, value := range tests.matching {
			if !re.MatchString(value) {
				t.Errorf("input pattern '%s' does not match '%s' (regex %s)", pattern, value, re.String())
			}
		}
		for _, value := range tests.failing {
			if re.MatchString(value) {
				t.Errorf("input pattern '%s' should not match '%s' (regex %s)", pattern, value, re.String())
			}
		}
	}
}
