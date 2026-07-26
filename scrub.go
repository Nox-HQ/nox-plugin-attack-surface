package main

import "strings"

// scrubber strips comments — and, in a second projection, string literal
// contents — from source lines. It is stateful because block comments, Go raw
// strings, JS template literals and Python triple-quoted strings all span lines.
//
// Two projections are produced per line:
//
//	code     comments removed, string contents kept — route paths live in strings
//	codeOnly comments removed, string contents blanked — for keyword matchers
//
// Matching keyword patterns against raw lines is what made a doc comment about
// "multipart/alternative" and a `strings.Contains(got, "multipart/mixed")`
// assertion register as file upload handling.
type scrubber struct {
	lang      language
	inComment bool     // inside /* ... */
	inString  bool     // inside a string that spans lines
	delim     strDelim // the string currently open, when inString
}

// strDelim describes a string literal syntax.
type strDelim struct {
	quote     string
	multiline bool
	escapes   bool
}

// scrubLines applies a scrubber across a whole file.
func scrubLines(lang language, lines []string) (code, codeOnly []string) {
	s := &scrubber{lang: lang}
	code = make([]string, len(lines))
	codeOnly = make([]string, len(lines))
	for i, line := range lines {
		code[i], codeOnly[i] = s.scrub(line)
	}
	return code, codeOnly
}

// scrub processes one line, carrying multi-line state forward.
func (s *scrubber) scrub(line string) (code, codeOnly string) {
	rs := []rune(line)
	var withStr, noStr strings.Builder

	for i := 0; i < len(rs); {
		switch {
		case s.inComment:
			i = s.consumeBlockComment(rs, i)
		case s.inString:
			i = s.consumeString(rs, i, s.delim, true, &withStr, &noStr)
		case s.atLineComment(rs, i):
			return withStr.String(), noStr.String()
		case s.atBlockComment(rs, i):
			s.inComment = true
			i += 2
		default:
			if d, ok := openingDelim(s.lang, rs, i); ok {
				i = s.consumeString(rs, i, d, false, &withStr, &noStr)
				continue
			}
			withStr.WriteRune(rs[i])
			noStr.WriteRune(rs[i])
			i++
		}
	}
	return withStr.String(), noStr.String()
}

// consumeBlockComment skips to the end of a /* ... */ comment.
func (s *scrubber) consumeBlockComment(rs []rune, i int) int {
	if s.lang != langPython && i+1 < len(rs) && rs[i] == '*' && rs[i+1] == '/' {
		s.inComment = false
		return i + 2
	}
	return i + 1
}

// atLineComment reports a `//` (Go/JS) or `#` (Python) comment start.
func (s *scrubber) atLineComment(rs []rune, i int) bool {
	if s.lang == langPython {
		return rs[i] == '#'
	}
	return rs[i] == '/' && i+1 < len(rs) && rs[i+1] == '/'
}

// atBlockComment reports a `/*` comment start.
func (s *scrubber) atBlockComment(rs []rune, i int) bool {
	return s.lang != langPython && rs[i] == '/' && i+1 < len(rs) && rs[i+1] == '*'
}

// consumeString copies a string literal. The delimiters are kept in both
// projections so call shapes stay intact; the contents are kept only in the
// code projection. resuming is true when continuing a string opened on an
// earlier line.
func (s *scrubber) consumeString(rs []rune, i int, d strDelim, resuming bool, withStr, noStr *strings.Builder) int {
	q := []rune(d.quote)
	if !resuming {
		withStr.WriteString(d.quote)
		noStr.WriteString(d.quote)
		i += len(q)
	}
	for i < len(rs) {
		if d.escapes && rs[i] == '\\' && i+1 < len(rs) {
			withStr.WriteRune(rs[i])
			withStr.WriteRune(rs[i+1])
			i += 2
			continue
		}
		if hasRunePrefix(rs, i, q) {
			withStr.WriteString(d.quote)
			noStr.WriteString(d.quote)
			s.inString = false
			return i + len(q)
		}
		withStr.WriteRune(rs[i])
		i++
	}
	// Ran off the end of the line.
	s.inString = d.multiline
	s.delim = d
	return len(rs)
}

// openingDelim reports whether a string literal starts at rs[i].
func openingDelim(lang language, rs []rune, i int) (strDelim, bool) {
	switch lang {
	case langPython:
		for _, q := range []string{`"""`, `'''`} {
			if hasRunePrefix(rs, i, []rune(q)) {
				return strDelim{quote: q, multiline: true, escapes: true}, true
			}
		}
		if rs[i] == '"' || rs[i] == '\'' {
			return strDelim{quote: string(rs[i]), escapes: true}, true
		}
	case langGo:
		if rs[i] == '`' {
			return strDelim{quote: "`", multiline: true}, true
		}
		if rs[i] == '"' || rs[i] == '\'' {
			return strDelim{quote: string(rs[i]), escapes: true}, true
		}
	case langJS:
		if rs[i] == '`' {
			return strDelim{quote: "`", multiline: true, escapes: true}, true
		}
		if rs[i] == '"' || rs[i] == '\'' {
			return strDelim{quote: string(rs[i]), escapes: true}, true
		}
	}
	return strDelim{}, false
}

// hasRunePrefix reports whether rs[i:] starts with prefix.
func hasRunePrefix(rs []rune, i int, prefix []rune) bool {
	if i+len(prefix) > len(rs) {
		return false
	}
	for j, r := range prefix {
		if rs[i+j] != r {
			return false
		}
	}
	return true
}
