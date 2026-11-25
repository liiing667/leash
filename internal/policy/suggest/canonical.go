package suggest

import (
	"sort"
	"strings"
)

// CanonicalCedar returns a whitespace- and comment-normalized Cedar
// representation. Set literals are rendered in a stable order so two policies
// that differ only by serialized object order compare equal.
func CanonicalCedar(input string) string {
	statements := CanonicalCedarStatements(input)
	seen := make(map[string]struct{}, len(statements))
	unique := make([]string, 0, len(statements))
	for _, statement := range statements {
		if _, ok := seen[statement]; ok {
			continue
		}
		seen[statement] = struct{}{}
		unique = append(unique, statement)
	}
	return strings.Join(unique, "\n")
}

// CanonicalCedarIdentity returns a stable identity for a Cedar policy set.
// Cedars policies form an unordered set, so statement order is ignored as well.
func CanonicalCedarIdentity(input string) string {
	statements := CanonicalCedarStatements(input)
	statements = uniqueSorted(statements)
	return strings.Join(statements, "\n---\n")
}

// CanonicalCedarStatements splits input into canonical, semicolon-terminated
// policy statements. Comments are discarded because they are not part of the
// policy's semantics.
func CanonicalCedarStatements(input string) []string {
	raw := splitCedarStatements(stripCedarComments(input))
	out := make([]string, 0, len(raw))
	for _, statement := range raw {
		statement = canonicalizeCedarStatement(statement)
		if statement != "" {
			out = append(out, statement)
		}
	}
	return out
}

func stripCedarComments(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	inString := false
	escaped := false

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inString {
			b.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			b.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(input) && input[i+1] == '/' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
			continue
		}
		if c == '/' && i+1 < len(input) && input[i+1] == '*' {
			i += 2
			for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
				i++
			}
			if i+1 < len(input) {
				i++
			}
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func splitCedarStatements(input string) []string {
	var statements []string
	var current strings.Builder
	inString := false
	escaped := false
	depth := 0

	for i := 0; i < len(input); i++ {
		c := input[i]
		current.WriteByte(c)

		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}

		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				if statement := strings.TrimSpace(current.String()); statement != "" {
					statements = append(statements, statement)
				}
				current.Reset()
			}
		}
	}
	if statement := strings.TrimSpace(current.String()); statement != "" {
		statements = append(statements, statement)
	}
	return statements
}

func canonicalizeCedarStatement(input string) string {
	statement := normalizeCedarWhitespace(input)
	statement = canonicalizeCedarSets(statement)
	statement = normalizeCedarWhitespace(statement)
	statement = strings.TrimSpace(strings.TrimSuffix(statement, ";"))
	if statement == "" {
		return ""
	}
	return statement + ";"
}

// normalizeCedarWhitespace removes formatting differences outside string
// literals. Whitespace next to punctuation and operators is not significant in
// Cedar, so it is removed to make identities stable across pretty-printers.
func normalizeCedarWhitespace(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	inString := false
	escaped := false
	pendingSpace := false
	lastWord := false
	isPunctuation := func(c byte) bool {
		switch c {
		case '(', ')', '[', ']', '{', '}', ',', ';', ':', '=', '!', '<', '>', '&', '|', '+', '-', '*', '/', '?':
			return true
		default:
			return false
		}
	}

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inString {
			if pendingSpace && lastWord {
				b.WriteByte(' ')
			}
			pendingSpace = false
			b.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
				lastWord = true
			}
			continue
		}
		if c == '"' {
			if pendingSpace && lastWord {
				b.WriteByte(' ')
			}
			pendingSpace = false
			inString = true
			b.WriteByte(c)
			lastWord = false
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if b.Len() > 0 {
				pendingSpace = true
			}
			continue
		}
		if isPunctuation(c) {
			pendingSpace = false
			b.WriteByte(c)
			lastWord = false
			continue
		}
		if pendingSpace && lastWord {
			b.WriteByte(' ')
		}
		pendingSpace = false
		b.WriteByte(c)
		lastWord = true
	}
	return strings.TrimSpace(b.String())
}

// canonicalizeCedarSets sorts and deduplicates square-bracket set literals.
// Cedar sets are unordered, so this removes object-order differences from
// policy identity.
func canonicalizeCedarSets(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	inString := false
	escaped := false

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inString {
			b.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			b.WriteByte(c)
			continue
		}
		if c != '[' {
			b.WriteByte(c)
			continue
		}

		close := matchingSquareBracket(input, i)
		if close < 0 {
			b.WriteString(input[i:])
			break
		}

		parts := splitTopLevelCommas(input[i+1 : close])
		canonical := make([]string, 0, len(parts))
		for _, part := range parts {
			part = canonicalizeCedarSets(part)
			part = normalizeCedarWhitespace(part)
			if part != "" {
				canonical = append(canonical, part)
			}
		}
		canonical = uniqueSorted(canonical)

		b.WriteByte('[')
		b.WriteString(strings.Join(canonical, ","))
		b.WriteByte(']')
		i = close
	}
	return b.String()
}

func matchingSquareBracket(input string, open int) int {
	depth := 0
	inString := false
	escaped := false
	for i := open; i < len(input); i++ {
		c := input[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopLevelCommas(input string) []string {
	var parts []string
	var current strings.Builder
	depth := 0
	inString := false
	escaped := false

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inString {
			current.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			current.WriteByte(c)
		case '[', '(', '{':
			depth++
			current.WriteByte(c)
		case ']', ')', '}':
			if depth > 0 {
				depth--
			}
			current.WriteByte(c)
		case ',':
			if depth == 0 {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		default:
			current.WriteByte(c)
		}
	}
	if strings.TrimSpace(current.String()) != "" || len(parts) > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
