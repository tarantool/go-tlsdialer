package gostls

import (
	"fmt"
	"strings"

	"github.com/tarantool/go-gostls"
)

// parseSslCiphers translates an OpenSSL-style cipher-list string into IANA
// suite IDs resolved against the gostls registry, for gostls.Config.CipherSuites.
//
// Grammar: colon-separated words, each an optional prefix + name:
//   - no prefix / "+": add the suite (deduplicated, "+" moves it to the end);
//   - "!" / "-": remove the suite;
//   - "DEFAULT" / "ALL" (and the empty string): all registered suites;
//   - "@" directives are unsupported and an unknown name is an error — a
//     misconfigured list fails fast rather than silently using other suites.
func parseSslCiphers(s string) ([]uint16, error) {
	if s == "" {
		s = "DEFAULT"
	}

	// Insertion-ordered result with a set for O(1) membership.
	var ordered []uint16
	inSet := make(map[uint16]bool)

	add := func(id uint16) {
		if !inSet[id] {
			ordered = append(ordered, id)
			inSet[id] = true
		}
	}

	remove := func(id uint16) {
		if !inSet[id] {
			return
		}
		inSet[id] = false
		// Rebuild ordered without this ID.
		out := ordered[:0]
		for _, v := range ordered {
			if v != id {
				out = append(out, v)
			}
		}
		ordered = out
	}

	// allSuites returns IDs in registration order (stable for repeated calls).
	allSuites := func() []uint16 {
		infos := gostls.AllSuites()
		ids := make([]uint16, len(infos))
		for i, info := range infos {
			ids[i] = info.ID
		}
		return ids
	}

	tokens := strings.Split(s, ":")
	for _, tok := range tokens {
		if tok == "" {
			continue
		}

		exclude := false
		moveToEnd := false
		switch tok[0] {
		case '!', '-':
			exclude = true
			tok = tok[1:]
		case '+':
			moveToEnd = true
			tok = tok[1:]
		}

		if tok == "" {
			continue
		}

		if strings.HasPrefix(tok, "@") {
			return nil, fmt.Errorf("tlsdialer: cipher-list directive %q is not supported", tok)
		}

		if tok == "DEFAULT" || tok == "ALL" {
			if exclude {
				// Removing ALL — clear the result set.
				for _, id := range ordered {
					inSet[id] = false
				}
				ordered = ordered[:0]
			} else {
				for _, id := range allSuites() {
					add(id)
				}
			}
			continue
		}

		id, ok := gostls.LookupSuiteByName(tok)
		if !ok {
			return nil, fmt.Errorf("tlsdialer: unknown cipher suite %q", tok)
		}

		switch {
		case exclude:
			remove(id)
		case moveToEnd:
			// "+NAME" semantics: move to end if already present, otherwise add.
			remove(id)
			add(id)
		default:
			add(id)
		}
	}

	if len(ordered) == 0 {
		return nil, fmt.Errorf("tlsdialer: cipher list %q resolved to empty set", s)
	}

	return ordered, nil
}
