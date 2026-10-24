package linked

import (
	"slices"
	"strings"
)

func listed(roots []Root, name string) bool {
	return slices.ContainsFunc(roots, func(r Root) bool { return r.Name == name })
}

func rootOf(rel string) string {
	name, _, _ := strings.Cut(rel, "/")
	return name
}

// Under reports whether rel is dir itself or a path beneath it.
func Under(rel, dir string) bool {
	return rel == dir || strings.HasPrefix(rel, dir+"/")
}

// GrantFor selects the widest grant covering rel, so overlapping grants do not
// accidentally narrow a file symlink's permitted target. The grant itself must
// still be opened through Roots.Open before resolving anything beneath it.
func GrantFor(isAdmin bool, allow []string, rel string) string {
	if !ValidRel(rel) {
		return ""
	}
	if isAdmin {
		return rootOf(rel)
	}
	grant := ""
	for _, candidate := range allow {
		if ValidRel(candidate) && Under(rel, candidate) && (grant == "" || len(candidate) < len(grant)) {
			grant = candidate
		}
	}
	return grant
}

// Allowed answers whether an account may share from rel: admins may use any
// listed root; a user may use rel when it equals or lies below one of their
// allow entries whose root is listed.
func Allowed(isAdmin bool, allow []string, roots []Root, rel string) bool {
	if !ValidRel(rel) || !listed(roots, rootOf(rel)) {
		return false
	}
	if isAdmin {
		return true
	}
	for _, a := range allow {
		if ValidRel(a) && listed(roots, rootOf(a)) && Under(rel, a) {
			return true
		}
	}
	return false
}

// Granted answers the allowlist rule alone: an admin is granted every
// path, a user the paths at or below a valid entry. Unlike Allowed it does
// not ask whether the server lists the root right now, which is what lets
// an allowlist EDIT decide a revoke without an unmounted volume revoking
// every share on the box.
func Granted(isAdmin bool, allow []string, rel string) bool {
	if isAdmin {
		return true
	}
	for _, a := range allow {
		if ValidRel(a) && Under(rel, a) {
			return true
		}
	}
	return false
}

// VisibleRoots answers the roots an account may browse: every root for an
// admin, else the allow entries that resolve to a listed root.
func VisibleRoots(isAdmin bool, allow []string, roots []Root) []string {
	var out []string
	if isAdmin {
		for _, r := range roots {
			out = append(out, r.Name)
		}
		return out
	}
	for _, a := range allow {
		if ValidRel(a) && listed(roots, rootOf(a)) {
			out = append(out, a)
		}
	}
	return out
}
