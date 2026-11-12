package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// registeredRoute is one mux registration.
type registeredRoute struct {
	Method  string
	Pattern string
}

// muxRegistration is one Handle or HandleFunc call in api.go, with the gate
// its handler is wrapped in when that handler is a call on h (h.auth, h.read).
type muxRegistration struct {
	registeredRoute
	Gate string
}

// muxRegistrations reads every route registration of this package from its
// syntax tree. http.ServeMux exposes no way to enumerate what was
// registered, and the coverage rules (the origin split, cookie routes,
// inbox containment, the second-factor allow-list, the public docs) are
// only as complete as this list, so it refuses any registration it could
// not read in full: a Handle or HandleFunc call in a file other than
// api.go, or one whose pattern is not a string literal naming a method and
// a path. A route registered through a variable or a helper therefore fails
// here instead of falling outside every rule.
func muxRegistrations(t *testing.T) []muxRegistration {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var out []muxRegistration
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			pos := fset.Position(call.Pos())
			if name != "api.go" {
				t.Errorf("%s: a %s call outside api.go; every route is registered in api.go, where the coverage rules read it", pos, sel.Sel.Name)
				return true
			}
			if len(call.Args) != 2 {
				t.Errorf("%s: a %s call with %d arguments", pos, sel.Sel.Name, len(call.Args))
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: the route pattern is not a string literal, so no coverage rule can read it", pos)
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("%s: unquote %s: %v", pos, lit.Value, err)
				return true
			}
			method, path, ok := strings.Cut(pattern, " ")
			if !ok || method == "" || method != strings.ToUpper(method) || !strings.HasPrefix(path, "/") {
				t.Errorf("%s: pattern %q does not name a method and a path", pos, pattern)
				return true
			}
			reg := muxRegistration{registeredRoute: registeredRoute{Method: method, Pattern: path}}
			if gate, ok := call.Args[1].(*ast.CallExpr); ok {
				if gs, ok := gate.Fun.(*ast.SelectorExpr); ok {
					if recv, ok := gs.X.(*ast.Ident); ok && recv.Name == "h" {
						reg.Gate = gs.Sel.Name
					}
				}
			}
			out = append(out, reg)
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("found no mux registrations in api.go")
	}
	return out
}

func registeredRoutes(t *testing.T) []registeredRoute {
	t.Helper()
	regs := muxRegistrations(t)
	out := make([]registeredRoute, 0, len(regs))
	for _, r := range regs {
		out = append(out, r.registeredRoute)
	}
	return out
}

// authGates are the gates built on h.auth, the routes the second-factor rule
// covers.
var authGates = []string{"auth", "read", "admin", "adminRead", "webAuth"}

// authenticatedRoutes is every route in api.go behind h.auth or a gate built
// on it.
func authenticatedRoutes(t *testing.T) []registeredRoute {
	t.Helper()
	var out []registeredRoute
	for _, r := range muxRegistrations(t) {
		if slices.Contains(authGates, r.Gate) {
			out = append(out, r.registeredRoute)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no authenticated routes in api.go")
	}
	return out
}

func TestEveryRouteRegistrationIsReadable(t *testing.T) {
	muxRegistrations(t)
}
