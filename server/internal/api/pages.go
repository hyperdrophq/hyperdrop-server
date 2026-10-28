package api

import (
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
)

// The public pages: HTML in .html files rather than in Go raw string literals,
// because a Go raw string cannot hold a backtick and a page's script may use
// template literals.
//
// Each page is one self-contained document with inline CSS, inline vanilla
// JS and inline SVG, requesting nothing from a THIRD PARTY: a public page
// that fetched a stylesheet would tell somebody else who opened which link.
// The one request a page does make is for this server's own tab icon, at a
// path carrying no share id, so it reaches only the operator who served the
// page already.
//
//go:embed pages/*.html
var pageFS embed.FS

// brandPartials are the pieces every page draws from: the light palette and
// the wordmark SVGs.
//
// Invoked as templates, not spliced as text. html/template escapes ACTIONS,
// not static text, so a define holding plain CSS renders byte-identically
// inside a <style> block; a misspelled {{template}} is an error on the first
// Execute, where a misspelled text marker would ship a literal comment and a
// page whose every var(--ink) resolves to nothing.
//
// Only the LIGHT palette is shared. The dark blocks genuinely differ per page
// (paper #161618 / #1C1C1E / #131315, ink #F2F2F7 / #F5F5F7); unifying them
// changes what already-published pages look like, which is a product decision
// rather than a refactor, so each page states its own and the difference is
// visible where it is chosen.
//
// Every page reaches "mark" through this one definition, so every page draws
// the same icon: website/icon.svg's tile and glyph.
const brandPartials = `
{{define "brandTokens"}}--ink: #1D1D1F; --paper: #FFFFFF; --muted: #6E6E73; --hairline: #E5E5EA;
  --indigo: #6B52F2; --sky: #1CADF8;{{end}}
{{define "favicon"}}<link rel="icon" href="/favicon.ico" sizes="32x32"><link rel="icon" href="/icon.svg" type="image/svg+xml">{{end}}
{{define "mark"}}<svg class="mark" width="{{.}}" height="{{.}}" viewBox="0 0 640 640" aria-hidden="true"><rect width="640" height="640" fill="#712dff"/><path fill="#fff" d="M416.82 187.3L510.1 187.3L566.7 274.18L416.5 452.7L291.87 452.7L318.01 421.52L401.98 421.52L527.95 271.81L493.2 218.48L431.4 218.48L364.46 298.68L254.51 298.68L280.93 267.5L349.87 267.5Z"/><path fill="#fff" d="M223.5 187.3L348.13 187.3L322.06 218.48L238.02 218.48L112.05 368.19L146.8 421.52L208.6 421.52L275.54 341.32L385.38 341.32L359.11 372.5L290.13 372.5L223.18 452.7L129.9 452.7L73.3 365.82Z"/></svg>{{end}}
{{define "foldermark"}}<svg class="mark" width="{{.}}" height="{{.}}" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="gdir{{.}}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6B52F2"/><stop offset="1" stop-color="#1CADF8"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#gdir{{.}})"/><path d="M12 20 a3 3 0 0 1 3 -3 h11 l5 5 h18 a3 3 0 0 1 3 3 v19 a3 3 0 0 1 -3 3 H15 a3 3 0 0 1 -3 -3 Z" fill="#fff"/></svg>{{end}}
{{define "filemark"}}<svg class="mark" width="{{.}}" height="{{.}}" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="gdoc{{.}}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6B52F2"/><stop offset="1" stop-color="#1CADF8"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#gdoc{{.}})"/><path d="M22 14 h13 l9 9 v25 a3 3 0 0 1 -3 3 H22 a3 3 0 0 1 -3 -3 V17 a3 3 0 0 1 3 -3 Z" fill="#fff"/><path d="M35 14 l9 9 h-9 Z" fill="#6B52F2" fill-opacity=".45"/></svg>{{end}}`

// page builds one public page's template: the shared partials, then the page.
//
// The template keeps `name` rather than the file name, so every Execute call
// site reads as it did.
func page(name, file string) *template.Template {
	src, err := pageFS.ReadFile("pages/" + file)
	if err != nil {
		// A missing page is a build-time mistake: the file is embedded, so it
		// either shipped in the binary or the binary is wrong.
		panic("page " + file + ": " + err.Error())
	}
	t := template.Must(template.New(name).Parse(brandPartials))
	return template.Must(t.Parse(string(src)))
}

// pageFraming says whether a page of ours may be shown inside another site's
// frame.
type pageFraming bool

const (
	// framable is every page an owner may put in an <iframe> on their own
	// site: a listing, a gallery, a Receive Inbox, and the pages those reach.
	framable pageFraming = true
	// unframed is a page worth clickjacking: the password form, which takes
	// a password, and the join page, which shows a sign-in. Each refuses
	// every frame.
	unframed pageFraming = false
)

// pageCSP is the Content-Security-Policy of every page this server renders.
//
// It restricts what a page needs no part of, so it changes nothing a page
// does: no <base> (base-uri), no plugin content (object-src), and forms
// that post only to this server. The one form, the password form, renders
// on either origin and always posts to the app origin (passwordFormAction).
// The unlock's 303 and the redirects after it can end on files.<domain>: a
// single-file share's /share/{id} goes on to its /view, which originRouter's
// 308 carries there. Chrome checks form-action on every hop of that chain
// and refuses the submit when one leaves the list, so both origins are
// named whichever one the form rendered on. Without the split there is one
// origin, 'self'.
//
// Script and style sources are not restricted: every page runs inline
// script and style.
func pageCSP(o Origins, f pageFraming) string {
	csp := "base-uri 'none'; object-src 'none'; form-action 'self'"
	if o.Split() {
		csp += " https://" + o.App + " https://" + o.File
	}
	if f == unframed {
		csp += "; frame-ancestors 'none'"
	}
	return csp
}

// renderPage writes one page response: the HTML content type, noindex (no
// page this server renders is meant for a search index), the page policy
// (pageCSP; an unframed page also sends X-Frame-Options for a browser that
// predates frame-ancestors), no-store when the page reports a state that
// changes under it, the status (0 for 200), and tmpl executed over data; a
// nil tmpl writes the headers alone, which is what a HEAD gets. An Execute
// failure is logged under the template's name.
//
// The policy replaces any Content-Security-Policy already on the response:
// a page of ours rendered where a file would have been served (the password
// form or the 404 in place of a /view) is our page, not the upload.
func (h *handler) renderPage(w http.ResponseWriter, f pageFraming, status int, noStore bool, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	noIndex(w)
	w.Header().Set("Content-Security-Policy", pageCSP(h.origins(), f))
	if f == unframed {
		w.Header().Set("X-Frame-Options", "DENY")
	}
	if noStore {
		w.Header().Set("Cache-Control", "no-store")
	}
	if status != 0 {
		w.WriteHeader(status)
	}
	if tmpl == nil {
		return
	}
	if err := tmpl.Execute(w, data); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		log.Printf("%s page: %v", tmpl.Name(), err)
	}
}
