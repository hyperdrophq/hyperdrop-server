package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/webapp"
)

// webConfig is the web client's boot configuration.
type webConfig struct {
	// DevDir (HYPERDROP_WEB_DEV_DIR) is a directory /app serves unsigned in
	// place of any install; "" serves the installed bundle.
	DevDir string
	// Keys are the web release keys a bundle must be signed by:
	// webbundle.TrustedKeys plus any development keys
	// (HYPERDROP_WEB_DEV_KEYS, comma-separated base64 Ed25519 public keys).
	Keys []string
	// Base is the directory of the web release manifest (webapp.ResolveBase
	// over HYPERDROP_WEB_RELEASES and HYPERDROP_SERVER_RELEASES); "" never
	// fetches. BaseErr says why a malformed value turned fetching off.
	Base    string
	BaseErr error
}

// resolveWeb reads the web client's variables through lookup. The two
// development options trust what no release key signed, so either one set
// without allowPrivate (HYPERDROP_ALLOW_PRIVATE=1) is an error, as is a
// development directory that is not an absolute path to a directory or a
// development key that is not a base64 Ed25519 public key. A malformed
// manifest directory is not an error: it turns fetching off, as a malformed
// HYPERDROP_SERVER_RELEASES turns the update check off, and BaseErr says so.
func resolveWeb(lookup func(string) (string, bool), allowPrivate bool) (webConfig, error) {
	get := func(k string) string {
		v, _ := lookup(k)
		return v
	}
	wc := webConfig{Keys: slices.Clone(webbundle.TrustedKeys)}
	dir, keys := get("HYPERDROP_WEB_DEV_DIR"), get("HYPERDROP_WEB_DEV_KEYS")
	if (dir != "" || keys != "") && !allowPrivate {
		return wc, errors.New("HYPERDROP_WEB_DEV_DIR and HYPERDROP_WEB_DEV_KEYS serve a web client no release key signed, " +
			"so they are honoured only on a development server: set HYPERDROP_ALLOW_PRIVATE=1 or unset them")
	}
	if dir != "" {
		if !filepath.IsAbs(dir) {
			return wc, fmt.Errorf("HYPERDROP_WEB_DEV_DIR=%q is not an absolute path", dir)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return wc, fmt.Errorf("HYPERDROP_WEB_DEV_DIR=%q is not a directory", dir)
		}
		wc.DevDir = dir
	}
	if keys != "" {
		for k := range strings.SplitSeq(keys, ",") {
			k = strings.TrimSpace(k)
			if pub, err := base64.StdEncoding.DecodeString(k); err != nil || len(pub) != ed25519.PublicKeySize {
				return wc, fmt.Errorf("HYPERDROP_WEB_DEV_KEYS: %q is not a base64 Ed25519 public key", k)
			}
			wc.Keys = append(wc.Keys, k)
		}
	}
	web, webSet := lookup("HYPERDROP_WEB_RELEASES")
	server, serverSet := lookup("HYPERDROP_SERVER_RELEASES")
	wc.Base, wc.BaseErr = webapp.ResolveBase(web, webSet, server, serverSet)
	if wc.BaseErr != nil {
		wc.Base = ""
	}
	return wc, nil
}
