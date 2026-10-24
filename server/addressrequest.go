package main

// An address change asked for on DSM (the upgrade wizard, the DSM page) is a
// one-line file the package writes while the server may be stopped,
// HYPERDROP_ADDRESS_REQUEST: "free <name>" or "domain <fqdn>". The server
// carries it out through its own domain switch, the one PUT /api/domain,
// PUT /api/ddns and DELETE /api/ddns make for the app, and only once the new
// address is proven: an own domain when it and its file origin resolve to
// the public address the names service sees, a free name when it is
// approved and published. Until then the old address keeps serving and the
// request waits, its reason in the status file and the health verdict, so a
// typo never moves links or the certificate to a name that does not
// resolve here. The last writer wins: an address change the app makes
// replaces a waiting request.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

const (
	// addressRetry is how often a waiting request is checked again.
	addressRetry = 10 * time.Minute
	// addressRefresh is how often the status file's approval link is
	// re-read from the free-name state while a request waits; the names
	// service rotates the link every few minutes.
	addressRefresh = time.Minute
	// addressRequestLimit bounds the request file: one short line.
	addressRequestLimit = 512
	// addressApplyLimit bounds one attempt's calls to the resolver and the
	// names service.
	addressApplyLimit = 2 * time.Minute
)

const (
	addressInvalidText   = "The requested address is not valid."
	addressRenameText    = "Change your free name in the HyperDrop app."
	namesUnreachableText = "HyperDrop cannot reach the HyperDrop names service yet."
)

var (
	errAddressInvalid = errors.New("the requested address is not valid")
	// errAddressSuperseded: an address change made in the app since the
	// request was read replaced it, so nothing read before it is acted on.
	errAddressSuperseded = errors.New("an address change made in the app replaced the request")
)

// addressRequest is a parsed request: a free name (the bare name) or an own
// domain (lowercase, without a trailing dot).
type addressRequest struct {
	free bool
	name string
}

// addressRequests carries out the request at path. Every step that changes
// the address, the request file or its status runs under mu and only while
// gen is still the one the request was read under; AppChange holds mu across
// the app's own change and advances gen when that change is accepted, so
// the two never interleave and the later one wins.
type addressRequests struct {
	path string
	dom  *domain.Manager
	up   *ddns.Updater
	st   *statusWriter

	mu  sync.Mutex
	gen uint64
}

// loadedAddressRequest is one reading of the request file: what it asked,
// the generation it was read under and the file it was read from (nil when
// there is none), which is the only file a later step removes.
type loadedAddressRequest struct {
	req  addressRequest
	err  error
	gen  uint64
	info os.FileInfo
}

// AppChange runs change, an address change made in the app, ordered against
// the request's own steps. When change reports it accepted, the waiting
// request is dropped: its file is removed when it is a regular file, its
// status cleared, and a request read before it is never acted on. A nil
// receiver runs change alone.
func (a *addressRequests) AppChange(change func() bool) {
	if a == nil {
		change()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !change() {
		return
	}
	a.gen++
	if fi, err := os.Lstat(a.path); err == nil && fi.Mode().IsRegular() {
		if err := os.Remove(a.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("address request: removing %s: %v", a.path, err)
		} else {
			log.Printf("address request: replaced by an address change in the app")
		}
	}
	a.st.Update(func(s *Status) { s.AddressPending = nil })
}

// act runs fn under mu unless an app change was accepted since gen.
func (a *addressRequests) act(gen uint64, fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gen != gen {
		return errAddressSuperseded
	}
	return fn()
}

// load reads the request file. The file must be a regular file of its own:
// a link, a directory or anything else is errAddressInvalid, and a link's
// target is never opened.
func (a *addressRequests) load() loadedAddressRequest {
	a.mu.Lock()
	l := loadedAddressRequest{gen: a.gen}
	a.mu.Unlock()
	fi, err := os.Lstat(a.path)
	if err != nil {
		l.err = err
		return l
	}
	l.info = fi
	if !fi.Mode().IsRegular() {
		l.err = errAddressInvalid
		return l
	}
	f, err := os.OpenFile(a.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		l.err = errAddressInvalid
		return l
	}
	if err != nil {
		l.err = err
		return l
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
		l.err = err
		return l
	}
	l.info = fi
	if !fi.Mode().IsRegular() {
		l.err = errAddressInvalid
		return l
	}
	b, err := io.ReadAll(io.LimitReader(f, addressRequestLimit+1))
	switch {
	case err != nil:
		l.err = err
	case len(b) > addressRequestLimit:
		l.err = errAddressInvalid
	default:
		l.req, l.err = parseAddressRequest(string(b))
	}
	return l
}

// parseAddressRequest accepts exactly one line, "free <name>" with a name
// the names service issues, or "domain <fqdn>" with a domain outside the
// free-name zone.
func parseAddressRequest(s string) (addressRequest, error) {
	line, rest, _ := strings.Cut(s, "\n")
	if strings.TrimSpace(rest) != "" {
		return addressRequest{}, errAddressInvalid
	}
	kind, value, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok {
		return addressRequest{}, errAddressInvalid
	}
	switch kind {
	case "free":
		if ddns.ValidName(value) {
			return addressRequest{free: true, name: value}, nil
		}
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(value), ".")
		if domain.Valid(d) && d != ddns.Zone && !strings.HasSuffix(d, "."+ddns.Zone) {
			return addressRequest{name: d}, nil
		}
	}
	return addressRequest{}, errAddressInvalid
}

// apply makes one attempt at the request. done is true when nothing is left
// to do: no request, the address switched, or the request refused (its file
// deleted and the reason in the status file's lastError). Otherwise the
// request stays, with its reason in the status file's addressPending, for
// the next attempt; errAddressSuperseded means an app change replaced what
// was read, and the file is read again.
func (a *addressRequests) apply(ctx context.Context) (done bool, err error) {
	return a.applyLoaded(ctx, a.load())
}

func (a *addressRequests) applyLoaded(ctx context.Context, l loadedAddressRequest) (bool, error) {
	switch {
	case errors.Is(l.err, fs.ErrNotExist):
		err := a.act(l.gen, func() error {
			a.st.Update(func(s *Status) { s.AddressPending = nil })
			return nil
		})
		return err == nil, err
	case errors.Is(l.err, errAddressInvalid):
		return a.refuse(l, addressInvalidText)
	case l.err != nil:
		return false, l.err
	}
	ctx, cancel := context.WithTimeout(ctx, addressApplyLimit)
	defer cancel()
	if l.req.free {
		return a.applyFreeName(ctx, l)
	}
	return a.applyDomain(ctx, l)
}

// applyDomain moves to the own domain once it is proven, in the order the
// app's switch takes: adopt the domain (cancelling a free name still
// waiting for approval, as PUT /api/domain does), then, once the domain has
// its certificate, release a free name this server holds (DELETE
// /api/ddns). A request for the current domain is done once no free name is
// held beside it.
func (a *addressRequests) applyDomain(ctx context.Context, l loadedAddressRequest) (bool, error) {
	d := l.req.name
	if a.dom.Current() != d {
		if reason := proveDomain(ctx, a.dom, a.up, d); reason != "" {
			return a.wait(l, AddressPending{Address: d, Reason: reason}, nil)
		}
		err := a.act(l.gen, func() error {
			if err := a.up.ChangeDomain(ctx, func() error { return a.dom.Adopt(d) }); err != nil {
				return err
			}
			log.Printf("address request: switched to %s", d)
			return nil
		})
		if errors.Is(err, errAddressSuperseded) {
			return false, err
		}
		if err != nil {
			return a.wait(l, AddressPending{Address: d, Reason: sentence(d+" could not be set up yet: ", err)}, err)
		}
	}
	held := a.up.Store().Snapshot()
	if held.Name == "" || held.Token == "" || held.Pending {
		return a.finish(l)
	}
	if a.dom.CertStatus()[d].State != "issued" {
		return a.wait(l, AddressPending{Address: d, Reason: d + " has no certificate yet."}, nil)
	}
	err := a.act(l.gen, func() error {
		if err := a.up.Release(ctx); err != nil {
			return err
		}
		log.Printf("address request: disconnected %s", ddns.FQDN(held.Name))
		return nil
	})
	if errors.Is(err, errAddressSuperseded) {
		return false, err
	}
	if err != nil {
		return a.wait(l, AddressPending{Address: d, Reason: sentence(ddns.FQDN(held.Name)+" could not be disconnected yet: ", err)}, err)
	}
	return a.finish(l)
}

// proveDomain answers why d cannot be adopted yet, or "" once d and its file
// origin both resolve to this server's public IPv4: HYPERDROP_IP, else
// (behind NAT, where the server knows no public address of its own) the
// address the names service sees it come from.
func proveDomain(ctx context.Context, dom *domain.Manager, up *ddns.Updater, d string) string {
	ip := dom.IP
	if ip == "" {
		observed, ok := up.ObservedIPv4(ctx)
		if !ok {
			return "HyperDrop could not learn this NAS's public address yet."
		}
		ip = observed
	}
	for _, host := range []string{d, api.ShareHost(d)} {
		if !dom.PointsAt(ctx, host, ip) {
			return host + " does not point at this NAS yet."
		}
	}
	return ""
}

// applyFreeName moves to the free name through account approval, the path
// PUT /api/ddns takes: the current own domain keeps serving until the name
// is approved and published, when the updater adopts it. A different free
// name is changed in the app, never here.
func (a *addressRequests) applyFreeName(ctx context.Context, l loadedAddressRequest) (bool, error) {
	name := l.req.name
	fqdn := ddns.FQDN(name)
	current := a.dom.Current()
	if current == fqdn {
		return a.finish(l)
	}
	if held := a.up.Store().Snapshot(); (held.Name != "" && held.Name != name) || strings.HasSuffix(current, "."+ddns.Zone) {
		return a.refuse(l, addressRenameText)
	}
	serverID := ""
	if a.up.ServerID != nil {
		serverID = a.up.ServerID()
	}
	var chooseErr error
	err := a.act(l.gen, func() error {
		chooseErr = a.up.Choose(ctx, name, serverID)
		return nil
	})
	if err != nil {
		return false, err
	}
	var serviceErr *ddns.ServiceError
	switch {
	case errors.As(chooseErr, &serviceErr) && serviceErr.Code == "account-required":
		return a.wait(l, AddressPending{
			Address:     fqdn,
			Reason:      fqdn + " is waiting for approval in your HyperDrop account.",
			ApprovalURL: liveApprovalURL(a.up),
		}, nil)
	case errors.Is(chooseErr, ddns.ErrNameTaken):
		return a.refuse(l, fqdn+" is taken. Choose another name.")
	case errors.Is(chooseErr, ddns.ErrNameRefused):
		return a.refuse(l, fqdn+" is not a name HyperDrop gives out. Choose another name.")
	case chooseErr != nil:
		reason := sentence(fqdn+" could not be claimed yet: ", chooseErr)
		// A request that never got an answer (no route, a refused or cut
		// connection, a certificate for another name) is told as one
		// sentence; the transport's own error is returned, and watch logs it.
		var unanswered *url.Error
		if errors.As(chooseErr, &unanswered) {
			reason = namesUnreachableText
		}
		return a.wait(l, AddressPending{Address: fqdn, Reason: reason}, chooseErr)
	}
	if a.dom.Current() == fqdn {
		return a.finish(l)
	}
	// A name this server already holds and publishes, beside an own domain,
	// is adopted as it is at boot, under the updater's lock like any domain
	// change.
	if held := a.up.Store().Snapshot(); held.Name == name && !held.Pending && held.LastUpdate != 0 && held.LastError == "" {
		err := a.act(l.gen, func() error {
			if err := a.up.ChangeDomain(ctx, func() error { return a.dom.Adopt(fqdn) }); err != nil {
				return err
			}
			log.Printf("address request: switched to %s", fqdn)
			return nil
		})
		if errors.Is(err, errAddressSuperseded) {
			return false, err
		}
		if err != nil {
			return a.wait(l, AddressPending{Address: fqdn, Reason: sentence(fqdn+" could not be set up yet: ", err)}, err)
		}
		return a.finish(l)
	}
	return a.wait(l, AddressPending{Address: fqdn, Reason: fqdn + " is not published yet."}, nil)
}

// liveApprovalURL is the approval link of the free name waiting for
// approval, or "" when none is waiting or its link has expired.
func liveApprovalURL(up *ddns.Updater) string {
	s := up.Store().Snapshot()
	if !s.Pending || s.Enrollment == nil || s.Enrollment.ExpiresAt <= up.Now().Unix() {
		return ""
	}
	return s.Enrollment.ApprovalURL
}

// syncApproval copies the live approval link into a waiting free-name
// request's status: the updater's own retries renew it between attempts.
func (a *addressRequests) syncApproval() {
	s := a.up.Store().Snapshot()
	if !s.Pending {
		return
	}
	link := liveApprovalURL(a.up)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.Update(func(status *Status) {
		p := status.AddressPending
		if p == nil || p.Address != ddns.FQDN(s.Name) || p.ApprovalURL == link {
			return
		}
		next := *p
		next.ApprovalURL = link
		status.AddressPending = &next
	})
}

// watch attempts the request until it is done or ctx ends: again every
// retry, at once when an app change replaced what it read, and sooner when
// the waiting address has become the current one (the updater adopts an
// approved free name on its own). Every refresh it renews the status file's
// approval link.
func (a *addressRequests) watch(ctx context.Context, retry, refresh time.Duration) {
	for {
		done, err := a.apply(ctx)
		if errors.Is(err, errAddressSuperseded) {
			continue
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("address request: %v", err)
		}
		if done || ctx.Err() != nil {
			return
		}
	wait:
		for next := time.Now().Add(retry); time.Now().Before(next); {
			select {
			case <-ctx.Done():
				return
			case <-time.After(refresh):
			}
			a.syncApproval()
			if p := a.st.Current().AddressPending; p != nil && p.Address == a.dom.Current() {
				break wait
			}
		}
	}
}

// wait records p as the request's reason for waiting, logging it when it
// changes, and answers not done with err.
func (a *addressRequests) wait(l loadedAddressRequest, p AddressPending, err error) (bool, error) {
	if actErr := a.act(l.gen, func() error {
		if cur := a.st.Current().AddressPending; cur == nil || cur.Address != p.Address || cur.Reason != p.Reason {
			log.Printf("address request: waiting to switch to %s: %s", p.Address, p.Reason)
		}
		a.st.Update(func(s *Status) { s.AddressPending = &p })
		return nil
	}); actErr != nil {
		return false, actErr
	}
	return false, err
}

// finish deletes the carried-out request and clears its status.
func (a *addressRequests) finish(l loadedAddressRequest) (bool, error) {
	err := a.act(l.gen, func() error {
		a.st.Update(func(s *Status) { s.AddressPending = nil })
		return a.removeLoaded(l)
	})
	if errors.Is(err, errAddressSuperseded) {
		return false, err
	}
	return true, err
}

// refuse deletes a request the server will not carry out and records why as
// the status file's lastError.
func (a *addressRequests) refuse(l loadedAddressRequest, reason string) (bool, error) {
	err := a.act(l.gen, func() error {
		log.Printf("address request: refused: %s", reason)
		a.st.Update(func(s *Status) {
			s.AddressPending = nil
			s.LastError = reason
			s.At = time.Now().Unix()
		})
		return a.removeLoaded(l)
	})
	if errors.Is(err, errAddressSuperseded) {
		return false, err
	}
	return true, err
}

// removeLoaded removes the request file only while it is still the file l
// was read from (the same inode, unmodified): a request written since is
// the next one to carry out.
func (a *addressRequests) removeLoaded(l loadedAddressRequest) error {
	if l.info == nil {
		return nil
	}
	now, err := os.Lstat(a.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(now, l.info) || !now.ModTime().Equal(l.info.ModTime()) {
		return nil
	}
	if err := os.Remove(a.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// sentence is prefix followed by err's text, ending in one full stop.
func sentence(prefix string, err error) string {
	return fmt.Sprintf("%s%s.", prefix, strings.TrimSuffix(err.Error(), "."))
}
