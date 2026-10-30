package api

import (
	"log"
	"strconv"
	"time"
)

// requireTwoFactorKey is the server setting behind "require two-factor for
// every account": the UnixNano of the second the switch was turned on,
// absent while it is off. A token signed in at or after that second
// (Token.CreatedAt, stored to the second) owes its account a second factor
// (twoFactorRestricted); one signed in earlier keeps working. A sign-in in
// the switch's own second therefore counts as after it.
const requireTwoFactorKey = "require_two_factor"

// requireTwoFactorSince answers whether the switch is on and the second it
// was turned on. A setting that cannot be read, or holds no time, reads as
// on since the zero time, so every sign-in of an account without a second
// factor is restricted until it can be read again or holds a time; the log
// says so once for each.
func (h *handler) requireTwoFactorSince() (since time.Time, on bool) {
	v, ok, err := h.db.Setting(requireTwoFactorKey)
	if err != nil {
		if !h.requireTwoFactorUnread.Swap(true) {
			log.Printf("two-factor: reading the require switch: %v; every account without a second factor owes one until it can be read", err)
		}
		return time.Time{}, true
	}
	if h.requireTwoFactorUnread.Swap(false) {
		log.Printf("two-factor: the require switch can be read again")
	}
	if !ok {
		h.requireTwoFactorUnparsed.Store(false)
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		if !h.requireTwoFactorUnparsed.Swap(true) {
			log.Printf("two-factor: the require switch holds no time (%q); every account without a second factor owes one until it is turned off or on again", v)
		}
		return time.Time{}, true
	}
	h.requireTwoFactorUnparsed.Store(false)
	return time.Unix(0, ns).UTC(), true
}

// setRequireTwoFactor turns the switch on, recording now's second, or off,
// deleting the setting. Turning it on while it is on keeps the second it
// was first turned on, so the tokens signed in since stay restricted and
// the earlier ones stay unrestricted.
func (h *handler) setRequireTwoFactor(on bool, now time.Time) error {
	if !on {
		return h.db.DeleteSetting(requireTwoFactorKey)
	}
	v, ok, err := h.db.Setting(requireTwoFactorKey)
	if err != nil {
		return err
	}
	if ok {
		if _, err := strconv.ParseInt(v, 10, 64); err == nil {
			return nil
		}
	}
	return h.db.SetSetting(requireTwoFactorKey, strconv.FormatInt(now.UTC().Truncate(time.Second).UnixNano(), 10))
}
