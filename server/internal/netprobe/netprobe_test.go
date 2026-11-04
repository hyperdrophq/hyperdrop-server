package netprobe

import "testing"

func TestVerdict(t *testing.T) {
	cases := []struct{ router, public, want string }{
		{"203.0.113.7", "203.0.113.7", "direct"},
		{"100.64.1.2", "203.0.113.7", "cgnat"},
		{"100.64.1.2", "", "cgnat"}, // the router address alone is conclusive
		{"192.168.1.2", "203.0.113.7", "layered"},
		{"10.0.0.2", "203.0.113.7", "layered"},
		{"198.51.100.9", "203.0.113.7", "layered"}, // public but not ours: double NAT
		{"", "203.0.113.7", "unknown"},
		{"not-an-ip", "203.0.113.7", "unknown"},
		{"203.0.113.7", "", "unknown"},
	}
	for _, c := range cases {
		if got := Verdict(c.router, c.public); got != c.want {
			t.Errorf("Verdict(%q, %q) = %q, want %q", c.router, c.public, got, c.want)
		}
	}
}

func TestPortVerdict(t *testing.T) {
	cases := []struct{ answer, id, own, want string }{
		{"hyperdrop", "me", "me", "ok"},
		{"hyperdrop", "old-nas", "me", "taken"}, // a previous install still holds the forward
		{"other", "", "me", "taken"},
		{"none", "", "me", "closed"},
		{"unknown", "", "me", "unknown"},
		{"", "", "me", "unknown"},
		{"something-new", "", "me", "unknown"}, // a newer registry's word is no claim
	}
	for _, c := range cases {
		if got := PortVerdict(c.answer, c.id, c.own); got != c.want {
			t.Errorf("PortVerdict(%q,%q,%q) = %q, want %q", c.answer, c.id, c.own, got, c.want)
		}
	}
}
