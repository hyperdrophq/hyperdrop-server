package api

import (
	"strings"
	"testing"
)

func TestTheClientHeaderLandsOnTheTokenAndTheNewestIsReported(t *testing.T) {
	h := newTestAPI(t)
	tok := loginWithLabel(t, h, "laptop")
	rec := doReqWithBearerAndHeader(t, h, "GET", "/api/me", tok, "X-HyperDrop-Client", "2.1.0 macos")
	if rec.Code != 200 {
		t.Fatalf("me with header: %d", rec.Code)
	}
	var tokens struct {
		Tokens []struct {
			Label          string `json:"label"`
			ClientVersion  string `json:"clientVersion"`
			ClientPlatform string `json:"clientPlatform"`
		} `json:"tokens"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/me/tokens", tok, ""), &tokens)
	found := false
	for _, row := range tokens.Tokens {
		if row.Label == "laptop" {
			found = true
			if row.ClientVersion != "2.1.0" || row.ClientPlatform != "macos" {
				t.Fatalf("token row = %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("laptop token missing")
	}
	var users struct {
		Users []struct {
			Username     string `json:"username"`
			LatestClient *struct {
				Version  string `json:"version"`
				Platform string `json:"platform"`
			} `json:"latestClient"`
		} `json:"users"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/users", testToken, ""), &users)
	for _, u := range users.Users {
		if u.Username == "admin" && (u.LatestClient == nil || u.LatestClient.Version != "2.1.0") {
			t.Fatalf("admin row = %+v", u)
		}
	}
}

func TestAMalformedClientHeaderIsIgnored(t *testing.T) {
	h := newTestAPI(t)
	tok := loginWithLabel(t, h, "odd")
	for _, bad := range []string{"", "banana", "3.4 macos", "3.4.0", "3.4.0 MacOS!", strings.Repeat("9", 40) + ".0.0 macos"} {
		if rec := doReqWithBearerAndHeader(t, h, "GET", "/api/me", tok, "X-HyperDrop-Client", bad); rec.Code != 200 {
			t.Fatalf("%q failed the request: %d", bad, rec.Code)
		}
	}
	var tokens struct {
		Tokens []struct {
			Label         string `json:"label"`
			ClientVersion string `json:"clientVersion"`
		} `json:"tokens"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/me/tokens", tok, ""), &tokens)
	for _, row := range tokens.Tokens {
		if row.Label == "odd" && row.ClientVersion != "" {
			t.Fatalf("junk stored: %+v", row)
		}
	}
}
