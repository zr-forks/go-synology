package api

import (
	"fmt"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// dsm62Server emulates a DSM 6.2 NAS: SYNO.API.Auth maxes at v6 and is only
// served on auth.cgi; SYNO.API.Info is served on query.cgi; entry.cgi answers
// error 102 for everything (DSM 6.x does not route these APIs through it).
func dsm62Server(t *testing.T, loginVersions *[]int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/webapi/query.cgi", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"SYNO.API.Auth": map[string]any{
					"path": "auth.cgi", "minVersion": 1, "maxVersion": 6,
				},
				"SYNO.API.Info": map[string]any{
					"path": "query.cgi", "minVersion": 1, "maxVersion": 1,
				},
			},
		})
	})
	mux.HandleFunc("/webapi/auth.cgi", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		v := 0
		_, _ = fmt.Sscanf(r.Form.Get("version"), "%d", &v)
		*loginVersions = append(*loginVersions, v)
		if v > 6 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false, "error": map[string]any{"code": 102},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"sid": "test-sid", "synotoken": "test-token"},
		})
	})
	mux.HandleFunc("/webapi/entry.cgi", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false, "error": map[string]any{"code": 102},
		})
	})
	return httptest.NewServer(mux)
}

func TestLoginDSM62_ClampsVersionAndRoutesToAuthCgi(t *testing.T) {
	var versions []int
	srv := dsm62Server(t, &versions)
	defer srv.Close()

	c, err := New(Options{Host: srv.URL, AllowHTTP: true, VerifyCert: false})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Login(context.Background(), LoginOptions{
		Username: "admin",
		Password: "pw",
	})
	if err != nil {
		t.Fatalf("Login on DSM 6.2 emulator: %v", err)
	}
	if resp.SessionID != "test-sid" {
		t.Fatalf("sid = %q, want test-sid", resp.SessionID)
	}
	if len(versions) == 0 {
		t.Fatal("no login request reached auth.cgi")
	}
	for _, v := range versions {
		if v > 6 {
			t.Fatalf("login requested version %d; DSM 6.2 supports at most 6", v)
		}
	}
}

func TestApiURL_RoutesByDiscoveredPath(t *testing.T) {
	c := &Client{BaseURL: mustParse(t, "https://nas:5001/webapi/entry.cgi")}
	c.apiInfo = map[string]InfoData{
		"SYNO.API.Auth": {Path: "auth.cgi", MaxVersion: 6},
		"SYNO.API.Info": {Path: "query.cgi", MaxVersion: 1},
	}

	if got := c.apiURL("SYNO.API.Auth").Path; got != "/webapi/auth.cgi" {
		t.Errorf("auth path = %q, want /webapi/auth.cgi", got)
	}
	if got := c.apiURL("SYNO.API.Info").Path; got != "/webapi/query.cgi" {
		t.Errorf("info path = %q, want /webapi/query.cgi", got)
	}
	// Unknown APIs fall back to the base URL (DSM 7 behavior).
	if got := c.apiURL("SYNO.Core.System").Path; got != "/webapi/entry.cgi" {
		t.Errorf("fallback path = %q, want /webapi/entry.cgi", got)
	}
	// The shared BaseURL must never be mutated.
	if got := c.BaseURL.Path; got != "/webapi/entry.cgi" {
		t.Errorf("BaseURL mutated: %q", got)
	}
}

func TestDiscoverApiPaths(t *testing.T) {
	var versions []int
	srv := dsm62Server(t, &versions)
	defer srv.Close()

	c, err := New(Options{Host: srv.URL, AllowHTTP: true, VerifyCert: false})
	if err != nil {
		t.Fatal(err)
	}
	cl := c.(*Client)
	if err := cl.DiscoverApiPaths(context.Background()); err != nil {
		t.Fatalf("DiscoverApiPaths: %v", err)
	}
	d, ok := cl.apiInfo["SYNO.API.Auth"]
	if !ok {
		t.Fatal("SYNO.API.Auth missing from discovered catalog")
	}
	if d.MaxVersion != 6 || d.Path != "auth.cgi" {
		t.Fatalf("got %+v, want maxVersion 6 path auth.cgi", d)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
