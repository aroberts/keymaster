package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) (*httptest.Server, *store) {
	t.Helper()
	st := newStore(4)
	srv, err := newServer(st, testToken)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts, st
}

func testRequest(id string, exp time.Time) []byte {
	// Deliberately includes characters encoding/json would escape, to check
	// the relay hands back the exact bytes it was given.
	return []byte(fmt.Sprintf(`{"exp":%d,"id":"%s","key":"a<b>&c","kind":"approve","v":1}`, exp.Unix(), id))
}

func do(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, ts.URL+path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func create(t *testing.T, ts *httptest.Server, raw []byte) int {
	t.Helper()
	code, _ := do(t, ts, "POST", "/api/requests", testToken, map[string]string{
		"request": base64.RawURLEncoding.EncodeToString(raw),
	})
	return code
}

const id1 = "AAAAAAAAAAAAAAAAAAAAAA"
const id2 = "BBBBBBBBBBBBBBBBBBBBBB"

func TestRoundTripKeepsExactBytes(t *testing.T) {
	ts, _ := newTestServer(t)
	raw := testRequest(id1, time.Now().Add(time.Minute))
	if code := create(t, ts, raw); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	code, got := do(t, ts, "GET", "/api/requests/"+id1, "", nil)
	if code != http.StatusOK || got["status"] != "pending" {
		t.Fatalf("get: %d %v", code, got)
	}
	back, _ := base64.RawURLEncoding.DecodeString(got["request"].(string))
	if !bytes.Equal(back, raw) {
		t.Fatalf("request bytes changed:\n%s\n%s", raw, back)
	}

	done := make(chan map[string]any)
	go func() {
		_, result := do(t, ts, "GET", "/api/requests/"+id1+"/result", testToken, nil)
		done <- result
	}()
	time.Sleep(100 * time.Millisecond)
	if code, _ := do(t, ts, "POST", "/api/requests/"+id1+"/response", "", map[string]string{"signature": "sig"}); code != http.StatusNoContent {
		t.Fatalf("respond: %d", code)
	}
	select {
	case result := <-done:
		if result["status"] != "responded" || result["response"].(map[string]any)["signature"] != "sig" {
			t.Fatalf("result: %v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake")
	}

	// The first answer is final.
	if code, _ := do(t, ts, "POST", "/api/requests/"+id1+"/response", "", map[string]string{"signature": "other"}); code != http.StatusConflict {
		t.Fatalf("second respond: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/requests/"+id1+"/deny", "", nil); code != http.StatusConflict {
		t.Fatalf("deny after respond: %d", code)
	}
}

func TestDeny(t *testing.T) {
	ts, _ := newTestServer(t)
	create(t, ts, testRequest(id1, time.Now().Add(time.Minute)))
	if code, _ := do(t, ts, "POST", "/api/requests/"+id1+"/deny", "", nil); code != http.StatusNoContent {
		t.Fatalf("deny: %d", code)
	}
	_, result := do(t, ts, "GET", "/api/requests/"+id1+"/result", testToken, nil)
	if result["status"] != "denied" {
		t.Fatalf("result: %v", result)
	}
}

func TestTokenRequired(t *testing.T) {
	ts, _ := newTestServer(t)
	body := map[string]string{"request": base64.RawURLEncoding.EncodeToString(testRequest(id1, time.Now().Add(time.Minute)))}
	for _, token := range []string{"", "wrong"} {
		if code, _ := do(t, ts, "POST", "/api/requests", token, body); code != http.StatusUnauthorized {
			t.Fatalf("create with token %q: %d", token, code)
		}
	}
	create(t, ts, testRequest(id1, time.Now().Add(time.Minute)))
	if code, _ := do(t, ts, "GET", "/api/requests/"+id1+"/result", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("result without token: %d", code)
	}
}

func TestCreateValidation(t *testing.T) {
	ts, _ := newTestServer(t)
	now := time.Now()
	cases := map[string][]byte{
		"short id":    testRequest("short", now.Add(time.Minute)),
		"expired":     testRequest(id1, now.Add(-time.Second)),
		"too long":    testRequest(id1, now.Add(time.Hour)),
		"bad version": []byte(fmt.Sprintf(`{"exp":%d,"id":"%s","kind":"approve","v":2}`, now.Add(time.Minute).Unix(), id1)),
		"bad kind":    []byte(fmt.Sprintf(`{"exp":%d,"id":"%s","kind":"other","v":1}`, now.Add(time.Minute).Unix(), id1)),
		"not json":    []byte("nope"),
	}
	for name, raw := range cases {
		if code := create(t, ts, raw); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code := create(t, ts, testRequest(id1, now.Add(time.Minute))); code != http.StatusCreated {
		t.Fatalf("valid: %d", code)
	}
	if code := create(t, ts, testRequest(id1, now.Add(time.Minute))); code != http.StatusConflict {
		t.Fatalf("duplicate: %d", code)
	}
}

func TestExpiry(t *testing.T) {
	ts, st := newTestServer(t)
	create(t, ts, testRequest(id1, time.Now().Add(time.Minute)))
	st.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if code, _ := do(t, ts, "GET", "/api/requests/"+id1, "", nil); code != http.StatusNotFound {
		t.Fatalf("get after expiry: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/requests/"+id1+"/response", "", map[string]string{"a": "b"}); code != http.StatusNotFound {
		t.Fatalf("respond after expiry: %d", code)
	}
	st.sweep()
	if len(st.entries) != 0 {
		t.Fatalf("sweep left %d entries", len(st.entries))
	}
}

func TestCapacity(t *testing.T) {
	ts, _ := newTestServer(t)
	exp := time.Now().Add(time.Minute)
	for i := 0; i < 4; i++ {
		id := strings.Repeat(string(rune('C'+i)), 22)
		if code := create(t, ts, testRequest(id, exp)); code != http.StatusCreated {
			t.Fatalf("create %d: %d", i, code)
		}
	}
	if code := create(t, ts, testRequest(id2, exp)); code != http.StatusServiceUnavailable {
		t.Fatalf("over capacity: %d", code)
	}
}

func TestPageAndHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
	res, err := http.Get(ts.URL + "/r/" + id1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "/static/app.js") {
		t.Fatalf("page: %d", res.StatusCode)
	}
	for _, h := range []string{"Content-Security-Policy", "Referrer-Policy", "Cache-Control"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	for _, path := range []string{"/static/app.js", "/static/style.css", "/healthz"} {
		res, err := http.Get(ts.URL + path)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Errorf("%s: %v %v", path, err, res.Status)
		}
		res.Body.Close()
	}
	res, _ = http.Get(ts.URL + "/r/not-an-id")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("bad id page: %d", res.StatusCode)
	}
	res.Body.Close()
}
