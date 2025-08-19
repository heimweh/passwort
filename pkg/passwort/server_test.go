package passwort

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_Handlers(t *testing.T) {
	s := NewServer(NewInmemoryStore())
	h := s.Handler()

	ts := httptest.NewServer(h)
	defer ts.Close()

	client := &http.Client{}

	tests := []struct {
		name       string
		method     string
		url        string
		wantStatus int
		wantBody   string
	}{
		{"set", http.MethodPost, "/set?key=foo&value=bar", http.StatusOK, ""},
		{"get", http.MethodGet, "/get?key=foo", http.StatusOK, "bar"},
		{"list", http.MethodGet, "/list", http.StatusOK, ""},
		{"delete", http.MethodPost, "/delete?key=foo", http.StatusOK, ""},
		{"get after delete", http.MethodGet, "/get?key=foo", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var err error
			url := ts.URL + tt.url
			if tt.method == http.MethodPost {
				resp, err = client.Post(url, "", nil)
			} else {
				resp, err = client.Get(url)
			}
			if err != nil {
				t.Fatalf("%s request failed: %v", tt.name, err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("%s status = %d, want %d", tt.name, resp.StatusCode, tt.wantStatus)
			}
			if tt.wantBody != "" {
				body, _ := ioutil.ReadAll(resp.Body)
				if string(body) != tt.wantBody {
					t.Errorf("%s body = %q, want %q", tt.name, string(body), tt.wantBody)
				}
			}
			resp.Body.Close()
		})
	}
}
