package web

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"netexplorer/internal/discovery/network"
	"testing"
)

func TestAPI(t *testing.T) {
	handler := Router("test", func() ([]network.Interface, error) { return []network.Interface{{Name: "fixture"}}, nil })
	for _, path := range []string{"/api/health", "/api/interfaces"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 || !json.Valid(response.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
	}
	handler = Router("test", func() ([]network.Interface, error) { return nil, errors.New("private details") })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/interfaces", nil))
	if response.Code != 500 {
		t.Fatal(response.Code)
	}
}
