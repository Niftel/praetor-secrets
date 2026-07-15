package transport

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsDuplicatesUnknownFieldsAndTrailingValues(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}
	tests := []string{
		`{"value":"a","value":"b"}`,
		`{"value":"a","unknown":true}`,
		`{"value":"a"} {"value":"b"}`,
		``,
		`{"value":`,
	}
	for _, body := range tests {
		request := httptest.NewRequest("POST", "/", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := decodeJSON(request, &payload{}); !errors.Is(err, errInvalidJSON) {
			t.Fatalf("body %q: %v", body, err)
		}
	}
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"ok"}`))
	request.Header.Set("Content-Type", "text/plain")
	if err := decodeJSON(request, &payload{}); !errors.Is(err, errInvalidJSON) {
		t.Fatalf("content type: %v", err)
	}
}

func TestDecodeJSONAcceptsNestedUniqueObject(t *testing.T) {
	var payload struct {
		Values []map[string]string `json:"values"`
	}
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"values":[{"one":"1"},{"two":"2"}]}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	if err := decodeJSON(request, &payload); err != nil || len(payload.Values) != 2 {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
}
