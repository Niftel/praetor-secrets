package transport

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func FuzzStrictJSONDecoder(f *testing.F) {
	f.Add(`{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z"}`)
	f.Add(`{"attempt_id":"a","attempt_id":"b"}`)
	f.Add(`{"unknown":true}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > maxRequestBody*2 {
			return
		}
		request := &http.Request{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		var decoded resolveBody
		_ = decodeJSON(request, &decoded)
	})
}
