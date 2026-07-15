package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

const maxRequestBody = 1 << 20

var (
	errInvalidJSON = errors.New("invalid JSON request")
	errTooLarge    = errors.New("request body too large")
)

func decodeJSON(request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errInvalidJSON
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBody+1))
	if err != nil {
		return errInvalidJSON
	}
	if len(body) == 0 {
		return errInvalidJSON
	}
	if len(body) > maxRequestBody {
		return errTooLarge
	}
	validator := json.NewDecoder(bytes.NewReader(body))
	validator.UseNumber()
	if err := validateJSONValue(validator); err != nil {
		return errInvalidJSON
	}
	if token, err := validator.Token(); err != io.EOF || token != nil {
		return errInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errInvalidJSON
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errInvalidJSON
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidJSON
			}
			if _, duplicate := seen[key]; duplicate {
				return errInvalidJSON
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidJSON
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidJSON
		}
	default:
		return errInvalidJSON
	}
	return nil
}
