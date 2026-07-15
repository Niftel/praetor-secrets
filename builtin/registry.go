// Package builtin contains the initial reviewed credential schemas and
// injectors shipped with the standalone service.
package builtin

import (
	"errors"
	"sort"

	"github.com/Niftel/praetor-secrets/credential"
)

type Registry struct{}

func (Registry) Validate(credentialType string, schemaVersion uint32, inputs map[string]string) ([]string, error) {
	if credentialType != "machine" || schemaVersion != 1 {
		return nil, credential.ErrInvalidInput
	}
	allowed := map[string]bool{
		"username": false, "password": true, "ssh_private_key": true,
		"become_method": false, "become_password": true,
	}
	for name, value := range inputs {
		if _, ok := allowed[name]; !ok || value == "" {
			return nil, credential.ErrInvalidInput
		}
	}
	if inputs["username"] == "" || (inputs["password"] == "" && inputs["ssh_private_key"] == "") {
		return nil, credential.ErrInvalidInput
	}
	fields := make([]string, 0, 3)
	for name, secret := range allowed {
		if secret && inputs[name] != "" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields, nil
}

func (Registry) Render(credentialType string, schemaVersion uint32, inputs map[string]string) (credential.InjectorResult, error) {
	if _, err := (Registry{}).Validate(credentialType, schemaVersion, inputs); err != nil {
		return credential.InjectorResult{}, errors.New("credential rendering failed")
	}
	result := credential.InjectorResult{Environment: map[string]string{
		"ANSIBLE_REMOTE_USER": inputs["username"],
	}}
	if method := inputs["become_method"]; method != "" {
		result.Environment["ANSIBLE_BECOME_METHOD"] = method
	}
	if value := inputs["ssh_private_key"]; value != "" {
		result.Files = append(result.Files, credential.ResolvedFile{Name: "ANSIBLE_PRIVATE_KEY_FILE", Mode: "0600", Content: value})
	}
	if value := inputs["password"]; value != "" {
		result.Files = append(result.Files, credential.ResolvedFile{Name: "ANSIBLE_PASSWORD_FILE", Mode: "0600", Content: value})
	}
	if value := inputs["become_password"]; value != "" {
		result.Files = append(result.Files, credential.ResolvedFile{Name: "ANSIBLE_BECOME_PASSWORD_FILE", Mode: "0600", Content: value})
	}
	return result, nil
}
