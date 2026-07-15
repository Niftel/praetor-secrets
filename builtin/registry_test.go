package builtin

import (
	"errors"
	"testing"

	"github.com/Niftel/praetor-secrets/credential"
)

func TestMachineSchemaAndInjector(t *testing.T) {
	inputs := map[string]string{
		"username": "automation", "ssh_private_key": "private-key",
		"become_method": "sudo", "become_password": "become-secret",
	}
	fields, err := (Registry{}).Validate("machine", 1, inputs)
	if err != nil || len(fields) != 2 || fields[0] != "become_password" || fields[1] != "ssh_private_key" {
		t.Fatalf("fields=%v err=%v", fields, err)
	}
	result, err := (Registry{}).Render("machine", 1, inputs)
	if err != nil || result.Environment["ANSIBLE_REMOTE_USER"] != "automation" || len(result.Files) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, file := range result.Files {
		if file.Mode != "0600" {
			t.Fatalf("unsafe file mode: %+v", file)
		}
	}
}

func TestMachineSchemaFailsClosed(t *testing.T) {
	tests := []map[string]string{
		nil,
		{"username": "automation"},
		{"username": "automation", "password": "secret", "unknown": "value"},
		{"username": "", "password": "secret"},
	}
	for _, inputs := range tests {
		if _, err := (Registry{}).Validate("machine", 1, inputs); !errors.Is(err, credential.ErrInvalidInput) {
			t.Fatalf("inputs=%v err=%v", inputs, err)
		}
	}
	if _, err := (Registry{}).Render("unknown", 1, map[string]string{"username": "user", "password": "secret"}); err == nil {
		t.Fatal("unknown credential rendered")
	}
}
