package securitygate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSecurityArchitectureBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	allowedEnvelope := map[string]bool{"credential": true, "masterkey": true}
	allowedStorage := map[string]bool{"app": true, "audit": true, "auditsink": true, "credential": true}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		top := strings.Split(filepath.ToSlash(relative), "/")[0]
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imported := range file.Imports {
			name, _ := strconv.Unquote(imported.Path.Value)
			switch {
			case name == "log" || name == "log/slog":
				if top != "cmd" {
					t.Errorf("%s: logging is restricted to command boundaries", relative)
				}
			case name == "github.com/Niftel/praetor-secrets/envelope":
				if !allowedEnvelope[top] {
					t.Errorf("%s: only credential and masterkey may import envelope", relative)
				}
			case name == "database/sql" || strings.HasPrefix(name, "github.com/jackc/pgx/"):
				if !allowedStorage[top] {
					t.Errorf("%s: direct database access is outside an approved storage boundary", relative)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretBearingJSONFieldsStayOnApprovedTypes(t *testing.T) {
	root := repositoryRoot(t)
	approved := map[string]map[string]bool{
		"envelope.Record":                 {"ciphertext": true, "wrapped_data_key": true},
		"credential.ResolvedFile":         {"content": true},
		"transport.createCredentialBody":  {"inputs": true},
		"transport.replaceCredentialBody": {"inputs": true},
	}
	found := map[string]map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		for _, declaration := range file.Decls {
			gen, ok := declaration.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				owner := file.Name.Name + "." + typeSpec.Name.Name
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					tag, _ := strconv.Unquote(field.Tag.Value)
					jsonName := jsonTagName(tag)
					if isSecretJSONName(jsonName) {
						if !approved[owner][jsonName] {
							t.Errorf("%s.%s has unapproved secret-bearing JSON field %q", owner, fieldName(field), jsonName)
						}
						if found[owner] == nil {
							found[owner] = map[string]bool{}
						}
						found[owner][jsonName] = true
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for owner, fields := range approved {
		for field := range fields {
			if !found[owner][field] {
				t.Errorf("approved secret boundary %s.%s disappeared; review the gate", owner, field)
			}
		}
	}
}

func jsonTagName(tag string) string {
	const prefix = `json:"`
	start := strings.Index(tag, prefix)
	if start < 0 {
		return ""
	}
	value := tag[start+len(prefix):]
	end := strings.IndexByte(value, '"')
	if end < 0 {
		return ""
	}
	return strings.Split(value[:end], ",")[0]
}

func isSecretJSONName(name string) bool {
	switch name {
	case "inputs", "content", "ciphertext", "wrapped_data_key", "password", "private_key", "secret":
		return true
	default:
		return false
	}
}

func fieldName(field *ast.Field) string {
	if len(field.Names) == 0 {
		return "<embedded>"
	}
	return field.Names[0].Name
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(directory)
}
