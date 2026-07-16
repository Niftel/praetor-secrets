package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mutation struct {
	name, file, before, after, testPackage, testPattern string
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	mutations := []mutation{
		{
			name: "executor role authorization", file: "transport/server.go",
			before: `if identity.Role != credential.RoleExecutor {`, after: `if false {`,
			testPackage: "./transport", testPattern: `TestEveryWorkloadRole|TestExecutorResolution`,
		},
		{
			name: "memory backend executor binding", file: "credential/backend_resolution.go",
			before: `if binding.ExecutorIdentity != claim.executorIdentity {`, after: `if false {`,
			testPackage: "./credential", testPattern: `Test.*Executor|TestRunScoped`,
		},
		{
			name: "postgres executor binding", file: "credential/postgres_resolution.go",
			before: `if binding.ExecutorIdentity != claim.executorIdentity {`, after: `if false {`,
			testPackage: "./credential", testPattern: `TestPostgres.*Executor|TestPostgresRunScoped`,
		},
		{
			name: "mandatory client certificate", file: "transport/identity.go",
			before: `ClientAuth:   tls.RequireAndVerifyClientCert,`, after: `ClientAuth:   tls.NoClientCert,`,
			testPackage: "./transport", testPattern: `TestTLSConfig|TestUnsafeServerConfigurations`,
		},
		{
			name: "secret response cache prevention", file: "transport/server.go",
			before: `writer.Header().Set("Cache-Control", "no-store")`, after: `writer.Header().Set("Cache-Control", "public")`,
			testPackage: "./transport", testPattern: `TestExecutorResolutionAndRouteSeparation|TestSchedulerBindingRoutes`,
		},
	}
	for _, mutant := range mutations {
		if err := runMutation(root, mutant); err != nil {
			fatal(err)
		}
		fmt.Printf("PASS: tests killed mutation: %s\n", mutant.name)
	}
}

func runMutation(root string, mutant mutation) error {
	temp, err := os.MkdirTemp("", "praetor-secrets-mutant-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if output, err := exec.Command("cp", "-R", root+string(os.PathSeparator)+".", temp).CombinedOutput(); err != nil {
		return fmt.Errorf("copy repository: %w: %s", err, output)
	}
	path := filepath.Join(temp, mutant.file)
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	source := string(content)
	if strings.Count(source, mutant.before) != 1 {
		return fmt.Errorf("%s: expected exactly one mutation target in %s", mutant.name, mutant.file)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(source, mutant.before, mutant.after, 1)), 0o600); err != nil {
		return err
	}
	command := exec.Command("go", "test", mutant.testPackage, "-run", mutant.testPattern, "-count=1")
	command.Dir = temp
	cache := os.Getenv("GOCACHE")
	if cache == "" {
		cache = filepath.Join(os.TempDir(), "praetor-secrets-mutation-cache")
	}
	command.Env = append(os.Environ(), "GOWORK=off", "GOCACHE="+cache)
	output, testErr := command.CombinedOutput()
	if strings.Contains(string(output), "[no tests to run]") {
		return fmt.Errorf("%s selected no tests", mutant.name)
	}
	if testErr == nil {
		return fmt.Errorf("%s survived; tests unexpectedly passed:\n%s", mutant.name, output)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mutation gate:", err)
	os.Exit(1)
}
