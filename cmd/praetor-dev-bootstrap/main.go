package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Niftel/praetor-secrets/devbootstrap"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "development bootstrap generation failed")
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("praetor-dev-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var config devbootstrap.Config
	flags.StringVar(&config.OutputDirectory, "output", "", "new output directory for generated development files")
	flags.StringVar(&config.Namespace, "namespace", "praetor-secrets", "Kubernetes namespace")
	flags.StringVar(&config.TrustDomain, "trust-domain", "praetor.local", "development SPIFFE trust domain")
	flags.StringVar(&config.SchedulerServiceName, "scheduler-service-name", "praetor-scheduler", "scheduler Service DNS name for the claim-server certificate")
	flags.StringVar(&config.SecretsDatabaseURLFile, "secrets-database-url-file", "", "restricted file containing the Secrets Service PostgreSQL URL")
	flags.StringVar(&config.AuditDatabaseURLFile, "audit-database-url-file", "", "restricted file containing the audit sink PostgreSQL URL")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid arguments")
	}
	if err := devbootstrap.Generate(config); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "development bootstrap files generated in", config.OutputDirectory)
	return err
}
