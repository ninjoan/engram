package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudbackup"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// `engram cloud backup` is the operator-only front end of package
// cloudbackup. Import deliberately has no HTTP or dashboard route: archives
// are not authenticated, so only an operator holding ENGRAM_DATABASE_URL may
// restore one.

const (
	cloudBackupExportUsage = "usage: engram cloud backup export --output <path|-> [--force]"
	cloudBackupImportUsage = "       engram cloud backup import --input <path|-> (--dry-run|--apply)"
)

// cloudBackupStore is the database surface of the backup commands, satisfied
// by *cloudstore.CloudStore.
type cloudBackupStore interface {
	cloudbackup.Source
	cloudbackup.Target
	Close() error
}

// openCloudBackupStore is injectable so argument and file handling can be
// tested without Postgres.
var openCloudBackupStore = func(ctx context.Context, cfg cloud.Config) (cloudBackupStore, error) {
	return cloudstore.NewContext(ctx, cfg)
}

func printCloudBackupUsage(w io.Writer) {
	fmt.Fprintln(w, cloudBackupExportUsage)
	fmt.Fprintln(w, cloudBackupImportUsage)
	fmt.Fprintln(w, "export writes a logical Engram Cloud backup (gzip tar, file mode 0600) of the database at ENGRAM_DATABASE_URL; --force replaces an existing file")
	fmt.Fprintln(w, "import restores an archive into the empty database at ENGRAM_DATABASE_URL; --dry-run validates and rolls back")
	fmt.Fprintln(w, "archives hold plaintext memories but no tokens or password hashes; '-' means stdout/stdin")
}

func cloudBackupUsageError(format string, args ...any) {
	printCloudBackupUsage(os.Stderr)
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	exitFunc(1)
}

func cmdCloudBackup() {
	if len(os.Args) < 4 {
		cloudBackupUsageError("a backup subcommand is required")
		return
	}
	switch strings.TrimSpace(os.Args[3]) {
	case "export":
		cmdCloudBackupExport(os.Args[4:])
	case "import":
		cmdCloudBackupImport(os.Args[4:])
	case "--help", "-h", "help":
		printCloudBackupUsage(os.Stdout)
	default:
		cloudBackupUsageError("unknown cloud backup subcommand: %s", os.Args[3])
	}
}

type cloudBackupArgs struct {
	path  string
	flags map[string]bool
	help  bool
}

// parseCloudBackupArgs accepts one required "<pathFlag> <value>" pair and the
// given boolean flags, in any order.
func parseCloudBackupArgs(args []string, pathFlag string, boolFlags ...string) (cloudBackupArgs, error) {
	parsed := cloudBackupArgs{flags: map[string]bool{}}
	havePath := false
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == "--help" || arg == "-h":
			parsed.help = true
			return parsed, nil
		case arg == pathFlag:
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return parsed, fmt.Errorf("%s requires a value", pathFlag)
			}
			if havePath {
				return parsed, fmt.Errorf("%s may be given only once", pathFlag)
			}
			i++
			parsed.path, havePath = strings.TrimSpace(args[i]), true
		case slices.Contains(boolFlags, arg):
			parsed.flags[arg] = true
		default:
			return parsed, fmt.Errorf("unknown option: %s", arg)
		}
	}
	if !havePath {
		return parsed, fmt.Errorf("%s is required", pathFlag)
	}
	return parsed, nil
}

// cloudBackupConfig mirrors the other operator commands: the database comes
// only from ENGRAM_DATABASE_URL, never from a built-in default DSN.
func cloudBackupConfig(command string) (cloud.Config, error) {
	if strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_URL")) == "" {
		return cloud.Config{}, fmt.Errorf("cloud backup %s requires ENGRAM_DATABASE_URL", command)
	}
	return cloud.ConfigFromEnv(), nil
}

func cmdCloudBackupExport(argv []string) {
	args, err := parseCloudBackupArgs(argv, "--output", "--force")
	if err != nil {
		cloudBackupUsageError("%v", err)
		return
	}
	if args.help {
		fmt.Println(cloudBackupExportUsage)
		fmt.Println("Writes the Cloud database at ENGRAM_DATABASE_URL to a gzip tar archive (mode 0600). The archive contains plaintext memories; protect it.")
		return
	}
	cfg, err := cloudBackupConfig("export")
	if err != nil {
		fatal(err)
		return
	}
	toStdout := args.path == "-"
	force := args.flags["--force"]
	if !toStdout {
		if err := checkCloudBackupOutput(args.path, force); err != nil {
			fatal(err)
			return
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cs, err := openCloudBackupStore(ctx, cfg)
	if err != nil {
		fatal(fmt.Errorf("cloud backup export: connect cloud store: %w", err))
		return
	}
	defer cs.Close()

	var (
		summary cloudbackup.Summary
		written int64
		path    = "-"
		report  = os.Stdout
	)
	opts := cloudbackup.ExportOptions{EngramVersion: version}
	if toStdout {
		// stdout carries the archive, so the summary goes to stderr.
		report = os.Stderr
		counter := &cloudBackupByteCounter{w: os.Stdout}
		summary, err = cloudbackup.Export(ctx, cs, counter, opts)
		written = counter.n
	} else {
		path, err = filepath.Abs(args.path)
		if err == nil {
			summary, written, err = exportCloudBackupFile(ctx, cs, path, force, opts)
		}
	}
	if err != nil {
		fatal(fmt.Errorf("cloud backup export: %w", err))
		return
	}

	fmt.Fprintln(report, "backup: exported")
	fmt.Fprintf(report, "path: %s\n", path)
	fmt.Fprintf(report, "bytes: %d\n", written)
	printCloudBackupSummary(report, summary)
	if !toStdout {
		fmt.Fprintln(report, "The archive contains plaintext memories: keep it private and encrypt it before copying it off this host.")
	}
}

// checkCloudBackupOutput refuses an existing output unless force is set and
// never replaces anything that is not a regular file.
func checkCloudBackupOutput(path string, force bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cloud backup export: check output %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cloud backup export: output %s exists and is not a regular file", path)
	}
	if !force {
		return fmt.Errorf("cloud backup export: output %s already exists; use --force to replace it", path)
	}
	return nil
}

// exportCloudBackupFile writes the archive to a 0600 temp file next to path
// and renames it into place only after a complete, synced write, so a failed
// or interrupted export never leaves a partial archive at path.
func exportCloudBackupFile(ctx context.Context, src cloudbackup.Source, path string, force bool, opts cloudbackup.ExportOptions) (cloudbackup.Summary, int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return cloudbackup.Summary{}, 0, fmt.Errorf("create temp archive: %w", err)
	}
	tmpPath := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return cloudbackup.Summary{}, 0, fmt.Errorf("restrict temp archive: %w", err)
	}
	counter := &cloudBackupByteCounter{w: tmp}
	summary, err := cloudbackup.Export(ctx, src, counter, opts)
	if err != nil {
		return cloudbackup.Summary{}, 0, err
	}
	if err := tmp.Sync(); err != nil {
		return cloudbackup.Summary{}, 0, fmt.Errorf("sync archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return cloudbackup.Summary{}, 0, fmt.Errorf("close archive: %w", err)
	}
	// An interrupt that arrived while the archive was being written still
	// cancels the export.
	if err := ctx.Err(); err != nil {
		return cloudbackup.Summary{}, 0, err
	}
	// Re-check right before the rename: the output may have appeared while
	// the export ran.
	if err := checkCloudBackupOutput(path, force); err != nil {
		return cloudbackup.Summary{}, 0, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return cloudbackup.Summary{}, 0, fmt.Errorf("move archive into place: %w", err)
	}
	done = true
	return summary, counter.n, nil
}

type cloudBackupByteCounter struct {
	w io.Writer
	n int64
}

func (c *cloudBackupByteCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func printCloudBackupSummary(w io.Writer, summary cloudbackup.Summary) {
	var rows int64
	for _, table := range summary.Tables {
		rows += table.Rows
	}
	fmt.Fprintf(w, "created_at: %s\n", summary.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(w, "format_version: %d\n", summary.FormatVersion)
	fmt.Fprintf(w, "max_mutation_seq: %d\n", summary.MaxMutationSeq)
	fmt.Fprintf(w, "tables: %d\n", len(summary.Tables))
	fmt.Fprintf(w, "rows: %d\n", rows)
	for _, table := range summary.Tables {
		fmt.Fprintf(w, "  %s: %d\n", table.Name, table.Rows)
	}
}

func cmdCloudBackupImport(argv []string) {
	args, err := parseCloudBackupArgs(argv, "--input", "--dry-run", "--apply")
	if err != nil {
		cloudBackupUsageError("%v", err)
		return
	}
	if args.help {
		fmt.Println(strings.TrimSpace(cloudBackupImportUsage))
		fmt.Println("Restores an archive into the empty Cloud database at ENGRAM_DATABASE_URL. Run it before any admin bootstrap.")
		return
	}
	dryRun, apply := args.flags["--dry-run"], args.flags["--apply"]
	if dryRun == apply {
		cloudBackupUsageError("exactly one of --dry-run or --apply is required")
		return
	}
	cfg, err := cloudBackupConfig("import")
	if err != nil {
		fatal(err)
		return
	}

	input := io.Reader(os.Stdin)
	if args.path != "-" {
		file, err := os.Open(args.path)
		if err != nil {
			fatal(fmt.Errorf("cloud backup import: open input: %w", err))
			return
		}
		defer file.Close()
		input = file
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cs, err := openCloudBackupStore(ctx, cfg)
	if err != nil {
		fatal(fmt.Errorf("cloud backup import: connect cloud store: %w", err))
		return
	}
	defer cs.Close()

	summary, err := cloudbackup.Import(ctx, cs, input, cloudbackup.ImportOptions{DryRun: dryRun})
	if errors.Is(err, cloudstore.ErrBackupTargetNotEmpty) {
		fatal(fmt.Errorf("cloud backup import: target database is not empty (%v); nothing was changed. Import only restores into a fresh Cloud database, before any admin bootstrap", err))
		return
	}
	if err != nil {
		fatal(fmt.Errorf("cloud backup import: %w; nothing was changed", err))
		return
	}

	if dryRun {
		fmt.Println("backup: dry run passed (nothing was written)")
	} else {
		fmt.Println("backup: imported")
	}
	printCloudBackupSummary(os.Stdout, summary)
	if dryRun {
		return
	}
	fmt.Println("Next steps:")
	fmt.Println("  - Managed tokens are never part of a backup: re-issue a token for every managed principal and have each client re-run its token setup.")
	fmt.Println("    With exactly one enabled managed admin, `engram cloud bootstrap recover-token` issues that admin's first token (requires ENGRAM_CLOUD_TOKEN_PEPPER).")
	fmt.Println("  - Legacy cloud_users were restored without password hashes and cannot log in.")
	fmt.Println("  - Restored managed admins replace admin bootstrap: run `engram cloud bootstrap admin` only if the backup held no managed admin.")
}
