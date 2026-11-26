// Package cloudbackup writes and restores provider-neutral Engram Cloud
// backup archives: one gzip-compressed tar stream holding one JSONL member per
// table followed by a checksummed backup.json manifest.
package cloudbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const (
	FormatName    = "engram-cloud-backup"
	FormatVersion = 1
	ManifestName  = "backup.json"

	tableMemberPrefix = "tables/"
	tableMemberSuffix = ".jsonl"
	mutationSeqKey    = "cloud_mutations.seq"

	maxManifestBytes = 16 << 20
	insertBatchRows  = 500
	insertBatchBytes = 8 << 20
)

var (
	ErrUnsupportedFormat = errors.New("cloudbackup: unsupported backup format")
	ErrChecksumMismatch  = errors.New("cloudbackup: archive member checksum mismatch")
	ErrInvalidArchive    = errors.New("cloudbackup: invalid backup archive")
)

// Source is the snapshot surface Export reads from.
type Source interface {
	ReadBackupSnapshot(ctx context.Context, fn func(*cloudstore.BackupReader) error) error
}

// Target is the restore surface Import writes to.
type Target interface {
	RestoreBackup(ctx context.Context, opts cloudstore.BackupRestoreOptions, fn func(*cloudstore.BackupWriter) error) error
}

type ExportOptions struct {
	// EngramVersion is recorded in the manifest when set.
	EngramVersion string
	// TempDir holds spooled members; empty uses the system temp directory.
	TempDir string
}

type ImportOptions struct {
	// DryRun validates the whole archive against the target and rolls back.
	DryRun bool
	// TempDir holds spooled members; empty uses the system temp directory.
	TempDir string
}

type TableSummary struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

type Summary struct {
	FormatVersion  int            `json:"format_version"`
	CreatedAt      time.Time      `json:"created_at"`
	MaxMutationSeq int64          `json:"max_mutation_seq"`
	Tables         []TableSummary `json:"tables"`
	DryRun         bool           `json:"dry_run"`
}

type manifest struct {
	Format        string                       `json:"format"`
	FormatVersion int                          `json:"format_version"`
	CreatedAt     string                       `json:"created_at"`
	EngramVersion string                       `json:"engram_version,omitempty"`
	Source        manifestSource               `json:"source"`
	Tables        []manifestTable              `json:"tables"`
	Excluded      []cloudstore.BackupExclusion `json:"excluded"`
}

type manifestSource struct {
	MaxMutationSeq int64            `json:"max_mutation_seq"`
	Sequences      map[string]int64 `json:"sequences"`
}

type manifestTable struct {
	Name    string   `json:"name"`
	Member  string   `json:"member"`
	Columns []string `json:"columns"`
	Rows    int64    `json:"rows"`
	Size    int64    `json:"size"`
	SHA256  string   `json:"sha256"`
}

// spooledMember is a member staged in a temp file with its digest.
type spooledMember struct {
	path   string
	size   int64
	sha256 string
}

func tableMemberName(table string) string {
	return tableMemberPrefix + table + tableMemberSuffix
}

// Export writes one archive of every backup table read from a single source
// snapshot. Members are spooled to temp files first so backup.json, written
// last, can carry the size and checksum of every member.
func Export(ctx context.Context, src Source, w io.Writer, opts ExportOptions) (Summary, error) {
	spoolDir, err := os.MkdirTemp(opts.TempDir, "engram-cloud-backup-export-*")
	if err != nil {
		return Summary{}, fmt.Errorf("cloudbackup: create spool dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(spoolDir) }()

	createdAt := time.Now().UTC()
	m := manifest{
		Format:        FormatName,
		FormatVersion: FormatVersion,
		CreatedAt:     createdAt.Format(time.RFC3339Nano),
		EngramVersion: strings.TrimSpace(opts.EngramVersion),
		Excluded:      cloudstore.BackupExclusions(),
	}
	members := make(map[string]spooledMember)
	err = src.ReadBackupSnapshot(ctx, func(r *cloudstore.BackupReader) error {
		maxSeq, err := r.MaxMutationSeq(ctx)
		if err != nil {
			return err
		}
		sequences, err := r.SequenceValues(ctx)
		if err != nil {
			return err
		}
		m.Source = manifestSource{MaxMutationSeq: maxSeq, Sequences: sequences}
		for _, table := range cloudstore.BackupTables() {
			columns, _ := cloudstore.BackupTableColumns(table)
			spooled, rows, err := spoolTable(ctx, r, spoolDir, table)
			if err != nil {
				return err
			}
			members[table] = spooled
			m.Tables = append(m.Tables, manifestTable{
				Name: table, Member: tableMemberName(table), Columns: columns,
				Rows: rows, Size: spooled.size, SHA256: spooled.sha256,
			})
		}
		return nil
	})
	if err != nil {
		return Summary{}, err
	}

	encodedManifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Summary{}, fmt.Errorf("cloudbackup: encode manifest: %w", err)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, table := range m.Tables {
		if err := writeSpooledMember(tw, table.Member, members[table.Name], createdAt); err != nil {
			return Summary{}, err
		}
	}
	if err := writeMember(tw, ManifestName, int64(len(encodedManifest)), createdAt, bytes.NewReader(encodedManifest)); err != nil {
		return Summary{}, err
	}
	if err := tw.Close(); err != nil {
		return Summary{}, fmt.Errorf("cloudbackup: close archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return Summary{}, fmt.Errorf("cloudbackup: close archive compression: %w", err)
	}
	return summarize(m, createdAt, false), nil
}

func spoolTable(ctx context.Context, r *cloudstore.BackupReader, dir, table string) (spooledMember, int64, error) {
	file, err := os.CreateTemp(dir, "table-*.jsonl")
	if err != nil {
		return spooledMember{}, 0, fmt.Errorf("cloudbackup: spool %s: %w", table, err)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(file, hash)}
	buffered := bufio.NewWriter(counter)
	rows, err := r.StreamTable(ctx, table, func(row []byte) error {
		if _, err := buffered.Write(row); err != nil {
			return err
		}
		return buffered.WriteByte('\n')
	})
	if err != nil {
		return spooledMember{}, 0, err
	}
	if err := buffered.Flush(); err != nil {
		return spooledMember{}, 0, fmt.Errorf("cloudbackup: spool %s: %w", table, err)
	}
	if err := file.Close(); err != nil {
		return spooledMember{}, 0, fmt.Errorf("cloudbackup: spool %s: %w", table, err)
	}
	return spooledMember{path: file.Name(), size: counter.n, sha256: hex.EncodeToString(hash.Sum(nil))}, rows, nil
}

func writeSpooledMember(tw *tar.Writer, name string, member spooledMember, modTime time.Time) error {
	file, err := os.Open(member.path)
	if err != nil {
		return fmt.Errorf("cloudbackup: reopen %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	return writeMember(tw, name, member.size, modTime, file)
}

func writeMember(tw *tar.Writer, name string, size int64, modTime time.Time, r io.Reader) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: modTime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("cloudbackup: write %s header: %w", name, err)
	}
	if _, err := io.Copy(tw, r); err != nil {
		return fmt.Errorf("cloudbackup: write %s: %w", name, err)
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Import restores an archive into an empty target in one transaction. The
// whole archive is spooled and verified (format, member set, sizes and
// checksums) before the target is touched; row decoding and chunk hashes are
// verified inside the transaction, so any failure leaves the target unchanged.
func Import(ctx context.Context, dst Target, r io.Reader, opts ImportOptions) (Summary, error) {
	spoolDir, err := os.MkdirTemp(opts.TempDir, "engram-cloud-backup-import-*")
	if err != nil {
		return Summary{}, fmt.Errorf("cloudbackup: create spool dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(spoolDir) }()

	members, rawManifest, err := spoolArchive(r, spoolDir)
	if err != nil {
		return Summary{}, err
	}
	m, err := verifyManifest(rawManifest, members)
	if err != nil {
		return Summary{}, err
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, m.CreatedAt)

	floors := make(map[string]int64, len(m.Source.Sequences)+1)
	for key, value := range m.Source.Sequences {
		floors[key] = value
	}
	floors[mutationSeqKey] = max(floors[mutationSeqKey], m.Source.MaxMutationSeq)

	err = dst.RestoreBackup(ctx, cloudstore.BackupRestoreOptions{DryRun: opts.DryRun, SequenceFloors: floors}, func(w *cloudstore.BackupWriter) error {
		for _, table := range m.Tables {
			if err := restoreTable(ctx, w, table, members[table.Member]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Summary{}, err
	}
	return summarize(m, createdAt, opts.DryRun), nil
}

// spoolArchive stages every table member and returns the manifest bytes. It
// reads the gzip stream to its end so a truncated trailer is detected too.
func spoolArchive(r io.Reader, dir string) (map[string]spooledMember, []byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	members := make(map[string]spooledMember)
	var rawManifest []byte
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: read member: %v", ErrInvalidArchive, err)
		}
		if rawManifest != nil {
			return nil, nil, fmt.Errorf("%w: member %q follows %s", ErrInvalidArchive, header.Name, ManifestName)
		}
		if header.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("%w: member %q is not a regular file", ErrInvalidArchive, header.Name)
		}
		if header.Name == ManifestName {
			rawManifest, err = io.ReadAll(io.LimitReader(tr, maxManifestBytes+1))
			if err != nil {
				return nil, nil, fmt.Errorf("%w: read %s: %v", ErrInvalidArchive, ManifestName, err)
			}
			if len(rawManifest) > maxManifestBytes {
				return nil, nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidArchive, ManifestName, maxManifestBytes)
			}
			continue
		}
		if !isTableMember(header.Name) {
			return nil, nil, fmt.Errorf("%w: unexpected member %q", ErrInvalidArchive, header.Name)
		}
		if _, duplicate := members[header.Name]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate member %q", ErrInvalidArchive, header.Name)
		}
		spooled, err := spoolMember(tr, dir, header.Name)
		if err != nil {
			return nil, nil, err
		}
		members[header.Name] = spooled
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, nil, fmt.Errorf("%w: read compression trailer: %v", ErrInvalidArchive, err)
	}
	if err := gz.Close(); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	if rawManifest == nil {
		return nil, nil, fmt.Errorf("%w: missing %s", ErrInvalidArchive, ManifestName)
	}
	return members, rawManifest, nil
}

func isTableMember(name string) bool {
	return slices.ContainsFunc(cloudstore.BackupTables(), func(table string) bool { return tableMemberName(table) == name })
}

func spoolMember(r io.Reader, dir, name string) (spooledMember, error) {
	file, err := os.CreateTemp(dir, "member-*.jsonl")
	if err != nil {
		return spooledMember{}, fmt.Errorf("cloudbackup: spool %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), r)
	if err != nil {
		return spooledMember{}, fmt.Errorf("%w: read %s: %v", ErrInvalidArchive, name, err)
	}
	if err := file.Close(); err != nil {
		return spooledMember{}, fmt.Errorf("cloudbackup: spool %s: %w", name, err)
	}
	return spooledMember{path: file.Name(), size: size, sha256: hex.EncodeToString(hash.Sum(nil))}, nil
}

// verifyManifest checks the format, that the manifest lists exactly the
// backup tables with their current columns, and that every member matches
// its recorded size and checksum.
func verifyManifest(raw []byte, members map[string]spooledMember) (manifest, error) {
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return manifest{}, fmt.Errorf("%w: decode %s: %v", ErrInvalidArchive, ManifestName, err)
	}
	if m.Format != FormatName {
		return manifest{}, fmt.Errorf("%w: format %q, want %q", ErrUnsupportedFormat, m.Format, FormatName)
	}
	if m.FormatVersion != FormatVersion {
		return manifest{}, fmt.Errorf("%w: format version %d, this engram reads version %d", ErrUnsupportedFormat, m.FormatVersion, FormatVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return manifest{}, fmt.Errorf("%w: created_at: %v", ErrInvalidArchive, err)
	}
	if m.Source.MaxMutationSeq < 0 {
		return manifest{}, fmt.Errorf("%w: negative max mutation seq", ErrInvalidArchive)
	}
	tables := cloudstore.BackupTables()
	if len(m.Tables) != len(tables) {
		return manifest{}, fmt.Errorf("%w: manifest lists %d tables, want %d", ErrInvalidArchive, len(m.Tables), len(tables))
	}
	for i, table := range m.Tables {
		if table.Name != tables[i] || table.Member != tableMemberName(table.Name) {
			return manifest{}, fmt.Errorf("%w: manifest table %d is %q (%q), want %q", ErrInvalidArchive, i, table.Name, table.Member, tables[i])
		}
		columns, _ := cloudstore.BackupTableColumns(table.Name)
		if !slices.Equal(table.Columns, columns) {
			return manifest{}, fmt.Errorf("%w: table %s columns %v, want %v", ErrInvalidArchive, table.Name, table.Columns, columns)
		}
		if table.Rows < 0 {
			return manifest{}, fmt.Errorf("%w: table %s has negative row count", ErrInvalidArchive, table.Name)
		}
		member, ok := members[table.Member]
		if !ok {
			return manifest{}, fmt.Errorf("%w: missing member %q", ErrInvalidArchive, table.Member)
		}
		if member.size != table.Size || member.sha256 != table.SHA256 {
			return manifest{}, fmt.Errorf("%w: %s", ErrChecksumMismatch, table.Member)
		}
	}
	return m, nil
}

// restoreTable streams one verified member into the restore transaction in
// bounded batches and checks its row count against the manifest.
func restoreTable(ctx context.Context, w *cloudstore.BackupWriter, table manifestTable, member spooledMember) error {
	file, err := os.Open(member.path)
	if err != nil {
		return fmt.Errorf("cloudbackup: reopen %s: %w", table.Member, err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(bufio.NewReader(file))
	var (
		batch      []json.RawMessage
		batchBytes int
		rows       int64
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := w.InsertRows(ctx, table.Name, batch); err != nil {
			return err
		}
		batch, batchBytes = batch[:0], 0
		return nil
	}
	for {
		var row json.RawMessage
		if err := decoder.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("%w: %s row %d: %v", ErrInvalidArchive, table.Member, rows+1, err)
		}
		rows++
		batch = append(batch, row)
		batchBytes += len(row)
		if len(batch) >= insertBatchRows || batchBytes >= insertBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if rows != table.Rows {
		return fmt.Errorf("%w: %s has %d rows, manifest records %d", ErrInvalidArchive, table.Member, rows, table.Rows)
	}
	return nil
}

func summarize(m manifest, createdAt time.Time, dryRun bool) Summary {
	tables := make([]TableSummary, 0, len(m.Tables))
	for _, table := range m.Tables {
		tables = append(tables, TableSummary{Name: table.Name, Rows: table.Rows})
	}
	return Summary{
		FormatVersion:  m.FormatVersion,
		CreatedAt:      createdAt,
		MaxMutationSeq: m.Source.MaxMutationSeq,
		Tables:         tables,
		DryRun:         dryRun,
	}
}
