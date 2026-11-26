package cloudbackup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// The tests in this file build archives in memory and import them into a
// recordingTarget, so archive parsing, size limits and manifest verification
// run without Postgres.

var errRestoreReached = errors.New("test: archive passed verification and reached the target")

// recordingTarget records RestoreBackup calls and never writes anything.
type recordingTarget struct {
	calls int
	opts  cloudstore.BackupRestoreOptions
}

func (r *recordingTarget) RestoreBackup(_ context.Context, opts cloudstore.BackupRestoreOptions, _ func(*cloudstore.BackupWriter) error) error {
	r.calls++
	r.opts = opts
	return errRestoreReached
}

type tarEntry struct {
	name     string
	data     []byte
	typeflag byte
	linkname string
}

// validArchiveParts returns one data member per backup table and a manifest
// that describes them exactly.
func validArchiveParts(t *testing.T) ([]tarEntry, manifest) {
	t.Helper()
	m := manifest{
		Format:        FormatName,
		FormatVersion: FormatVersion,
		CreatedAt:     "2026-11-25T03:00:00.123456789Z",
		Source:        manifestSource{MaxMutationSeq: 42, Sequences: map[string]int64{"cloud_mutations.seq": 40, "cloud_principals.id": 7}},
		Excluded:      cloudstore.BackupExclusions(),
	}
	var entries []tarEntry
	for i, table := range cloudstore.BackupTables() {
		columns, ok := cloudstore.BackupTableColumns(table)
		if !ok {
			t.Fatalf("no columns for backup table %s", table)
		}
		data := []byte(strings.Repeat(fmt.Sprintf("{\"row\":%q}\n", table), i%3))
		sum := sha256.Sum256(data)
		entries = append(entries, tarEntry{name: tableMemberName(table), data: data})
		m.Tables = append(m.Tables, manifestTable{
			Name: table, Member: tableMemberName(table), Columns: columns,
			Rows: int64(i % 3), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return entries, m
}

func manifestEntry(t *testing.T, m manifest) tarEntry {
	t.Helper()
	encoded, err := json.Marshal(m)
	must(t, err)
	return tarEntry{name: ManifestName, data: encoded}
}

// buildArchive writes entries as a tar stream, appends trailing bytes after
// the tar end-of-archive marker, and gzips the whole thing.
func buildArchive(t *testing.T, entries []tarEntry, trailing []byte) []byte {
	t.Helper()
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: 0o600, Typeflag: typeflag, Linkname: entry.linkname}
		if typeflag == tar.TypeReg {
			header.Size = int64(len(entry.data))
		}
		must(t, tw.WriteHeader(header))
		if typeflag == tar.TypeReg {
			_, err := tw.Write(entry.data)
			must(t, err)
		}
	}
	must(t, tw.Close())
	plain.Write(trailing)
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	_, err := gz.Write(plain.Bytes())
	must(t, err)
	must(t, gz.Close())
	return out.Bytes()
}

func validArchive(t *testing.T) []byte {
	t.Helper()
	entries, m := validArchiveParts(t)
	return buildArchive(t, append(entries, manifestEntry(t, m)), nil)
}

func uncompressedMemberBytes(t *testing.T) int64 {
	t.Helper()
	entries, m := validArchiveParts(t)
	total := int64(len(manifestEntry(t, m).data))
	for _, entry := range entries {
		total += int64(len(entry.data))
	}
	return total
}

func importInto(t *testing.T, archive []byte, opts ImportOptions) (*recordingTarget, error) {
	t.Helper()
	target := &recordingTarget{}
	spool := t.TempDir()
	opts.TempDir = spool
	_, err := Import(context.Background(), target, bytes.NewReader(archive), opts)
	entries, readErr := os.ReadDir(spool)
	must(t, readErr)
	if len(entries) != 0 {
		t.Errorf("spool dir kept %d entries after Import returned", len(entries))
	}
	return target, err
}

// assertRejected checks that Import failed with wantErr, that the message
// names the failing check, and that the target was never touched.
func assertRejected(t *testing.T, archive []byte, opts ImportOptions, wantErr error, wantText string) {
	t.Helper()
	target, err := importInto(t, archive, opts)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Import error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), wantText) {
		t.Errorf("Import error %q does not contain %q", err, wantText)
	}
	if target.calls != 0 {
		t.Errorf("target RestoreBackup called %d times for a rejected archive", target.calls)
	}
}

func assertAccepted(t *testing.T, archive []byte, opts ImportOptions) *recordingTarget {
	t.Helper()
	target, err := importInto(t, archive, opts)
	if !errors.Is(err, errRestoreReached) {
		t.Fatalf("Import error = %v, want the archive to reach the target", err)
	}
	if target.calls != 1 {
		t.Fatalf("target RestoreBackup called %d times, want 1", target.calls)
	}
	return target
}

func TestArchiveValidReachesTargetWithSequenceFloors(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		target := assertAccepted(t, validArchive(t), ImportOptions{DryRun: dryRun})
		want := cloudstore.BackupRestoreOptions{DryRun: dryRun, SequenceFloors: map[string]int64{"cloud_mutations.seq": 42, "cloud_principals.id": 7}}
		if !reflect.DeepEqual(target.opts, want) {
			t.Errorf("restore options = %+v, want %+v", target.opts, want)
		}
	}
}

func TestArchiveTrailingDataAfterEndMarker(t *testing.T) {
	entries, m := validArchiveParts(t)
	members := append(entries, manifestEntry(t, m))

	t.Run("zero padding within one tar record is accepted", func(t *testing.T) {
		assertAccepted(t, buildArchive(t, members, make([]byte, maxTrailingPadding)), ImportOptions{})
	})
	t.Run("non-zero byte after end marker is rejected", func(t *testing.T) {
		assertRejected(t, buildArchive(t, members, []byte("x")), ImportOptions{}, ErrInvalidArchive, "trailing data")
	})
	t.Run("non-zero data hidden behind zero padding is rejected", func(t *testing.T) {
		trailing := append(make([]byte, 512), []byte("smuggled")...)
		assertRejected(t, buildArchive(t, members, trailing), ImportOptions{}, ErrInvalidArchive, "trailing data")
	})
	t.Run("zero padding over one tar record is rejected", func(t *testing.T) {
		assertRejected(t, buildArchive(t, members, make([]byte, maxTrailingPadding+1)), ImportOptions{}, ErrInvalidArchive, "trailing data")
	})
	t.Run("large compressible padding is rejected without draining it", func(t *testing.T) {
		archive := buildArchive(t, members, make([]byte, 64<<20))
		assertRejected(t, archive, ImportOptions{}, ErrInvalidArchive, "trailing data")
	})
}

func TestArchiveCompressionStreamIsVerified(t *testing.T) {
	archive := validArchive(t)
	corruptCRC := bytes.Clone(archive)
	corruptCRC[len(corruptCRC)-8] ^= 0xff
	cases := []struct {
		name    string
		archive []byte
	}{
		{"not gzip", []byte("plain text, not a backup")},
		{"truncated before gzip trailer", archive[:len(archive)-4]},
		{"truncated stream", archive[:len(archive)/2]},
		{"corrupted gzip checksum", corruptCRC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, tc.archive, ImportOptions{}, ErrInvalidArchive, "invalid backup archive")
		})
	}
}

func TestArchiveStructureIsChecked(t *testing.T) {
	entries, m := validArchiveParts(t)
	manifestMember := manifestEntry(t, m)
	with := func(extra ...tarEntry) []tarEntry {
		return append(append([]tarEntry{}, entries...), extra...)
	}
	cases := []struct {
		name     string
		members  []tarEntry
		wantText string
	}{
		{"member after manifest", with(manifestMember, entries[0]), "follows backup.json"},
		{"extra file after manifest", with(manifestMember, tarEntry{name: "notes.txt", data: []byte("x")}), "follows backup.json"},
		{"symlink member", append([]tarEntry{{name: entries[0].name, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}}, with(manifestMember)[1:]...), "is not a regular file"},
		{"directory member", append([]tarEntry{{name: "tables/", typeflag: tar.TypeDir}}, with(manifestMember)...), "is not a regular file"},
		{"unexpected member name", append([]tarEntry{{name: "tables/unknown.jsonl", data: []byte("{}\n")}}, with(manifestMember)...), `unexpected member "tables/unknown.jsonl"`},
		{"token table member", append([]tarEntry{{name: "tables/cloud_principal_tokens.jsonl", data: []byte("{}\n")}}, with(manifestMember)...), `unexpected member "tables/cloud_principal_tokens.jsonl"`},
		{"path traversal member", append([]tarEntry{{name: "../tables/cloud_users.jsonl", data: []byte("{}\n")}}, with(manifestMember)...), "unexpected member"},
		{"duplicate table member", with(entries[0], manifestMember), "duplicate member"},
		{"missing manifest", with(), "missing backup.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, buildArchive(t, tc.members, nil), ImportOptions{}, ErrInvalidArchive, tc.wantText)
		})
	}
}

func TestArchiveSizeLimit(t *testing.T) {
	archive := validArchive(t)
	total := uncompressedMemberBytes(t)
	for _, limit := range []int64{1, total - 1} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			assertRejected(t, archive, ImportOptions{MaxArchiveBytes: limit}, ErrArchiveTooLarge, fmt.Sprintf("exceed %d bytes", limit))
		})
	}
	t.Run("limit equal to member bytes", func(t *testing.T) {
		assertAccepted(t, archive, ImportOptions{MaxArchiveBytes: total})
	})
}

func TestArchiveManifestIsVerified(t *testing.T) {
	entries, _ := validArchiveParts(t)
	cases := []struct {
		name     string
		edit     func(*manifest)
		raw      []byte
		members  func([]tarEntry) []tarEntry
		wantErr  error
		wantText string
	}{
		{name: "undecodable manifest", raw: []byte("{"), wantErr: ErrInvalidArchive, wantText: "decode backup.json"},
		{name: "unknown format", edit: func(m *manifest) { m.Format = "other" }, wantErr: ErrUnsupportedFormat, wantText: `format "other"`},
		{name: "unknown format version", edit: func(m *manifest) { m.FormatVersion = 2 }, wantErr: ErrUnsupportedFormat, wantText: "format version 2"},
		{name: "invalid created_at", edit: func(m *manifest) { m.CreatedAt = "yesterday" }, wantErr: ErrInvalidArchive, wantText: "created_at"},
		{name: "negative max mutation seq", edit: func(m *manifest) { m.Source.MaxMutationSeq = -1 }, wantErr: ErrInvalidArchive, wantText: "negative max mutation seq"},
		{name: "missing table", edit: func(m *manifest) { m.Tables = m.Tables[:len(m.Tables)-1] }, wantErr: ErrInvalidArchive,
			wantText: fmt.Sprintf("manifest lists %d tables, want %d", len(entries)-1, len(entries))},
		{name: "extra table", edit: func(m *manifest) { m.Tables = append(m.Tables, m.Tables[0]) }, wantErr: ErrInvalidArchive,
			wantText: fmt.Sprintf("manifest lists %d tables, want %d", len(entries)+1, len(entries))},
		{name: "tables out of restore order", edit: func(m *manifest) { m.Tables[0], m.Tables[1] = m.Tables[1], m.Tables[0] }, wantErr: ErrInvalidArchive, wantText: "manifest table 0"},
		{name: "member name does not match table", edit: func(m *manifest) { m.Tables[2].Member = m.Tables[3].Member }, wantErr: ErrInvalidArchive, wantText: "manifest table 2"},
		{name: "column list mismatch", edit: func(m *manifest) { m.Tables[1].Columns = append(m.Tables[1].Columns, "password_hash") }, wantErr: ErrInvalidArchive, wantText: "columns"},
		{name: "column order mismatch", edit: func(m *manifest) {
			c := m.Tables[1].Columns
			c[0], c[1] = c[1], c[0]
		}, wantErr: ErrInvalidArchive, wantText: "columns"},
		{name: "negative rows", edit: func(m *manifest) { m.Tables[4].Rows = -1 }, wantErr: ErrInvalidArchive, wantText: "negative row count"},
		{name: "listed member missing from archive", members: func(e []tarEntry) []tarEntry { return e[1:] }, wantErr: ErrInvalidArchive,
			wantText: fmt.Sprintf("missing member %q", entries[0].name)},
		{name: "member checksum mismatch", edit: func(m *manifest) { m.Tables[1].SHA256 = strings.Repeat("0", 64) }, wantErr: ErrChecksumMismatch, wantText: entries[1].name},
		{name: "member size mismatch", edit: func(m *manifest) { m.Tables[1].Size++ }, wantErr: ErrChecksumMismatch, wantText: entries[1].name},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			members, m := validArchiveParts(t)
			if tc.edit != nil {
				tc.edit(&m)
			}
			if tc.members != nil {
				members = tc.members(members)
			}
			manifestMember := manifestEntry(t, m)
			if tc.raw != nil {
				manifestMember.data = tc.raw
			}
			assertRejected(t, buildArchive(t, append(members, manifestMember), nil), ImportOptions{}, tc.wantErr, tc.wantText)
		})
	}
}
