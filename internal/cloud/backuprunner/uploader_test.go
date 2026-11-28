package backuprunner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

const (
	testDropboxAppSecret    = "dbx-runner-app-secret-do-not-leak"
	testDropboxRefreshToken = "dbx-runner-refresh-token-do-not-leak"
	testGDriveClientSecret  = "gdrive-runner-client-secret-do-not-leak"
	testGDriveRefreshToken  = "gdrive-runner-refresh-token-do-not-leak"
)

var (
	testDropbox = cloudstore.OpenedBackupDestination{Kind: cloudstore.BackupDestinationKindDropbox, Dropbox: cloudstore.DropboxDestinationCredentials{
		AppKey: "dbxappkeyrunner", FolderPath: "/Engram backups", AppSecret: testDropboxAppSecret, RefreshToken: testDropboxRefreshToken,
	}}
	testGDrive = cloudstore.OpenedBackupDestination{Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationCredentials{
		ClientID: "runner.apps.googleusercontent.com", FolderName: "Engram backups", ClientSecret: testGDriveClientSecret, RefreshToken: testGDriveRefreshToken,
	}}
)

// fakeKindUploader is a Dropbox or Google Drive uploader.
type fakeKindUploader struct {
	mu       sync.Mutex
	uploads  []fakePut
	location string
	err      error
}

func (u *fakeKindUploader) Upload(ctx context.Context, objectName string, body io.ReadSeeker, size int64) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	put := fakePut{key: objectName, size: size, body: data}
	if d, ok := ctx.Deadline(); ok {
		put.deadline = time.Until(d)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.uploads = append(u.uploads, put)
	if u.err != nil {
		return "", u.err
	}
	return u.location, nil
}

func (u *fakeKindUploader) CheckAccess(context.Context) error { return u.err }

func (u *fakeKindUploader) snapshot() []fakePut {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]fakePut(nil), u.uploads...)
}

func waitFinished(t *testing.T, h *harness) cloudstore.BackupRun {
	t.Helper()
	waitFor(t, "the finished run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	return h.store.snapshot()[0]
}

// The S3 uploader stores the object under the key BackupRunObjectKey has
// always produced and reports that key as the location.
func TestS3UploaderKeepsTheBackupRunObjectKey(t *testing.T) {
	stamp := time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)
	for _, prefix := range []string{"", "prod/nightly", "prod/nightly/", " /a//b/ ", "/lead"} {
		client := &fakeUploader{}
		uploader := newS3Uploader(client, prefix)
		name := s3client.BackupRunObjectKey("", stamp, 7)
		location, err := uploader.Upload(context.Background(), name, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		want := s3client.BackupRunObjectKey(prefix, stamp, 7)
		puts := client.snapshot()
		if err != nil || location != want || len(puts) != 1 || puts[0].key != want || puts[0].contentType != ContentType || !bytes.Equal(puts[0].body, archiveBytes) {
			t.Fatalf("prefix %q: location %q err %v puts %+v; want key %q", prefix, location, err, puts, want)
		}
	}
	failing := &fakeUploader{err: errors.New("denied")}
	uploader := newS3Uploader(failing, "p")
	if location, err := uploader.Upload(context.Background(), "x.tar.gz", bytes.NewReader(nil), 0); err == nil || err.Error() != "denied" || location != "" {
		t.Fatalf("failing upload = %q, %v; want the client's error unchanged", location, err)
	}
	if err := uploader.CheckAccess(context.Background()); err == nil || err.Error() != "denied" {
		t.Fatalf("CheckAccess = %v, want the client's", err)
	}
}

// The runner picks the uploader of the destination's kind, hands it the
// opened credentials and the kind-neutral object name, and records the
// location it returns.
func TestRunnerSelectsTheUploaderByKind(t *testing.T) {
	for name, tc := range map[string]struct {
		dest     cloudstore.OpenedBackupDestination
		location string
	}{
		"dropbox": {dest: testDropbox, location: "/Engram backups/engram-cloud-backup-20261130T030000Z-run1.tar.gz"},
		"gdrive":  {dest: testGDrive, location: "Engram backups/engram-cloud-backup-20261130T030000Z-run1.tar.gz (file id 1AbC)"},
	} {
		t.Run(name, func(t *testing.T) {
			kindUploader := &fakeKindUploader{location: tc.location}
			var gotDropbox cloudstore.DropboxDestinationCredentials
			var gotGDrive cloudstore.GDriveDestinationCredentials
			h := newHarness(t, beforeSlot, func(cfg *Config) {
				cfg.NewDropboxUploader = func(c cloudstore.DropboxDestinationCredentials) (Uploader, error) {
					gotDropbox = c
					return kindUploader, nil
				}
				cfg.NewGDriveUploader = func(c cloudstore.GDriveDestinationCredentials) (Uploader, error) {
					gotGDrive = c
					return kindUploader, nil
				}
			})
			h.store.setOpened(&tc.dest)
			h.store.setSchedule(mondayAt3())
			h.start(t)
			h.clock.waitSleeping(t)
			h.clock.Advance(time.Minute)
			run := waitFinished(t, h)
			if run.Status != cloudstore.BackupRunStatusSuccess || run.ObjectKey != tc.location || run.SizeBytes != int64(len(archiveBytes)) {
				t.Fatalf("run = %+v, want success at %q", run, tc.location)
			}
			if gotDropbox != tc.dest.Dropbox || gotGDrive != tc.dest.GDrive {
				t.Fatalf("constructors got %v / %v, want %v", gotDropbox, gotGDrive, tc.dest)
			}
			uploads := kindUploader.snapshot()
			if len(uploads) != 1 || uploads[0].key != "engram-cloud-backup-20261130T030000Z-run1.tar.gz" || !bytes.Equal(uploads[0].body, archiveBytes) || uploads[0].size != int64(len(archiveBytes)) {
				t.Fatalf("uploads = %+v", uploads)
			}
			if uploads[0].deadline <= 0 || uploads[0].deadline > MinUploadDeadline {
				t.Fatalf("upload deadline in %s, want at most %s", uploads[0].deadline, MinUploadDeadline)
			}
			if n := len(h.uploader.snapshot()); n != 0 {
				t.Fatalf("the S3 client uploaded %d times for a %s destination", n, name)
			}
			h.assertTempDirEmpty(t)
		})
	}
}

// Until a server wires the Dropbox or Google Drive uploader, a scheduled run
// is recorded as skipped and a manual run is refused without a run row.
func TestUnwiredKindIsSkippedOrRefused(t *testing.T) {
	for name, dest := range map[string]cloudstore.OpenedBackupDestination{"dropbox": testDropbox, "gdrive": testGDrive} {
		t.Run(name, func(t *testing.T) {
			want := "skipped: " + name + " destination is not supported by this server yet"
			h := newHarness(t, beforeSlot, nil)
			h.store.setOpened(&dest)
			h.store.setSchedule(mondayAt3())
			h.start(t)
			h.clock.waitSleeping(t)

			for range 2 {
				_, err := h.runner.StartManualBackup(context.Background(), "1")
				if !errors.Is(err, cloudserver.ErrBackupDestinationUnsupported) || !strings.Contains(err.Error(), name+" destination is not supported by this server yet") {
					t.Fatalf("manual run error = %v, want %v", err, cloudserver.ErrBackupDestinationUnsupported)
				}
			}
			if runs := h.store.snapshot(); len(runs) != 0 || h.runner.busy.Load() {
				t.Fatalf("a refused manual run recorded %+v (busy %v)", runs, h.runner.busy.Load())
			}

			h.clock.Advance(time.Minute)
			run := waitFinished(t, h)
			if run.Status != cloudstore.BackupRunStatusFailure || run.ErrorMessage != want || run.ErrorMessage != SkippedUnsupportedMessage(name) {
				t.Fatalf("scheduled run = %+v, want %q", run, want)
			}
			if n := len(h.uploader.snapshot()); n != 0 {
				t.Fatalf("uploads = %d, want 0", n)
			}
			h.assertTempDirEmpty(t)

			// Switching the destination back to S3 makes manual runs work.
			h.store.setOpened(nil)
			h.clock.waitSleeping(t)
			if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
				t.Fatalf("manual run on s3: %v", err)
			}
			waitFor(t, "the s3 manual run", func() bool {
				runs := h.store.snapshot()
				return len(runs) == 2 && runs[1].Status == cloudstore.BackupRunStatusSuccess
			})
		})
	}
}

// A manual run whose destination cannot be read up front still starts and
// records the real reason, as before kinds existed.
func TestManualRunStartsWhenTheDestinationKindCannotBeRead(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.getErr = errStoreUnavailable
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatalf("manual run: %v", err)
	}
	if run := waitFinished(t, h); run.Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("run = %+v", run)
	}
}

func TestPendingGDriveDestinationIsSkipped(t *testing.T) {
	pending := testGDrive
	pending.GDrive.RefreshToken = ""
	called := false
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.NewGDriveUploader = func(cloudstore.GDriveDestinationCredentials) (Uploader, error) {
			called = true
			return &fakeKindUploader{}, nil
		}
	})
	h.store.setOpened(&pending)
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatalf("manual run: %v", err)
	}
	run := waitFinished(t, h)
	if run.Status != cloudstore.BackupRunStatusFailure || run.ErrorMessage != SkippedNotAuthorizedMessage || called {
		t.Fatalf("run = %+v (constructor called %v), want %q", run, called, SkippedNotAuthorizedMessage)
	}
}

// Errors of a kind uploader or its constructor are recorded without the
// destination's secrets.
func TestKindUploaderErrorsAreRecordedWithoutSecrets(t *testing.T) {
	for name, tc := range map[string]struct {
		construct error
		upload    error
		prefix    string
	}{
		"constructor": {construct: &credentialEchoError{msg: "bad app " + testDropboxAppSecret + " token " + testDropboxRefreshToken}, prefix: "invalid backup destination: bad app"},
		"upload":      {upload: &credentialEchoError{msg: "refresh failed for " + testDropboxRefreshToken + " secret " + testDropboxAppSecret}, prefix: "upload: refresh failed for"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, beforeSlot, func(cfg *Config) {
				cfg.NewDropboxUploader = func(cloudstore.DropboxDestinationCredentials) (Uploader, error) {
					if tc.construct != nil {
						return nil, tc.construct
					}
					return &fakeKindUploader{err: tc.upload}, nil
				}
			})
			h.store.setOpened(&testDropbox)
			h.start(t)
			if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
				t.Fatal(err)
			}
			run := waitFinished(t, h)
			if run.Status != cloudstore.BackupRunStatusFailure || !strings.HasPrefix(run.ErrorMessage, tc.prefix) {
				t.Fatalf("run = %+v, want a failure starting %q", run, tc.prefix)
			}
			for _, secret := range []string{testDropboxAppSecret, testDropboxRefreshToken} {
				if strings.Contains(run.ErrorMessage, secret) || strings.Contains(h.logs.text(), secret) {
					t.Fatalf("a secret leaked: %q / logs %s", run.ErrorMessage, h.logs.text())
				}
			}
			h.assertTempDirEmpty(t)
		})
	}
}
