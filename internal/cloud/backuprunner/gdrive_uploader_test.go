package backuprunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/gdrive"
)

// fakeGDriveClient is the narrow GDriveClient the uploader uses; it never
// reaches the network.
type fakeGDriveClient struct {
	ensured   []string
	checked   []string
	uploads   []fakePut
	folders   []string
	folderID  string
	fileID    string
	ensureErr error
	uploadErr error
	checkErr  error
}

func (c *fakeGDriveClient) EnsureFolder(_ context.Context, name string) (string, error) {
	c.ensured = append(c.ensured, name)
	if c.ensureErr != nil {
		return "", c.ensureErr
	}
	return c.folderID, nil
}

func (c *fakeGDriveClient) CheckAccess(_ context.Context, folder string) error {
	c.checked = append(c.checked, folder)
	return c.checkErr
}

func (c *fakeGDriveClient) Upload(_ context.Context, folderID, name string, body io.ReadSeeker, size int64) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	c.folders = append(c.folders, folderID)
	c.uploads = append(c.uploads, fakePut{key: name, size: size, body: data})
	if c.uploadErr != nil {
		return "", c.uploadErr
	}
	return c.fileID, nil
}

const testGDriveObject = "engram-cloud-backup-20261130T030000Z-run1.tar.gz"

// S15: Upload ensures the backup folder (once per uploader, which the
// runner builds per run), uploads the archive into it under the run's
// object name and reports "<folder>/<object> (file id <id>)".
func TestGDriveUploaderEnsuresTheFolderOnceAndUploadsIntoIt(t *testing.T) {
	client := &fakeGDriveClient{folderID: "folder-1AbC", fileID: "file-9XyZ"}
	uploader := newGDriveUploader(client, "Engram backups")
	location, err := uploader.Upload(context.Background(), testGDriveObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if want := "Engram backups/" + testGDriveObject + " (file id file-9XyZ)"; location != want {
		t.Fatalf("location = %q, want %q", location, want)
	}
	if len(client.ensured) != 1 || client.ensured[0] != "Engram backups" {
		t.Fatalf("ensured = %q", client.ensured)
	}
	if len(client.uploads) != 1 || client.folders[0] != "folder-1AbC" || client.uploads[0].key != testGDriveObject ||
		client.uploads[0].size != int64(len(archiveBytes)) || !bytes.Equal(client.uploads[0].body, archiveBytes) {
		t.Fatalf("uploads = %+v into %q", client.uploads, client.folders)
	}
	if _, err := uploader.Upload(context.Background(), "second.tar.gz", bytes.NewReader(archiveBytes), int64(len(archiveBytes))); err != nil {
		t.Fatalf("second Upload: %v", err)
	}
	if len(client.ensured) != 1 || len(client.uploads) != 2 || client.folders[1] != "folder-1AbC" {
		t.Fatalf("second upload ensured %d times into %q", len(client.ensured), client.folders)
	}
}

// Folder and upload errors keep their Google Drive kind and add no
// credential; a failed folder lookup uploads nothing and is retried by the
// next Upload.
func TestGDriveUploaderKeepsTheErrorKind(t *testing.T) {
	for _, kind := range []error{gdrive.ErrAuth, gdrive.ErrQuota, gdrive.ErrRateLimited, gdrive.ErrNetwork, gdrive.ErrScope} {
		client := &fakeGDriveClient{ensureErr: &gdrive.Error{Op: "EnsureFolder", Kind: kind, StatusCode: 403}}
		uploader := newGDriveUploader(client, "Engram backups")
		location, err := uploader.Upload(context.Background(), testGDriveObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if location != "" || !errors.Is(err, kind) || len(client.uploads) != 0 {
			t.Fatalf("folder error = %q, %v (uploads %d); want %v", location, err, len(client.uploads), kind)
		}
		client.ensureErr, client.folderID = nil, "folder-1"
		if _, err := uploader.Upload(context.Background(), testGDriveObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes))); err != nil || len(client.ensured) != 2 {
			t.Fatalf("retry after a folder error = %v, ensured %d times", err, len(client.ensured))
		}

		failing := &fakeGDriveClient{folderID: "folder-1", uploadErr: &gdrive.Error{Op: "Upload", Kind: kind, StatusCode: 403}}
		location, err = newGDriveUploader(failing, "Engram backups").Upload(context.Background(), testGDriveObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if location != "" || !errors.Is(err, kind) {
			t.Fatalf("upload error = %q, %v; want %v", location, err, kind)
		}
	}
}

// CheckAccess checks the folder by name without writing; errors are
// returned unchanged.
func TestGDriveUploaderCheckAccess(t *testing.T) {
	client := &fakeGDriveClient{}
	if err := newGDriveUploader(client, "Engram backups").CheckAccess(context.Background()); err != nil || len(client.checked) != 1 || client.checked[0] != "Engram backups" || len(client.ensured) != 0 {
		t.Fatalf("CheckAccess = %v, checked %q ensured %q", err, client.checked, client.ensured)
	}
	failing := &fakeGDriveClient{checkErr: &gdrive.Error{Op: "CheckAccess", Kind: gdrive.ErrAuth}}
	if err := newGDriveUploader(failing, "Engram backups").CheckAccess(context.Background()); !errors.Is(err, gdrive.ErrAuth) {
		t.Fatalf("check error = %v, want %v", err, gdrive.ErrAuth)
	}
}

// NewGDriveUploader builds the real client from the opened credentials
// without any network call; a refused configuration (for example a pending
// destination without a refresh token) never echoes a secret.
func TestNewGDriveUploaderValidatesWithoutEchoingSecrets(t *testing.T) {
	if _, err := NewGDriveUploader(testGDrive.GDrive); err != nil {
		t.Fatalf("NewGDriveUploader: %v", err)
	}
	for name, mutate := range map[string]func(*cloudstore.GDriveDestinationCredentials){
		"no client id":     func(c *cloudstore.GDriveDestinationCredentials) { c.ClientID = "" },
		"no refresh token": func(c *cloudstore.GDriveDestinationCredentials) { c.RefreshToken = "" },
	} {
		bad := testGDrive.GDrive
		mutate(&bad)
		_, err := NewGDriveUploader(bad)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		for _, secret := range []string{testGDriveClientSecret, testGDriveRefreshToken} {
			if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
				t.Fatalf("%s: constructor error leaked a secret: %v", name, err)
			}
		}
	}
}

// A run of an authorized Google Drive destination uploads through the real
// uploader (over a fake client) into the folder, records the location and,
// when it fails, a sanitized message without the destination's secrets.
func TestRunnerUploadsToGDriveEndToEnd(t *testing.T) {
	for name, tc := range map[string]struct {
		client     *fakeGDriveClient
		wantStatus string
		wantKey    string
		wantPrefix string
	}{
		"success": {client: &fakeGDriveClient{folderID: "folder-1", fileID: "file-1"}, wantStatus: cloudstore.BackupRunStatusSuccess, wantKey: "Engram backups/" + testGDriveObject + " (file id file-1)"},
		"auth": {client: &fakeGDriveClient{folderID: "folder-1", uploadErr: &gdrive.Error{Op: "Upload", Kind: gdrive.ErrAuth, StatusCode: 400, Message: "invalid_grant for " + testGDriveRefreshToken}},
			wantStatus: cloudstore.BackupRunStatusFailure, wantPrefix: "upload: gdrive: Upload: authorization revoked or expired"},
		"quota": {client: &fakeGDriveClient{folderID: "folder-1", uploadErr: &gdrive.Error{Op: "Upload", Kind: gdrive.ErrQuota, StatusCode: 403, Message: "secret " + testGDriveClientSecret}},
			wantStatus: cloudstore.BackupRunStatusFailure, wantPrefix: "upload: gdrive: Upload: storage or daily upload quota"},
	} {
		t.Run(name, func(t *testing.T) {
			var got cloudstore.GDriveDestinationCredentials
			h := newHarness(t, beforeSlot, func(cfg *Config) {
				cfg.NewGDriveUploader = func(c cloudstore.GDriveDestinationCredentials) (Uploader, error) {
					got = c
					return newGDriveUploader(tc.client, c.FolderName), nil
				}
			})
			h.store.setOpened(&testGDrive)
			h.store.setSchedule(mondayAt3())
			h.start(t)
			h.clock.waitSleeping(t)
			h.clock.Advance(time.Minute)
			run := waitFinished(t, h)
			if got != testGDrive.GDrive {
				t.Fatalf("constructor got %v", got)
			}
			if run.Status != tc.wantStatus || run.ObjectKey != tc.wantKey || !strings.HasPrefix(run.ErrorMessage, tc.wantPrefix) {
				t.Fatalf("run = %+v, want %s %q %q", run, tc.wantStatus, tc.wantKey, tc.wantPrefix)
			}
			if len(tc.client.ensured) != 1 || tc.client.ensured[0] != "Engram backups" || len(tc.client.uploads) != 1 || tc.client.uploads[0].key != testGDriveObject {
				t.Fatalf("ensured %q uploads %+v", tc.client.ensured, tc.client.uploads)
			}
			for _, secret := range []string{testGDriveClientSecret, testGDriveRefreshToken} {
				if strings.Contains(run.ErrorMessage, secret) || strings.Contains(h.logs.text(), secret) {
					t.Fatalf("a secret leaked: %q / logs %s", run.ErrorMessage, h.logs.text())
				}
			}
			h.assertTempDirEmpty(t)
		})
	}
}
