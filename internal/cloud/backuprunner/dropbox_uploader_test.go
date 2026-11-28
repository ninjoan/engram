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
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dropbox"
)

// fakeDropboxClient is the narrow DropboxClient the uploader uses; it never
// reaches the network.
type fakeDropboxClient struct {
	uploads   []fakePut
	checked   []string
	location  string
	uploadErr error
	checkErr  error
}

func (c *fakeDropboxClient) Upload(_ context.Context, path string, body io.ReadSeeker, size int64) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	c.uploads = append(c.uploads, fakePut{key: path, size: size, body: data})
	if c.uploadErr != nil {
		return "", c.uploadErr
	}
	return c.location, nil
}

func (c *fakeDropboxClient) CheckAccess(_ context.Context, folder string) error {
	c.checked = append(c.checked, folder)
	return c.checkErr
}

const testDropboxObject = "engram-cloud-backup-20261130T030000Z-run1.tar.gz"

// Upload stores the archive at "<folder>/<objectName>" and reports the
// Dropbox path the client returns, or the path it asked for when the client
// returns none.
func TestDropboxUploaderJoinsTheFolderAndTheObjectName(t *testing.T) {
	for folder, want := range map[string]string{
		"/Engram backups":  "/Engram backups/" + testDropboxObject,
		"/Engram backups/": "/Engram backups/" + testDropboxObject,
		"/":                "/" + testDropboxObject,
		"":                 "/" + testDropboxObject,
		"/a/b":             "/a/b/" + testDropboxObject,
	} {
		client := &fakeDropboxClient{}
		location, err := newDropboxUploader(client, folder).Upload(context.Background(), testDropboxObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if err != nil || location != want {
			t.Fatalf("folder %q: location %q err %v, want %q", folder, location, err, want)
		}
		if len(client.uploads) != 1 || client.uploads[0].key != want || client.uploads[0].size != int64(len(archiveBytes)) || !bytes.Equal(client.uploads[0].body, archiveBytes) {
			t.Fatalf("folder %q: uploads %+v", folder, client.uploads)
		}
	}
	client := &fakeDropboxClient{location: "/Engram Backups/" + testDropboxObject}
	location, err := newDropboxUploader(client, "/engram backups").Upload(context.Background(), testDropboxObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil || location != client.location {
		t.Fatalf("location %q err %v, want the client's path_display %q", location, err, client.location)
	}
}

// Upload errors keep their Dropbox kind so the run history and the logs can
// tell them apart; the uploader adds no credential.
func TestDropboxUploaderKeepsTheErrorKind(t *testing.T) {
	for _, kind := range []error{dropbox.ErrAuth, dropbox.ErrInsufficientSpace, dropbox.ErrRateLimited, dropbox.ErrNetwork, dropbox.ErrConflict} {
		client := &fakeDropboxClient{uploadErr: &dropbox.Error{Op: "Upload", Kind: kind, StatusCode: 409}}
		location, err := newDropboxUploader(client, "/Engram backups").Upload(context.Background(), testDropboxObject, bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if location != "" || !errors.Is(err, kind) {
			t.Fatalf("upload error = %q, %v; want %v", location, err, kind)
		}
	}
}

// CheckAccess checks the destination's folder. A missing folder is not a
// failure: Upload creates it, so it is reported as
// ErrDropboxFolderPending, which still matches dropbox.ErrFolderNotFound.
// Other errors are returned unchanged.
func TestDropboxUploaderCheckAccess(t *testing.T) {
	client := &fakeDropboxClient{}
	if err := newDropboxUploader(client, "/Engram backups").CheckAccess(context.Background()); err != nil || len(client.checked) != 1 || client.checked[0] != "/Engram backups" {
		t.Fatalf("CheckAccess = %v, checked %q", err, client.checked)
	}
	missing := &fakeDropboxClient{checkErr: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrFolderNotFound, StatusCode: 409}}
	err := newDropboxUploader(missing, "/Engram backups").CheckAccess(context.Background())
	if !errors.Is(err, ErrDropboxFolderPending) || !errors.Is(err, dropbox.ErrFolderNotFound) {
		t.Fatalf("missing folder = %v, want ErrDropboxFolderPending", err)
	}
	if !strings.Contains(ErrDropboxFolderPending.Error(), "created on the first upload") {
		t.Fatalf("ErrDropboxFolderPending = %q", ErrDropboxFolderPending)
	}
	for _, kind := range []error{dropbox.ErrAuth, dropbox.ErrConflict, dropbox.ErrNetwork} {
		failing := &fakeDropboxClient{checkErr: &dropbox.Error{Op: "CheckAccess", Kind: kind}}
		err := newDropboxUploader(failing, "/Engram backups").CheckAccess(context.Background())
		if !errors.Is(err, kind) || errors.Is(err, ErrDropboxFolderPending) {
			t.Fatalf("check error = %v, want %v", err, kind)
		}
	}
}

// NewDropboxUploader builds the real client from the opened credentials
// without any network call; a refused configuration never echoes a secret.
func TestNewDropboxUploaderValidatesWithoutEchoingSecrets(t *testing.T) {
	if _, err := NewDropboxUploader(testDropbox.Dropbox); err != nil {
		t.Fatalf("NewDropboxUploader: %v", err)
	}
	bad := testDropbox.Dropbox
	bad.AppKey = ""
	_, err := NewDropboxUploader(bad)
	if err == nil {
		t.Fatalf("an empty app key was accepted")
	}
	for _, secret := range []string{testDropboxAppSecret, testDropboxRefreshToken} {
		if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
			t.Fatalf("constructor error leaked a secret: %v", err)
		}
	}
}

// A run of a Dropbox destination uploads through the real uploader (over a
// fake client) to "<folder>/<object name>", records the Dropbox path and,
// when it fails, records a sanitized message without the destination's
// secrets.
func TestRunnerUploadsToDropboxEndToEnd(t *testing.T) {
	for name, tc := range map[string]struct {
		client     *fakeDropboxClient
		wantStatus string
		wantKey    string
		wantPrefix string
	}{
		"success": {client: &fakeDropboxClient{location: "/Engram backups/" + testDropboxObject}, wantStatus: cloudstore.BackupRunStatusSuccess, wantKey: "/Engram backups/" + testDropboxObject},
		"auth": {client: &fakeDropboxClient{uploadErr: &dropbox.Error{Op: "Upload", Kind: dropbox.ErrAuth, StatusCode: 400, Summary: "invalid_grant: token " + testDropboxRefreshToken}},
			wantStatus: cloudstore.BackupRunStatusFailure, wantPrefix: "upload: dropbox: Upload: Dropbox authentication failed"},
		"space": {client: &fakeDropboxClient{uploadErr: &dropbox.Error{Op: "Upload", Kind: dropbox.ErrInsufficientSpace, StatusCode: 409, Summary: "path/insufficient_space/ secret " + testDropboxAppSecret}},
			wantStatus: cloudstore.BackupRunStatusFailure, wantPrefix: "upload: dropbox: Upload: not enough space in the Dropbox account"},
	} {
		t.Run(name, func(t *testing.T) {
			var got cloudstore.DropboxDestinationCredentials
			h := newHarness(t, beforeSlot, func(cfg *Config) {
				cfg.NewDropboxUploader = func(c cloudstore.DropboxDestinationCredentials) (Uploader, error) {
					got = c
					return newDropboxUploader(tc.client, c.FolderPath), nil
				}
			})
			h.store.setOpened(&testDropbox)
			h.store.setSchedule(mondayAt3())
			h.start(t)
			h.clock.waitSleeping(t)
			h.clock.Advance(time.Minute)
			run := waitFinished(t, h)
			if got != testDropbox.Dropbox {
				t.Fatalf("constructor got %v", got)
			}
			if run.Status != tc.wantStatus || run.ObjectKey != tc.wantKey || !strings.HasPrefix(run.ErrorMessage, tc.wantPrefix) {
				t.Fatalf("run = %+v, want %s %q %q", run, tc.wantStatus, tc.wantKey, tc.wantPrefix)
			}
			if len(tc.client.uploads) != 1 || tc.client.uploads[0].key != "/Engram backups/"+testDropboxObject {
				t.Fatalf("uploads = %+v", tc.client.uploads)
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
