package backuprunner

import (
	"context"
	"io"
	"sync"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/gdrive"
)

// GDriveClient is the Google Drive API the Google Drive uploader uses;
// *gdrive.Client satisfies it.
type GDriveClient interface {
	EnsureFolder(ctx context.Context, name string) (string, error)
	CheckAccess(ctx context.Context, folderName string) error
	Upload(ctx context.Context, folderID, name string, body io.ReadSeeker, size int64) (string, error)
}

// NewGDriveUploader builds the uploader of an opened, authorized Google
// Drive destination over the stdlib Drive client (drive.file scope); it is
// the Config.NewGDriveUploader that cloud serve wires. It makes no network
// call, and its errors never echo the client secret or the refresh token.
func NewGDriveUploader(creds cloudstore.GDriveDestinationCredentials) (Uploader, error) {
	client, err := gdrive.New(gdrive.Config{ClientID: creds.ClientID, ClientSecret: creds.ClientSecret, RefreshToken: creds.RefreshToken})
	if err != nil {
		return nil, err
	}
	return newGDriveUploader(client, creds.FolderName), nil
}

// gdriveUploader stores archives as files inside the destination's folder,
// a folder this app created in the account's My Drive. The runner builds one
// uploader per run, so the folder is looked up (or created) once per run.
type gdriveUploader struct {
	client GDriveClient
	folder string

	mu       sync.Mutex
	folderID string
}

func newGDriveUploader(client GDriveClient, folder string) Uploader {
	return &gdriveUploader{client: client, folder: folder}
}

// Upload ensures the folder, uploads the archive into it as objectName and
// returns "<folder>/<objectName> (file id <id>)": Drive allows duplicate
// names, so the file id is what identifies the upload. Drive errors are
// returned unchanged: they keep their kind and never carry a credential.
func (u *gdriveUploader) Upload(ctx context.Context, objectName string, body io.ReadSeeker, size int64) (string, error) {
	folderID, err := u.ensureFolder(ctx)
	if err != nil {
		return "", err
	}
	fileID, err := u.client.Upload(ctx, folderID, objectName, body, size)
	if err != nil {
		return "", err
	}
	return u.folder + "/" + objectName + " (file id " + fileID + ")", nil
}

// CheckAccess proves, without writing, that the refresh token works and
// Drive answers a lookup of the folder.
func (u *gdriveUploader) CheckAccess(ctx context.Context) error {
	return u.client.CheckAccess(ctx, u.folder)
}

// ensureFolder returns the folder id, looking it up or creating it on the
// first call; a failed lookup is retried by the next call.
func (u *gdriveUploader) ensureFolder(ctx context.Context) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.folderID != "" {
		return u.folderID, nil
	}
	id, err := u.client.EnsureFolder(ctx, u.folder)
	if err != nil {
		return "", err
	}
	u.folderID = id
	return id, nil
}
