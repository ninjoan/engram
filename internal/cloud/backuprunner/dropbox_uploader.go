package backuprunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dropbox"
)

// ErrDropboxFolderPending is the CheckAccess result of a Dropbox destination
// whose credentials work but whose folder does not exist yet. It is not a
// failure: Upload creates the folder with the first archive. It matches
// dropbox.ErrFolderNotFound with errors.Is.
var ErrDropboxFolderPending = fmt.Errorf("backuprunner: the Dropbox folder does not exist yet; it is created on the first upload: %w", dropbox.ErrFolderNotFound)

// DropboxClient is the Dropbox API the Dropbox uploader uses;
// *dropbox.Client satisfies it.
type DropboxClient interface {
	Upload(ctx context.Context, path string, body io.ReadSeeker, size int64) (string, error)
	CheckAccess(ctx context.Context, folder string) error
}

// NewDropboxUploader builds the uploader of an opened Dropbox destination
// over the stdlib Dropbox client; it is the Config.NewDropboxUploader that
// cloud serve wires. It makes no network call, and its errors never echo
// the app secret or the refresh token.
func NewDropboxUploader(creds cloudstore.DropboxDestinationCredentials) (Uploader, error) {
	client, err := dropbox.New(dropbox.Config{AppKey: creds.AppKey, AppSecret: creds.AppSecret, RefreshToken: creds.RefreshToken})
	if err != nil {
		return nil, err
	}
	return newDropboxUploader(client, creds.FolderPath), nil
}

// dropboxUploader stores archives as files inside the destination's folder.
type dropboxUploader struct {
	client DropboxClient
	folder string
}

func newDropboxUploader(client DropboxClient, folder string) Uploader {
	return dropboxUploader{client: client, folder: folder}
}

// Upload stores the archive at "<folder>/<objectName>" and returns the
// Dropbox path of the new file (its path_display, else the path asked for).
// Dropbox errors are returned unchanged: they keep their kind and never
// carry a credential.
func (u dropboxUploader) Upload(ctx context.Context, objectName string, body io.ReadSeeker, size int64) (string, error) {
	path := dropboxFilePath(u.folder, objectName)
	location, err := u.client.Upload(ctx, path, body, size)
	if err != nil {
		return "", err
	}
	if location == "" {
		location = path
	}
	return location, nil
}

// CheckAccess reads the folder's metadata without writing. A missing folder
// is reported as ErrDropboxFolderPending.
func (u dropboxUploader) CheckAccess(ctx context.Context) error {
	err := u.client.CheckAccess(ctx, u.folder)
	if errors.Is(err, dropbox.ErrFolderNotFound) {
		return ErrDropboxFolderPending
	}
	return err
}

// dropboxFilePath joins an absolute Dropbox folder ("/" or "" is the root
// of the app's space) and a file name.
func dropboxFilePath(folder, name string) string {
	return strings.TrimRight(folder, "/") + "/" + name
}
