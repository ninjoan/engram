package gdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxNameBytes = 1024

var fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

type driveFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`
}

// EnsureFolder returns the ID of the folder called name that this app
// created, creating it when absent. With the drive.file scope Drive only
// lists folders the app created, so a folder made by hand is never reused.
// When several match, the oldest wins (Drive allows duplicate names).
func (c *Client) EnsureFolder(ctx context.Context, name string) (folderID string, err error) {
	const op = "EnsureFolder"
	if err := validateName(op, name); err != nil {
		return "", err
	}
	files, err := c.listFolders(ctx, op, name, 100)
	if err != nil {
		return "", err
	}
	if len(files) > 0 {
		return files[0].ID, nil
	}
	meta, _ := json.Marshal(map[string]string{"name": name, "mimeType": FolderMimeType})
	q := url.Values{"supportsAllDrives": {"true"}, "fields": {"id"}}
	resp, err := c.do(ctx, call{
		op:     op,
		method: http.MethodPost,
		url:    c.ep.api + "/files?" + q.Encode(),
		header: http.Header{"Content-Type": {"application/json; charset=UTF-8"}},
		body:   meta,
	}, true)
	if err != nil {
		return "", err
	}
	return parseFileID(op, resp)
}

// CheckAccess proves, without writing anything, that the refresh token still
// works (a fresh access token is always requested) and that Drive answers a
// files.list for the backup folder.
func (c *Client) CheckAccess(ctx context.Context, folderName string) error {
	const op = "CheckAccess"
	if err := validateName(op, folderName); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Kind: err}
	}
	c.tok.invalidate("")
	_, err := c.listFolders(ctx, op, folderName, 1)
	return err
}

// listFolders returns the app's non-trashed folders named exactly name,
// oldest first.
func (c *Client) listFolders(ctx context.Context, op, name string, pageSize int) ([]driveFile, error) {
	q := url.Values{
		"q":                         {fmt.Sprintf("mimeType='%s' and name='%s' and trashed=false", FolderMimeType, escapeQuery(name))},
		"fields":                    {"files(id,name,createdTime)"},
		"orderBy":                   {"createdTime"},
		"pageSize":                  {strconv.Itoa(pageSize)},
		"spaces":                    {"drive"},
		"supportsAllDrives":         {"true"},
		"includeItemsFromAllDrives": {"true"},
	}
	resp, err := c.do(ctx, call{op: op, method: http.MethodGet, url: c.ep.api + "/files?" + q.Encode()}, true)
	if err != nil {
		return nil, err
	}
	var body struct {
		Files []driveFile `json:"files"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		return nil, &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Message: "file list is not JSON"}
	}
	var out []driveFile
	for _, f := range body.Files {
		if f.Name == name && fileIDPattern.MatchString(f.ID) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return createdAt(out[i]).Before(createdAt(out[j])) })
	return out, nil
}

func createdAt(f driveFile) time.Time {
	t, err := time.Parse(time.RFC3339Nano, f.CreatedTime)
	if err != nil {
		return time.Time{}
	}
	return t
}

// escapeQuery escapes a string literal for the Drive query language.
func escapeQuery(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

func validateName(op, name string) error {
	if name == "" || len(name) > maxNameBytes || !utf8.ValidString(name) ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 || strings.TrimSpace(name) == "" {
		return fmt.Errorf("gdrive: %s: %w: name must be 1-%d bytes of printable UTF-8", op, ErrInvalidArgument, maxNameBytes)
	}
	return nil
}

func parseFileID(op string, resp *response) (string, error) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil || !fileIDPattern.MatchString(body.ID) {
		return "", &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Message: "response has no valid file id"}
	}
	return body.ID, nil
}
