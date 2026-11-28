package backuprunner

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dropbox"
)

const echoedRunnerAccessToken = "sl.ECHOEDRUNNERACCESSTOKEN0987654321"

type echoingDropboxTransport struct {
	mu     sync.Mutex
	paths  []string
	args   []string
	upCode int
	upBody string
}

func (e *echoingDropboxTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	e.mu.Lock()
	e.paths = append(e.paths, r.URL.Host+r.URL.Path)
	e.args = append(e.args, r.Header.Get("Dropbox-API-Arg"))
	e.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	resp := func(code int, s string) *http.Response {
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(s)), Request: r}
	}
	if strings.HasSuffix(r.URL.Path, "/oauth2/token") {
		return resp(200, `{"access_token":"`+echoedRunnerAccessToken+`","token_type":"bearer","expires_in":14400}`), nil
	}
	_ = body
	echo := "auth=" + r.Header.Get("Authorization") + " s=" + testDropboxAppSecret + " r=" + testDropboxRefreshToken
	return resp(e.upCode, strings.ReplaceAll(e.upBody, "{ECHO}", echo)), nil
}

func TestRunnerDropboxUploadWithTheRealClientNeverLeaksEchoedCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		code   int
		body   string
		status string
	}{
		"success":  {200, `{"path_display":"/Engram backups/` + testDropboxObject + `","name":"x"}`, cloudstore.BackupRunStatusSuccess},
		"conflict": {409, `{"error_summary":"path/conflict/file/ {ECHO}"}`, cloudstore.BackupRunStatusFailure},
		"auth":     {401, `{"error_summary":"invalid_access_token/ {ECHO}"}`, cloudstore.BackupRunStatusFailure},
		"text400":  {400, `Error in call to API function: {ECHO}`, cloudstore.BackupRunStatusFailure},
		"space":    {409, `{"error_summary":"path/insufficient_space/ {ECHO}"}`, cloudstore.BackupRunStatusFailure},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &echoingDropboxTransport{upCode: tc.code, upBody: tc.body}
			h := newHarness(t, beforeSlot, func(cfg *Config) {
				cfg.NewDropboxUploader = func(c cloudstore.DropboxDestinationCredentials) (Uploader, error) {
					client, err := dropbox.New(dropbox.Config{AppKey: c.AppKey, AppSecret: c.AppSecret, RefreshToken: c.RefreshToken, HTTPClient: &http.Client{Transport: tr}})
					if err != nil {
						return nil, err
					}
					return newDropboxUploader(client, c.FolderPath), nil
				}
			})
			h.store.setOpened(&testDropbox)
			h.store.setSchedule(mondayAt3())
			h.start(t)
			h.clock.waitSleeping(t)
			h.clock.Advance(time.Minute)
			run := waitFinished(t, h)
			t.Logf("run status=%s key=%q err=%q paths=%v args=%v", run.Status, run.ObjectKey, run.ErrorMessage, tr.paths, tr.args)
			if run.Status != tc.status {
				t.Fatalf("status %s", run.Status)
			}
			if tc.status == cloudstore.BackupRunStatusSuccess && run.ObjectKey != "/Engram backups/"+testDropboxObject {
				t.Fatalf("key %q", run.ObjectKey)
			}
			for _, s := range []string{testDropboxAppSecret, testDropboxRefreshToken, echoedRunnerAccessToken, "ECHOEDRUNNERACCESS"} {
				if strings.Contains(run.ErrorMessage, s) || strings.Contains(h.logs.text(), s) {
					t.Fatalf("leak %q in %q / %s", s, run.ErrorMessage, h.logs.text())
				}
			}
			for _, p := range tr.paths {
				if strings.Contains(p, "delete") || strings.Contains(p, "move") || strings.Contains(p, "permanently") {
					t.Fatalf("destructive endpoint %s", p)
				}
			}
			for _, a := range tr.args {
				if strings.Contains(a, `"overwrite"`) {
					t.Fatalf("overwrite mode %s", a)
				}
			}
			h.assertTempDirEmpty(t)
		})
	}
}
