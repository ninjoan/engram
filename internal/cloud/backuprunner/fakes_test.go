package backuprunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const (
	testAccessKeyID = "AKIARUNNERTEST0001"
	testSecretKey   = "runner-secret-access-key-do-not-leak"
)

var testCreds = cloudstore.BackupDestinationCredentials{
	Endpoint: "https://acct.r2.example.test", Region: "auto", Bucket: "engram-backups", Prefix: "prod/nightly",
	AccessKeyID: testAccessKeyID, SecretAccessKey: testSecretKey,
}

// fakeClock is a manual clock: After registers a waiter that fires once
// Advance moves the time to or past its deadline.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeWaiter
}

type fakeWaiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, fakeWaiter{at: c.now.Add(d), ch: ch})
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
			continue
		}
		kept = append(kept, w)
	}
	c.waiters = kept
}

func (c *fakeClock) pending() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Time, 0, len(c.waiters))
	for _, w := range c.waiters {
		out = append(out, w.at)
	}
	return out
}

// waitSleeping waits until the scheduler loop sleeps on the clock and
// returns the instant it will wake.
func (c *fakeClock) waitSleeping(t *testing.T) time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := c.pending(); len(p) > 0 {
			return p[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scheduler loop never went to sleep")
	return time.Time{}
}

// fakeStore is an in-memory run history with the uniqueness and refusal
// rules of cloudstore. Finished error messages are sanitized with the real
// cloudstore.SanitizeBackupRunError, as FinishBackupRun does.
type fakeStore struct {
	mu          sync.Mutex
	schedule    cloudstore.BackupSchedule
	scheduleErr error
	creds       cloudstore.BackupDestinationCredentials
	credsErr    error
	runs        []cloudstore.BackupRun
	redacts     map[int64][]string
	expireCalls []time.Duration
	nextID      int64
	opener      cloudstore.BackupSecretOpener
	// calls records expire, start and finish calls in call order.
	calls []string
	// startFailures makes StartBackupRun fail this many times before it
	// records a run; negative fails every time.
	startFailures int
	// startHook runs after a run is recorded; an error it returns is
	// returned with the row kept, like a commit whose reply is lost.
	startHook func(ctx context.Context) error
	// finishFailures makes FinishBackupRun fail this many times; negative
	// fails every time.
	finishFailures int
}

var errStoreUnavailable = errors.New("fake store: connection reset by peer")

func newFakeStore() *fakeStore {
	return &fakeStore{creds: testCreds, redacts: map[int64][]string{}}
}

func (s *fakeStore) setSchedule(sched cloudstore.BackupSchedule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedule = sched
}

func (s *fakeStore) setCredsErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credsErr = err
}

func (s *fakeStore) setScheduleErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scheduleErr = err
}

func (s *fakeStore) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeStore) countCalls(name string) int {
	n := 0
	for _, c := range s.callLog() {
		if c == name {
			n++
		}
	}
	return n
}

func (s *fakeStore) GetBackupSchedule(context.Context) (cloudstore.BackupSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.schedule, s.scheduleErr
}

func (s *fakeStore) OpenBackupDestinationCredentials(_ context.Context, opener cloudstore.BackupSecretOpener) (cloudstore.BackupDestinationCredentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opener = opener
	if s.credsErr != nil {
		return cloudstore.BackupDestinationCredentials{}, s.credsErr
	}
	return s.creds, nil
}

func (s *fakeStore) StartBackupRun(ctx context.Context, params cloudstore.StartBackupRunParams) (cloudstore.BackupRun, error) {
	run, err := s.startBackupRun(params)
	if err != nil {
		return run, err
	}
	s.mu.Lock()
	hook := s.startHook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return cloudstore.BackupRun{}, err
		}
	}
	return run, nil
}

func (s *fakeStore) startBackupRun(params cloudstore.StartBackupRunParams) (cloudstore.BackupRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "start")
	if s.startFailures != 0 {
		if s.startFailures > 0 {
			s.startFailures--
		}
		return cloudstore.BackupRun{}, errStoreUnavailable
	}
	for _, run := range s.runs {
		if params.Trigger == cloudstore.BackupRunTriggerScheduled && run.Trigger == cloudstore.BackupRunTriggerScheduled && run.ScheduledFor.Equal(params.ScheduledFor) {
			return cloudstore.BackupRun{}, cloudstore.ErrBackupRunAlreadyRecorded
		}
		if params.RefuseIfRunning && run.Status == cloudstore.BackupRunStatusRunning {
			return cloudstore.BackupRun{}, cloudstore.ErrBackupRunInProgress
		}
	}
	s.nextID++
	run := cloudstore.BackupRun{ID: s.nextID, Trigger: params.Trigger, ScheduledFor: params.ScheduledFor, StartedAt: time.Now(), Status: cloudstore.BackupRunStatusRunning, ActorPrincipalID: params.ActorPrincipalID}
	s.runs = append(s.runs, run)
	return run, nil
}

func (s *fakeStore) FinishBackupRun(_ context.Context, params cloudstore.FinishBackupRunParams) (cloudstore.BackupRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "finish")
	if s.finishFailures != 0 {
		if s.finishFailures > 0 {
			s.finishFailures--
		}
		return cloudstore.BackupRun{}, errStoreUnavailable
	}
	for i, run := range s.runs {
		if run.ID != params.ID {
			continue
		}
		if run.Status != cloudstore.BackupRunStatusRunning {
			return cloudstore.BackupRun{}, cloudstore.ErrBackupRunNotRunning
		}
		run.Status, run.FinishedAt = params.Status, time.Now()
		if params.Status == cloudstore.BackupRunStatusSuccess {
			run.ObjectKey, run.SizeBytes = params.ObjectKey, params.SizeBytes
		} else {
			run.ErrorMessage = cloudstore.SanitizeBackupRunError(params.ErrorMessage, params.Redact...)
		}
		s.redacts[run.ID] = append([]string(nil), params.Redact...)
		s.runs[i] = run
		return run, nil
	}
	return cloudstore.BackupRun{}, cloudstore.ErrBackupRunNotRunning
}

func (s *fakeStore) ExpireStaleBackupRuns(_ context.Context, olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireCalls = append(s.expireCalls, olderThan)
	s.calls = append(s.calls, "expire")
	return 0, nil
}

func (s *fakeStore) ReadBackupSnapshot(context.Context, func(*cloudstore.BackupReader) error) error {
	return errors.New("fake store has no snapshot; inject Config.Export")
}

func (s *fakeStore) snapshot() []cloudstore.BackupRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]cloudstore.BackupRun(nil), s.runs...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *fakeStore) expireCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.expireCalls)
}

// fakeUploader records every PutObject. block, when set, runs before the
// upload is recorded and may return an error.
type fakeUploader struct {
	mu      sync.Mutex
	puts    []fakePut
	err     error
	block   func(ctx context.Context) error
	tempDir string
}

type fakePut struct {
	key, contentType string
	size             int64
	body             []byte
	deadline         time.Duration
	tempFiles        int
}

func (u *fakeUploader) PutObject(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	put := fakePut{key: key, contentType: contentType, size: size, body: data}
	if d, ok := ctx.Deadline(); ok {
		put.deadline = time.Until(d)
	}
	if u.tempDir != "" {
		entries, _ := os.ReadDir(u.tempDir)
		put.tempFiles = len(entries)
	}
	if u.block != nil {
		if err := u.block(ctx); err != nil {
			return err
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.puts = append(u.puts, put)
	return u.err
}

func (u *fakeUploader) snapshot() []fakePut {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]fakePut(nil), u.puts...)
}

// fakeOpener stands in for the backup key; the fake store never calls it.
type fakeOpener struct{}

func (fakeOpener) Open(string, string) ([]byte, error) { return nil, errors.New("not used") }

// logSink collects log lines so tests can assert they hold no credentials.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var archiveBytes = []byte("\x1f\x8b fake gzip archive bytes")

func writeArchive(_ context.Context, w io.Writer) error {
	_, err := io.Copy(w, bytes.NewReader(archiveBytes))
	return err
}

type harness struct {
	store    *fakeStore
	uploader *fakeUploader
	clock    *fakeClock
	logs     *logSink
	tempDir  string
	runner   *Runner
	cancel   context.CancelFunc
}

// newHarness builds a runner over fakes; mutate cfg before it is built.
func newHarness(t *testing.T, start time.Time, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{store: newFakeStore(), clock: newFakeClock(start), logs: &logSink{}, tempDir: t.TempDir()}
	h.uploader = &fakeUploader{tempDir: h.tempDir}
	cfg := Config{
		Store:       h.store,
		Key:         fakeOpener{},
		Clock:       h.clock,
		TempDir:     h.tempDir,
		Export:      writeArchive,
		NewUploader: func(cloudstore.BackupDestinationCredentials) (Uploader, error) { return h.uploader, nil },
		Logf:        h.logs.Logf,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.runner = runner
	return h
}

func (h *harness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.runner.Start(ctx)
	t.Cleanup(func() {
		cancel()
		waitDone(t, "runner shutdown", h.runner.Wait)
	})
}

func waitDone(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish", what)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) assertTempDirEmpty(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(h.tempDir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temp files left behind: %v", names)
	}
}

func (h *harness) assertNoSecretsLogged(t *testing.T) {
	t.Helper()
	logs := h.logs.text()
	for _, secret := range []string{testAccessKeyID, testSecretKey} {
		if strings.Contains(logs, secret) {
			t.Fatalf("logs leak a credential: %s", logs)
		}
	}
}
