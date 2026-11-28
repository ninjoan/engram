package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backuprunner"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// cloud serve wires every uploader; a Google Drive destination still pending
// its "Connect with Google" authorization starts a manual run that is
// recorded as skipped, never uploaded.
func TestBackupRunnerRuntimeSkipsAPendingGDriveDestination(t *testing.T) {
	ctx := context.Background()
	cs, _ := openCloudBackupRunnerStore(t)
	cfg := backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey)
	t.Setenv("TMPDIR", t.TempDir())
	sealer, err := backupcrypto.NewSealer(cfg.BackupKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.PutGDriveDestination(ctx, cloudstore.PutGDriveDestinationParams{
		ClientID: "cmd.apps.googleusercontent.com", FolderName: "Engram backups", ClientSecret: "cmd-client-secret",
		Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}, sealer); err != nil {
		t.Fatalf("store the gdrive destination: %v", err)
	}
	runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
	if err != nil {
		t.Fatalf("assembleCloudRuntime: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.backups.Start(runCtx)
	t.Cleanup(func() { cancel(); runtime.backups.Wait() })

	if _, err := runtime.backups.StartManualBackup(ctx, ""); err != nil {
		t.Fatalf("manual run of a pending gdrive destination: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		runs, err := cs.ListBackupRuns(ctx, 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning {
			if runs[0].Status != cloudstore.BackupRunStatusFailure || runs[0].ErrorMessage != backuprunner.SkippedNotAuthorizedMessage {
				t.Fatalf("run = %+v, want skipped %q", runs[0], backuprunner.SkippedNotAuthorizedMessage)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runs = %+v, want one finished run", runs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The runner config of cloud serve wires the Dropbox and Google Drive
// uploaders, both built without any network call.
func TestBackupRunnerConfigWiresTheKindUploaders(t *testing.T) {
	sealer, err := backupcrypto.NewSealer(backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey).BackupKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cloudBackupRunnerConfig(nil, sealer)
	if cfg.NewS3Client == nil || cfg.NewDropboxUploader == nil || cfg.NewGDriveUploader == nil || cfg.Key == nil || cfg.EngramVersion != version {
		t.Fatalf("runner config = %+v", cfg)
	}
	uploader, err := cfg.NewDropboxUploader(cloudstore.DropboxDestinationCredentials{AppKey: "cmdrunnerappkey", FolderPath: "/Engram backups", AppSecret: "cmd-app-secret", RefreshToken: "cmd-refresh-token"})
	if err != nil || uploader == nil {
		t.Fatalf("NewDropboxUploader = %v, %v", uploader, err)
	}
	gdriveUploader, err := cfg.NewGDriveUploader(cloudstore.GDriveDestinationCredentials{ClientID: "cmd.apps.googleusercontent.com", FolderName: "Engram backups", ClientSecret: "cmd-client-secret", RefreshToken: "cmd-refresh-token"})
	if err != nil || gdriveUploader == nil {
		t.Fatalf("NewGDriveUploader = %v, %v", gdriveUploader, err)
	}
}

// S15: an invalid ENGRAM_CLOUD_PUBLIC_URL stops cloud serve before it
// listens or builds the runtime, and the refusal names the variable.
func TestRunCloudServeRefusesInvalidPublicURLBeforeListening(t *testing.T) {
	t.Setenv("ENGRAM_CLOUD_PUBLIC_URL", "http://engram.example.com/dashboard")
	cfg := cloud.ConfigFromEnv()
	if !errors.Is(cfg.PublicURLError, cloud.ErrInvalidPublicURL) {
		t.Fatalf("fixture URL must be invalid, got %v", cfg.PublicURLError)
	}
	cfg.Port = 0
	original := listenCloudDuringStartup
	t.Cleanup(func() { listenCloudDuringStartup = original })
	listened := false
	listenCloudDuringStartup = func(network, _ string) (net.Listener, error) {
		listened = true
		return net.Listen(network, "127.0.0.1:0")
	}
	built := false
	stubCloudStartupRuntime(t, func(context.Context, cloud.Config) (cloudServerRuntime, error) {
		built = true
		return nil, errors.New("runtime must not be built")
	})
	err := runCloudServe(cfg)
	if !errors.Is(err, cloud.ErrInvalidPublicURL) || !strings.Contains(err.Error(), "refusing to start") || listened || built {
		t.Fatalf("runCloudServe = %v (listened %v built %v), want an ENGRAM_CLOUD_PUBLIC_URL refusal before listening", err, listened, built)
	}
	if _, err := cloudRuntimeBackupOptions(cfg, &cloudstore.CloudStore{}); !errors.Is(err, cloud.ErrInvalidPublicURL) {
		t.Fatalf("cloudRuntimeBackupOptions = %v, want the public URL refusal", err)
	}
}
