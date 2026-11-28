package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backuprunner"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// cloud serve wires the S3 and Dropbox uploaders; Google Drive is not wired
// yet: a stored Google Drive destination refuses a manual run without
// recording one.
func TestBackupRunnerRuntimeRefusesUnwiredDestinationKinds(t *testing.T) {
	for name, put := range map[string]func(context.Context, *cloudstore.CloudStore, *backupcrypto.Sealer) error{
		cloudstore.BackupDestinationKindGDrive: func(ctx context.Context, cs *cloudstore.CloudStore, sealer *backupcrypto.Sealer) error {
			return cs.PutGDriveDestination(ctx, cloudstore.PutGDriveDestinationParams{
				ClientID: "cmd.apps.googleusercontent.com", FolderName: "Engram backups", ClientSecret: "cmd-client-secret",
				Actor: cloudstore.BackupDestinationActor{Source: "test"},
			}, sealer)
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cs, _ := openCloudBackupRunnerStore(t)
			cfg := backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey)
			t.Setenv("TMPDIR", t.TempDir())
			sealer, err := backupcrypto.NewSealer(cfg.BackupKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := put(ctx, cs, sealer); err != nil {
				t.Fatalf("store the %s destination: %v", name, err)
			}
			runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
			if err != nil {
				t.Fatalf("assembleCloudRuntime: %v", err)
			}
			runCtx, cancel := context.WithCancel(ctx)
			runtime.backups.Start(runCtx)
			t.Cleanup(func() { cancel(); runtime.backups.Wait() })

			_, err = runtime.backups.StartManualBackup(ctx, "")
			if !errors.Is(err, cloudserver.ErrBackupDestinationUnsupported) || !strings.Contains(err.Error(), name+" destination is not supported by this server yet") {
				t.Fatalf("manual run error = %v, want %v", err, cloudserver.ErrBackupDestinationUnsupported)
			}
			if !strings.HasPrefix(backuprunner.SkippedUnsupportedMessage(name), "skipped: ") {
				t.Fatalf("skipped message = %q", backuprunner.SkippedUnsupportedMessage(name))
			}
			runs, err := cs.ListBackupRuns(ctx, 5)
			if err != nil || len(runs) != 0 {
				t.Fatalf("runs = %+v, %v; want none", runs, err)
			}
		})
	}
}

// The runner config of cloud serve wires the Dropbox uploader (built
// without any network call) and leaves Google Drive unwired until its OAuth
// flow exists.
func TestBackupRunnerConfigWiresTheDropboxUploader(t *testing.T) {
	sealer, err := backupcrypto.NewSealer(backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey).BackupKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cloudBackupRunnerConfig(nil, sealer)
	if cfg.NewS3Client == nil || cfg.NewDropboxUploader == nil || cfg.NewGDriveUploader != nil || cfg.Key == nil || cfg.EngramVersion != version {
		t.Fatalf("runner config = %+v", cfg)
	}
	uploader, err := cfg.NewDropboxUploader(cloudstore.DropboxDestinationCredentials{AppKey: "cmdrunnerappkey", FolderPath: "/Engram backups", AppSecret: "cmd-app-secret", RefreshToken: "cmd-refresh-token"})
	if err != nil || uploader == nil {
		t.Fatalf("NewDropboxUploader = %v, %v", uploader, err)
	}
}
