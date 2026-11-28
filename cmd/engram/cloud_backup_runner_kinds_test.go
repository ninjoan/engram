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

// cloud serve wires only the S3 uploader so far: a stored Dropbox or Google
// Drive destination refuses a manual run without recording one.
func TestBackupRunnerRuntimeRefusesUnwiredDestinationKinds(t *testing.T) {
	for name, put := range map[string]func(context.Context, *cloudstore.CloudStore, *backupcrypto.Sealer) error{
		cloudstore.BackupDestinationKindDropbox: func(ctx context.Context, cs *cloudstore.CloudStore, sealer *backupcrypto.Sealer) error {
			return cs.PutDropboxDestination(ctx, cloudstore.PutDropboxDestinationParams{
				AppKey: "cmdrunnerappkey", FolderPath: "/Engram backups", AppSecret: "cmd-app-secret", RefreshToken: "cmd-refresh-token",
				Actor: cloudstore.BackupDestinationActor{Source: "test"},
			}, sealer)
		},
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
