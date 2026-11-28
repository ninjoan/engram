package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// invalidBackupKey is neither valid hex nor valid base64 (its "-not-a-key"
// suffix breaks both), so cloud.ConfigFromEnv reports it as BackupKeyError.
// Its "secretish" tail lets the tests prove errors never echo the key.
const invalidBackupKey = "0123456789abcdef0123456789abcdef-not-a-key-but-secretish"

func backupKeyConfigFromEnv(t *testing.T, value string) cloud.Config {
	t.Helper()
	t.Setenv("ENGRAM_CLOUD_BACKUP_KEY", value)
	return cloud.ConfigFromEnv()
}

func assertInvalidBackupKeyError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an invalid ENGRAM_CLOUD_BACKUP_KEY error, got nil")
	}
	if !errors.Is(err, backupcrypto.ErrInvalidKey) {
		t.Fatalf("error %v does not wrap backupcrypto.ErrInvalidKey", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "refusing to start") || !strings.Contains(msg, "ENGRAM_CLOUD_BACKUP_KEY") {
		t.Fatalf("error %q does not explain the refusal", msg)
	}
	if strings.Contains(err.Error(), invalidBackupKey) || strings.Contains(err.Error(), "secretish") {
		t.Fatalf("error %q echoes the key", err)
	}
}

func TestRunCloudServeRefusesInvalidBackupKeyBeforeListening(t *testing.T) {
	cfg := backupKeyConfigFromEnv(t, invalidBackupKey)
	if cfg.BackupKeyError == nil {
		t.Fatal("fixture key must be reported as invalid by cloud.ConfigFromEnv")
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

	assertInvalidBackupKeyError(t, runCloudServe(cfg))
	if listened || built {
		t.Fatalf("invalid backup key must stop startup before listening (listened=%v) or building the runtime (built=%v)", listened, built)
	}
}

func TestCloudRuntimeBackupOptionsRejectsInvalidBackupKey(t *testing.T) {
	cfg := backupKeyConfigFromEnv(t, invalidBackupKey)
	backups, err := cloudRuntimeBackupOptions(cfg, &cloudstore.CloudStore{})
	assertInvalidBackupKeyError(t, err)
	if backups.options != nil || backups.sealer != nil || backups.runner != nil {
		t.Fatalf("invalid key must yield no backup wiring, got %+v", backups)
	}
}

func TestCloudRuntimeBackupOptionsNewSealerFailureRefusesToStart(t *testing.T) {
	cfg := backupKeyConfigFromEnv(t, hex.EncodeToString([]byte(strings.Repeat("k", backupcrypto.KeySize))))
	original := newCloudBackupSealer
	t.Cleanup(func() { newCloudBackupSealer = original })
	newCloudBackupSealer = func(*backupcrypto.Key) (*backupcrypto.Sealer, error) {
		return nil, fmt.Errorf("backupcrypto: init cipher: %w", backupcrypto.ErrInvalidKey)
	}
	backups, err := cloudRuntimeBackupOptions(cfg, &cloudstore.CloudStore{})
	assertInvalidBackupKeyError(t, err)
	if want := cloudServeBackupKeyError(cloud.Config{BackupKeyError: backupcrypto.ErrInvalidKey}); !strings.HasPrefix(err.Error(), strings.SplitN(want.Error(), "(", 2)[0]) {
		t.Fatalf("NewSealer failure %q does not use the startup refusal wording %q", err, want)
	}
	if backups.options != nil || backups.sealer != nil || backups.runner != nil {
		t.Fatalf("a failed sealer must yield no backup wiring, got %+v", backups)
	}
}

func TestCloudRuntimeBackupOptionsAcceptsValidOrAbsentBackupKey(t *testing.T) {
	for name, value := range map[string]string{
		"valid key":  hex.EncodeToString([]byte(strings.Repeat("k", backupcrypto.KeySize))),
		"absent key": "",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := backupKeyConfigFromEnv(t, value)
			if cfg.BackupKeyError != nil {
				t.Fatalf("fixture key reported invalid: %v", cfg.BackupKeyError)
			}
			if (value != "") != (cfg.BackupKey != nil) {
				t.Fatalf("fixture key parse mismatch: set=%v parsed=%v", value != "", cfg.BackupKey != nil)
			}
			backups, err := cloudRuntimeBackupOptions(cfg, &cloudstore.CloudStore{})
			if err != nil {
				t.Fatalf("cloudRuntimeBackupOptions: %v", err)
			}
			if value == "" {
				// No key: read-only settings, no runner, no "Back up now".
				if len(backups.options) != 1 || backups.sealer != nil || backups.runner != nil {
					t.Fatalf("absent key wiring = %d options, sealer %v, runner %v; want only read-only settings", len(backups.options), backups.sealer != nil, backups.runner != nil)
				}
			} else {
				// A valid key makes the settings writable and starts the runner.
				if len(backups.options) != 2 || backups.sealer == nil || backups.runner == nil {
					t.Fatalf("valid key wiring = %d options, sealer %v, runner %v; want settings with a sealer plus the runner", len(backups.options), backups.sealer != nil, backups.runner != nil)
				}
			}
			if err := cloudServeBackupKeyError(cfg); err != nil {
				t.Fatalf("cloudServeBackupKeyError: %v", err)
			}
		})
	}
}
