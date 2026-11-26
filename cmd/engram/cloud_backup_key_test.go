package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
)

// invalidBackupKey decodes as hex but is not 32 bytes long, so
// cloud.ConfigFromEnv reports it as BackupKeyError.
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
	options, err := cloudRuntimeBackupOptions(cfg, nil)
	assertInvalidBackupKeyError(t, err)
	if options != nil {
		t.Fatalf("invalid key must yield no server options, got %d", len(options))
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
			options, err := cloudRuntimeBackupOptions(cfg, nil)
			if err != nil {
				t.Fatalf("cloudRuntimeBackupOptions: %v", err)
			}
			if len(options) != 1 {
				t.Fatalf("expected the backup settings option, got %d options", len(options))
			}
			if err := cloudServeBackupKeyError(cfg); err != nil {
				t.Fatalf("cloudServeBackupKeyError: %v", err)
			}
		})
	}
}
