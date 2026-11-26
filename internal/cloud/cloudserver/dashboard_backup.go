package cloudserver

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudbackup"
)

// This file implements the dashboard on-demand backup download (cloud
// backups stage 2). It reuses the managed-user surface's authorization gate
// (requireManagedAdmin) and audit path (recordAdminAudit). There is
// deliberately no import/restore route: archives are unsigned, so restore
// stays an operator-only CLI (engram cloud backup import).

// BackupSource is the snapshot surface the dashboard backup download exports
// from. New uses the chunk store when it satisfies BackupSource, as
// *cloudstore.CloudStore does; otherwise the download reports 500.
type BackupSource interface {
	cloudbackup.Source
}

const backupFilenameTimeLayout = "20060102T150405Z"

func backupArchiveFilename(now time.Time) string {
	return "engram-cloud-backup-" + now.UTC().Format(backupFilenameTimeLayout) + ".tar.gz"
}

// handleDashboardBackupDownload handles POST /dashboard/admin/backups/download.
// The backup.download audit row is committed before any archive byte is
// produced; if the audit fails, nothing is exported. The archive streams on
// the request context, so a client disconnect cancels the export.
func (s *CloudServer) handleDashboardBackupDownload(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireManagedAdmin(w, r)
	if !ok {
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	export := s.backupExport
	if export == nil {
		if s.backupSource == nil {
			http.Error(w, "backup source is not configured", http.StatusInternalServerError)
			return
		}
		export = func(ctx context.Context, out io.Writer) error {
			_, err := cloudbackup.Export(ctx, s.backupSource, out, cloudbackup.ExportOptions{EngramVersion: s.version})
			return err
		}
	}
	// The form carries no fields, but the body is capped like every other
	// dashboard mutation POST.
	if !parseDashboardMutationForm(w, r) {
		return
	}
	filename := backupArchiveFilename(time.Now())
	if err := s.recordAdminAudit(r.Context(), store, actor, authAuditActionBackupDownload, "", "", map[string]any{"filename": filename}); err != nil {
		http.Error(w, "record audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := &backupDownloadWriter{w: w, filename: filename}
	if err := export(r.Context(), out); err != nil {
		if !out.started {
			log.Printf("[engram-cloud] backup download failed before streaming: actor=%q: %v", actor.ID, err)
			http.Error(w, "export backup failed", http.StatusInternalServerError)
			return
		}
		// Headers and part of the archive are already on the wire: abort the
		// connection so the client sees a truncated transfer, never success.
		log.Printf("[engram-cloud] backup download aborted mid-stream: actor=%q: %v", actor.ID, err)
		panic(http.ErrAbortHandler)
	}
	if !out.started {
		// A successful export always writes an archive; guard anyway so a
		// success response always carries the attachment headers.
		out.writeHeaders()
	}
}

// handleDashboardBackupDownloadMethodNotAllowed answers GET on the download
// path. Without it, the dashboard's "GET /dashboard/" catch-all would render
// the home page with 200 for a download link that never exports.
func (s *CloudServer) handleDashboardBackupDownloadMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// backupDownloadWriter defers the attachment headers until the first archive
// byte, so a failure before any byte can still answer with a plain 500.
type backupDownloadWriter struct {
	w        http.ResponseWriter
	filename string
	started  bool
}

func (b *backupDownloadWriter) writeHeaders() {
	b.started = true
	header := b.w.Header()
	header.Set("Content-Type", "application/gzip")
	header.Set("Content-Disposition", `attachment; filename="`+b.filename+`"`)
	header.Set("Cache-Control", "no-store")
	b.w.WriteHeader(http.StatusOK)
}

func (b *backupDownloadWriter) Write(p []byte) (int, error) {
	if !b.started {
		b.writeHeaders()
	}
	return b.w.Write(p)
}
