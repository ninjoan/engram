package cloudserver

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
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

// Reason codes of a failed backup.download.complete audit event.
const (
	backupDownloadReasonExportFailed   = "export_failed"
	backupDownloadReasonStreamAborted  = "stream_aborted"
	backupDownloadReasonClientCanceled = "client_canceled"
)

func backupArchiveFilename(now time.Time) string {
	return "engram-cloud-backup-" + now.UTC().Format(backupFilenameTimeLayout) + ".tar.gz"
}

// backupDownloadCompletionAuditTimeout bounds the completion audit insert,
// which runs detached from the (possibly canceled) request context.
const backupDownloadCompletionAuditTimeout = 10 * time.Second

// handleDashboardBackupDownload handles POST /dashboard/admin/backups/download.
// A backup.download audit row with outcome "started" is committed before any
// archive byte is produced; if it fails, nothing is exported. After the export
// a backup.download.complete row records the result: "success" with the bytes
// written, or "failure" with a reason code. The archive streams on the
// request context, so a client disconnect cancels the export.
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
	started := adminAuditEvent(actor, authAuditActionBackupDownload, "", "", map[string]any{"filename": filename})
	started.Outcome = authAuditOutcomeStarted
	if err := store.InsertAuthAuditEvent(r.Context(), started); err != nil {
		log.Printf("[engram-cloud] backup download audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	out := &backupDownloadWriter{w: w, filename: filename}
	exportErr := export(r.Context(), out)
	reason := backupDownloadFailureReason(r.Context(), exportErr, out.started)
	if exportErr == nil && !out.started {
		// Even an empty export answers with the attachment headers, so a
		// success response always looks like a download.
		out.writeHeaders()
	}
	s.recordBackupDownloadCompletion(r.Context(), store, actor, filename, out.written, reason)
	if exportErr == nil {
		return
	}
	if !out.started {
		log.Printf("[engram-cloud] backup download failed before streaming: actor=%q: %v", actor.ID, exportErr)
		http.Error(w, "export backup failed", http.StatusInternalServerError)
		return
	}
	// Headers and part of the archive are already on the wire: abort the
	// connection so the client sees a truncated transfer, never success.
	log.Printf("[engram-cloud] backup download aborted mid-stream: actor=%q: %v", actor.ID, exportErr)
	panic(http.ErrAbortHandler)
}

// backupDownloadFailureReason classifies the export result. A canceled
// request is a client cancel even when the exporter reported no error, since
// the archive may not have reached the client. "" means success.
func backupDownloadFailureReason(ctx context.Context, exportErr error, started bool) string {
	switch {
	case ctx.Err() != nil:
		return backupDownloadReasonClientCanceled
	case exportErr == nil:
		return ""
	case !started:
		return backupDownloadReasonExportFailed
	default:
		return backupDownloadReasonStreamAborted
	}
}

// recordBackupDownloadCompletion appends the backup.download.complete row.
// It runs after the response is decided, so a failure is logged, never
// surfaced. The metadata carries no error text, which could leak internals.
func (s *CloudServer) recordBackupDownloadCompletion(ctx context.Context, store AdminIdentityStore, actor cloudauth.Principal, filename string, written int64, reason string) {
	event := adminAuditEvent(actor, authAuditActionBackupDownloadComplete, "", "", map[string]any{"filename": filename, "bytes": written})
	if reason != "" {
		event.Outcome = authAuditOutcomeFailure
		event.ReasonCode = reason
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backupDownloadCompletionAuditTimeout)
	defer cancel()
	if err := store.InsertAuthAuditEvent(auditCtx, event); err != nil {
		log.Printf("[engram-cloud] backup download completion audit failed: actor=%q outcome=%s reason=%s: %v", actor.ID, event.Outcome, reason, err)
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
	written  int64
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
	n, err := b.w.Write(p)
	b.written += int64(n)
	return n, err
}
