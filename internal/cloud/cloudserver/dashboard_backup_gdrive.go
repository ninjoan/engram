package cloudserver

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dashboard"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/gdrive"
)

// Google Drive destination: settings, "Connect with Google" and its OAuth
// callback, and the connection test.
//
// The admin saves an OAuth client (client id, client secret, folder) like
// any destination (kind=gdrive on the save route); it is stored pending
// authorization. POST .../gdrive/connect (session, same-origin, managed
// admin) stores a single-use state bound to this admin and to the
// destination, with the PKCE verifier sealed by the backup key, audits
// backup.destination.authorize_start and redirects to Google's consent
// screen asking only for the drive.file scope. Google sends the browser back
// to GET .../gdrive/callback, a top-level cross-site GET: it has no
// same-origin check (SameSite=Lax cookies are sent on it) but needs a
// managed admin session, consumes the state once, exchanges the code with
// the stored client secret and the verifier, and stores the refresh token
// (sealed and audited by cloudstore). The redirect URI is always
// ENGRAM_CLOUD_PUBLIC_URL + backupGDriveCallbackPath, never built from Host
// or X-Forwarded headers. The authorization code, the state, the verifier
// and the tokens never reach a log line, an audit row, a URL Engram
// redirects to or the page.

const (
	backupGDriveCallbackPath = "/dashboard/admin/backups/gdrive/callback"
	// backupGDriveExchangeTimeout bounds the authorization code exchange.
	backupGDriveExchangeTimeout = 30 * time.Second
	// backupGDriveStoreTimeout bounds storing the refresh token; it runs
	// without the request's cancellation, because the code is already spent.
	backupGDriveStoreTimeout = 10 * time.Second

	// Reason codes of a failed Google Drive test or authorization.
	backupReasonNotAuthorized      = "not_authorized"
	backupReasonExchangeFailed     = "exchange_failed"
	backupReasonScope              = "scope"
	backupReasonNoRefreshToken     = "no_refresh_token"
	backupReasonDestinationChanged = "destination_changed"
)

// backupGDriveNotices are the fixed notices of the Google Drive routes,
// selected by the notice query parameter like backupNotices.
var backupGDriveNotices = map[string]dashboard.BackupsNotice{
	"gdrive-connected":     {Kind: "success", Title: "Google Drive connected.", Message: "Engram stored the authorization encrypted. Press Test connection to check the folder; scheduled backups now upload to Google Drive.", Destination: true},
	"gdrive-denied":        {Kind: "danger", Title: "Google access not granted.", Message: "Google reported that access was denied, so nothing was stored. Press Connect with Google and choose Allow.", Destination: true},
	"gdrive-error":         {Kind: "danger", Title: "Google did not complete the authorization.", Message: "Nothing was stored. Press Connect with Google to try again.", Destination: true},
	"gdrive-expired":       {Kind: "danger", Title: "Authorization link expired or already used.", Message: "Each Connect with Google link works once, for 10 minutes, for the admin who opened it. Nothing was stored; press Connect with Google again.", Destination: true},
	"gdrive-mismatch":      {Kind: "danger", Title: "Authorization does not match.", Message: "It was started by another admin, or the Google Drive settings changed since. Nothing was stored; press Connect with Google again.", Destination: true},
	"gdrive-key":           {Kind: "danger", Title: "Authorization cannot be completed.", Message: "The stored settings cannot be opened with the current ENGRAM_CLOUD_BACKUP_KEY. Save the Google Drive settings again, then connect.", Destination: true},
	"gdrive-exchange":      {Kind: "danger", Title: "Google refused the authorization.", Message: "The authorization code could not be exchanged (or Google was unreachable): check the client secret and that the redirect URI shown in the form is registered exactly, then connect again. Nothing was stored.", Destination: true},
	"gdrive-scope":         {Kind: "danger", Title: "Wrong access granted.", Message: "Google granted access other than the drive.file scope Engram asks for. Nothing was stored; connect again and allow only the requested access.", Destination: true},
	"gdrive-no-refresh":    {Kind: "danger", Title: "No refresh token.", Message: "Google issued no refresh token. Remove Engram's access at https://myaccount.google.com/permissions, then connect again. Nothing was stored.", Destination: true},
	"gdrive-no-public-url": {Kind: "danger", Title: "Set ENGRAM_CLOUD_PUBLIC_URL.", Message: "Connect with Google needs the dashboard's public https address in ENGRAM_CLOUD_PUBLIC_URL, from which the redirect URI is built. Set it and restart engram cloud serve.", Destination: true},
	"gdrive-not-saved":     {Kind: "danger", Title: "No Google Drive settings.", Message: "Save the Google Drive settings first, then press Connect with Google.", Destination: true},
	"gdrive-test-ok":       {Kind: "success", Title: "Connected.", Message: "Connection test passed: Google Drive accepted the stored authorization and answered for the folder.", Destination: true},
	"gdrive-test-auth":     {Kind: "danger", Title: "Authorization rejected.", Message: "Connection test failed: Google refused the stored authorization (revoked, expired or not limited to drive.file). Press Reconnect with Google.", Destination: true},
	"gdrive-test-network":  {Kind: "danger", Title: "Google Drive unreachable.", Message: "Connection test failed: Google Drive could not be reached (network error or timeout).", Destination: true},
	"gdrive-test-error":    {Kind: "danger", Title: "Unexpected response.", Message: "Connection test failed: Google Drive returned an unexpected response.", Destination: true},
	"gdrive-test-pending":  {Kind: "danger", Title: "Not connected yet.", Message: "Press Connect with Google before testing; nothing was checked.", Destination: true},
}

// backupGDriveCheckNotice answers a check-before-save of a Google Drive form:
// there is nothing to check before Google authorizes Engram.
var backupGDriveCheckNotice = dashboard.BackupsNotice{Kind: "danger", Title: "Nothing was checked.", Message: "Google Drive cannot be checked before it is authorized: save these settings, press Connect with Google, then Test connection.", Destination: true}

// WithPublicURL sets the dashboard's public origin (ENGRAM_CLOUD_PUBLIC_URL,
// already validated by cloud.ConfigFromEnv). It is the only base of the
// Google Drive OAuth redirect URI; empty disables Connect with Google.
func WithPublicURL(origin string) Option {
	return func(s *CloudServer) {
		s.publicURL = strings.TrimRight(strings.TrimSpace(origin), "/")
	}
}

// gdriveRedirectURI is the OAuth redirect URI registered with Google; empty
// without a public URL.
func (s *CloudServer) gdriveRedirectURI() string {
	if s.publicURL == "" {
		return ""
	}
	return s.publicURL + backupGDriveCallbackPath
}

// backupNotice selects a fixed notice by its query parameter value.
func backupNotice(key string) dashboard.BackupsNotice {
	if notice, ok := backupNotices[key]; ok {
		return notice
	}
	return backupGDriveNotices[key]
}

// setGDriveNoStoreHeaders keeps the Google Drive flow's responses out of
// caches and Referer headers.
func setGDriveNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// gdriveAuditMetadata is the non-secret description of a Google Drive
// destination in an audit row: kind, folder and client id hint, and the
// result when there is one.
func gdriveAuditMetadata(clientID, folder, result string) map[string]any {
	metadata := map[string]any{"kind": cloudstore.BackupDestinationKindGDrive, "folder_name": folder, "client_id_hint": backupClientIDHint(clientID)}
	if result != "" {
		metadata["result"] = result
	}
	return metadata
}

// saveGDriveDestination saves a kind=gdrive form. The client secret is
// required on every save; the store seals it bound to the client id and
// folder and audits backup.destination.update in the same transaction. The
// destination is pending authorization until Connect with Google. A refusal
// re-renders the client id and the folder only.
func (s *CloudServer) saveGDriveDestination(w http.ResponseWriter, r *http.Request, actor cloudauth.Principal) {
	params := gdriveDestinationFormParams(r, actor)
	err := s.backupSettings.PutGDriveDestination(r.Context(), params, s.backupKey)
	switch {
	case err == nil:
		redirectDashboardAdmin(w, r, backupsPageURL+"?notice=destination-saved")
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		reason := backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		form := dashboard.BackupGDriveForm{Submitted: true, ClientID: params.ClientID, FolderName: params.FolderName, Field: backupGDriveInvalidField(reason), Error: reason}
		s.renderBackupsPageWithGDrive(w, r, http.StatusBadRequest, dashboard.BackupsNotice{Kind: "danger", Message: "Destination not saved: " + reason + ".", Destination: true}, form)
	default:
		log.Printf("[engram-cloud] save Google Drive backup destination failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "save backup destination failed", http.StatusInternalServerError)
	}
}

// refuseGDriveCheck answers the check route for a kind=gdrive form: Google
// cannot be asked before it authorizes Engram, so nothing is sent, stored or
// audited. The fields are validated with the save's rules
// (cloudstore.ValidateGDriveDestination) so the re-rendered form already
// marks a field the save would refuse.
func (s *CloudServer) refuseGDriveCheck(w http.ResponseWriter, r *http.Request, actor cloudauth.Principal) {
	params := gdriveDestinationFormParams(r, actor)
	form := dashboard.BackupGDriveForm{Submitted: true, ClientID: params.ClientID, FolderName: params.FolderName}
	if _, err := cloudstore.ValidateGDriveDestination(params); errors.Is(err, cloudstore.ErrInvalidBackupDestination) {
		form.Error = backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		form.Field = backupGDriveInvalidField(form.Error)
	}
	s.renderBackupsPageWithGDrive(w, r, http.StatusBadRequest, backupGDriveCheckNotice, form)
}

// gdriveDestinationFormParams reads a Google Drive destination from the
// POST form (url-encoded body fields only).
func gdriveDestinationFormParams(r *http.Request, actor cloudauth.Principal) cloudstore.PutGDriveDestinationParams {
	return cloudstore.PutGDriveDestinationParams{
		ClientID:     r.PostForm.Get("client_id"),
		FolderName:   r.PostForm.Get("folder"),
		ClientSecret: r.PostForm.Get("client_secret"),
		Actor:        backupStoreActor(actor),
	}
}

// backupGDriveInvalidField maps a Google Drive validation reason to the form
// field it is about; "" when it names none.
func backupGDriveInvalidField(reason string) string {
	for _, field := range []struct{ prefix, name string }{
		{"client id ", "client_id"},
		{"client secret ", "client_secret"},
		{"folder name ", "folder"},
	} {
		if strings.HasPrefix(reason, field.prefix) {
			return field.name
		}
	}
	return ""
}

// renderBackupsPageWithGDrive renders the page with the Google Drive form
// re-rendered from form, which never carries the client secret.
func (s *CloudServer) renderBackupsPageWithGDrive(w http.ResponseWriter, r *http.Request, status int, notice dashboard.BackupsNotice, form dashboard.BackupGDriveForm) {
	view := s.backupsPageView(r)
	view.StorageKind = cloudstore.BackupDestinationKindGDrive
	view.GDriveForm = form
	s.renderBackupsPageView(w, r, status, view, notice)
}

// testGDriveDestination runs the connection test of an opened Google Drive
// destination: a pending one is reported without reaching Google.
func (s *CloudServer) testGDriveDestination(ctx context.Context, creds cloudstore.GDriveDestinationCredentials) (string, string) {
	if !creds.Authorized() {
		return "pending", backupReasonNotAuthorized
	}
	return classifyGDriveConnectionTest(s.runGDriveCheck(ctx, creds))
}

// runGDriveCheck runs the Drive access check bounded like the S3 one.
func (s *CloudServer) runGDriveCheck(ctx context.Context, creds cloudstore.GDriveDestinationCredentials) error {
	ctx, cancel := context.WithTimeout(ctx, backupConnectionTestTimeout)
	defer cancel()
	if s.backupCheckGDrive != nil {
		return s.backupCheckGDrive(ctx, creds)
	}
	client, err := gdrive.New(gdrive.Config{ClientID: creds.ClientID, ClientSecret: creds.ClientSecret, RefreshToken: creds.RefreshToken, HTTPClient: s.backupGDriveHTTPClient})
	if err != nil {
		return err
	}
	return client.CheckAccess(ctx, creds.FolderName)
}

// classifyGDriveConnectionTest maps a Drive access check to a result and a
// failure reason code ("" for success).
func classifyGDriveConnectionTest(err error) (string, string) {
	switch {
	case err == nil:
		return "ok", ""
	case errors.Is(err, gdrive.ErrAuth), errors.Is(err, gdrive.ErrScope), errors.Is(err, gdrive.ErrNoRefreshToken):
		return "auth", backupReasonAuthFailed
	case errors.Is(err, gdrive.ErrNetwork), errors.Is(err, gdrive.ErrUploadStalled), errors.Is(err, context.DeadlineExceeded):
		return "network", backupReasonNetwork
	default:
		return "error", backupReasonUnexpectedResponse
	}
}

// handleDashboardConnectGDrive handles POST
// /dashboard/admin/backups/gdrive/connect: it starts the authorization of
// the stored Google Drive destination and redirects to Google's consent
// screen.
func (s *CloudServer) handleDashboardConnectGDrive(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, true)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	setGDriveNoStoreHeaders(w)
	redirectURI := s.gdriveRedirectURI()
	if redirectURI == "" {
		s.renderBackupsPage(w, r, http.StatusConflict, backupGDriveNotices["gdrive-no-public-url"])
		return
	}
	ctx := r.Context()
	destination, err := s.backupSettings.GetBackupDestination(ctx)
	if err != nil {
		log.Printf("[engram-cloud] connect Google Drive failed to read the destination: actor=%q: %v", actor.ID, err)
		http.Error(w, "connect Google Drive failed", http.StatusInternalServerError)
		return
	}
	if !destination.Configured || destination.Kind != cloudstore.BackupDestinationKindGDrive {
		s.renderBackupsPage(w, r, http.StatusConflict, backupGDriveNotices["gdrive-not-saved"])
		return
	}
	verifier, challenge, err := gdrive.NewPKCE()
	if err != nil {
		log.Printf("[engram-cloud] connect Google Drive failed to create PKCE: actor=%q", actor.ID)
		http.Error(w, "connect Google Drive failed", http.StatusInternalServerError)
		return
	}
	state, err := s.backupSettings.CreateBackupOAuthState(ctx, s.backupKey, strings.TrimSpace(actor.ID), verifier)
	switch {
	case errors.Is(err, cloudstore.ErrBackupDestinationNotConfigured), errors.Is(err, cloudstore.ErrBackupDestinationKindMismatch):
		s.renderBackupsPage(w, r, http.StatusConflict, backupGDriveNotices["gdrive-not-saved"])
		return
	case err != nil:
		log.Printf("[engram-cloud] connect Google Drive failed to store the authorization state: actor=%q: %v", actor.ID, err)
		http.Error(w, "connect Google Drive failed", http.StatusInternalServerError)
		return
	}
	event := adminAuditEvent(actor, authAuditActionBackupDestinationAuthorizeStart, "", "", gdriveAuditMetadata(destination.GDrive.ClientID, destination.GDrive.FolderName, ""))
	if err := store.InsertAuthAuditEvent(ctx, event); err != nil {
		log.Printf("[engram-cloud] connect Google Drive audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, gdrive.AuthCodeURL(destination.GDrive.ClientID, redirectURI, state, challenge), http.StatusSeeOther)
}

// handleDashboardGDriveCallback handles GET
// /dashboard/admin/backups/gdrive/callback, where Google sends the browser
// after the consent screen. Every outcome redirects to the Backups page with
// a fixed notice, so the code and the state leave the address bar.
func (s *CloudServer) handleDashboardGDriveCallback(w http.ResponseWriter, r *http.Request) {
	setGDriveNoStoreHeaders(w)
	if err := s.authorizeDashboardRequest(r); err != nil {
		// Never r.URL: the query holds the code and the state.
		http.Redirect(w, r, dashboardLoginPathWithNextLocal(backupsPageURL), http.StatusSeeOther)
		return
	}
	actor, ok := s.requireManagedAdmin(w, r)
	if !ok {
		return
	}
	if s.backupSettings == nil {
		http.Error(w, "backup settings are not available on this server", http.StatusNotFound)
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	notice := s.completeGDriveAuthorization(r, actor, store)
	if notice == "" {
		http.Error(w, "connect Google Drive failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, backupsPageURL+"?notice="+notice, http.StatusSeeOther)
}

// completeGDriveAuthorization validates the callback and stores the refresh
// token. It returns the notice to redirect to, or "" for an internal error.
func (s *CloudServer) completeGDriveAuthorization(r *http.Request, actor cloudauth.Principal, store AdminIdentityStore) string {
	ctx := r.Context()
	query := r.URL.Query()
	if query.Has("error") {
		denied := query.Get("error") == "access_denied"
		log.Printf("[engram-cloud] Google authorization not completed: actor=%q denied=%t", actor.ID, denied)
		if denied {
			return "gdrive-denied"
		}
		return "gdrive-error"
	}
	if s.backupKey == nil {
		return "gdrive-key"
	}
	redirectURI := s.gdriveRedirectURI()
	if redirectURI == "" {
		return "gdrive-no-public-url"
	}
	states, codes := query["state"], query["code"]
	if len(states) != 1 || len(codes) != 1 || strings.TrimSpace(codes[0]) == "" {
		return "gdrive-expired"
	}
	grant, err := s.backupSettings.ConsumeBackupOAuthState(ctx, s.backupKey, states[0], strings.TrimSpace(actor.ID))
	if notice, done := gdriveStoreNotice(err); done {
		if notice == "" {
			log.Printf("[engram-cloud] Google authorization failed to consume the state: actor=%q: %v", actor.ID, err)
		}
		return notice
	}
	dest, err := s.backupSettings.OpenBackupDestination(ctx, s.backupKey)
	if err == nil && dest.Kind != cloudstore.BackupDestinationKindGDrive {
		err = cloudstore.ErrBackupDestinationKindMismatch
	}
	if err == nil {
		err = s.backupSettings.CheckBackupOAuthBinding(ctx, grant.Binding)
	}
	if notice, done := gdriveStoreNotice(err); done {
		if notice == "" {
			log.Printf("[engram-cloud] Google authorization failed to open the destination: actor=%q: %v", actor.ID, err)
		}
		return notice
	}
	creds := dest.GDrive
	exchangeCtx, cancel := context.WithTimeout(ctx, backupGDriveExchangeTimeout)
	token, err := gdrive.ExchangeCode(exchangeCtx, s.backupGDriveHTTPClient, creds.ClientID, creds.ClientSecret, codes[0], redirectURI, grant.Verifier)
	cancel()
	// The code is spent from here on: the outcome is stored even if the
	// browser went away.
	writeCtx, cancelWrite := context.WithTimeout(context.WithoutCancel(ctx), backupGDriveStoreTimeout)
	defer cancelWrite()
	if err != nil {
		notice, reason := classifyGDriveExchange(err)
		log.Printf("[engram-cloud] Google authorization code exchange failed: actor=%q reason=%s", actor.ID, reason)
		s.auditGDriveAuthorizeFailure(writeCtx, store, actor, creds, reason)
		return notice
	}
	// The binding is compared under the destination lock in the write's own
	// transaction: a save landing during or after the exchange is refused.
	err = s.backupSettings.SetGDriveRefreshToken(writeCtx, s.backupKey, grant.Binding, token, backupStoreActor(actor))
	notice, done := gdriveStoreNotice(err)
	if !done {
		log.Printf("[engram-cloud] Google Drive destination authorized: actor=%q", actor.ID)
		return "gdrive-connected"
	}
	if notice == "" {
		log.Printf("[engram-cloud] Google authorization failed to store the refresh token: actor=%q: %v", actor.ID, err)
		return ""
	}
	log.Printf("[engram-cloud] Google authorization discarded: the destination changed during the exchange: actor=%q", actor.ID)
	s.auditGDriveAuthorizeFailure(writeCtx, store, actor, creds, backupReasonDestinationChanged)
	return notice
}

// gdriveStoreNotice maps a store refusal in the callback to its notice.
// done is false for nil; an unexpected error is done with notice "".
func gdriveStoreNotice(err error) (notice string, done bool) {
	switch {
	case err == nil:
		return "", false
	case errors.Is(err, cloudstore.ErrBackupOAuthStateNotFound), errors.Is(err, cloudstore.ErrBackupOAuthStateExpired):
		return "gdrive-expired", true
	case errors.Is(err, cloudstore.ErrBackupOAuthStatePrincipal), errors.Is(err, cloudstore.ErrBackupOAuthDestinationChanged),
		errors.Is(err, cloudstore.ErrBackupDestinationNotConfigured), errors.Is(err, cloudstore.ErrBackupDestinationKindMismatch),
		errors.Is(err, cloudstore.ErrBackupDestinationKeyChanged):
		return "gdrive-mismatch", true
	case errors.Is(err, backupcrypto.ErrKeyMismatch), errors.Is(err, backupcrypto.ErrSealedValueInvalid):
		return "gdrive-key", true
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		return "gdrive-exchange", true
	default:
		return "", true
	}
}

// classifyGDriveExchange maps a failed code exchange to its notice and
// reason code.
func classifyGDriveExchange(err error) (string, string) {
	switch {
	case errors.Is(err, gdrive.ErrScope):
		return "gdrive-scope", backupReasonScope
	case errors.Is(err, gdrive.ErrNoRefreshToken):
		return "gdrive-no-refresh", backupReasonNoRefreshToken
	case errors.Is(err, gdrive.ErrNetwork), errors.Is(err, context.DeadlineExceeded):
		return "gdrive-exchange", backupReasonNetwork
	default:
		return "gdrive-exchange", backupReasonExchangeFailed
	}
}

// auditGDriveAuthorizeFailure records a failed backup.destination.authorize
// after the code was sent to Google; a successful one is recorded by
// cloudstore with the refresh token.
func (s *CloudServer) auditGDriveAuthorizeFailure(ctx context.Context, store AdminIdentityStore, actor cloudauth.Principal, creds cloudstore.GDriveDestinationCredentials, reason string) {
	event := adminAuditEvent(actor, cloudstore.AuthAuditActionBackupDestinationAuthorize, "", "", gdriveAuditMetadata(creds.ClientID, creds.FolderName, ""))
	event.Outcome = authAuditOutcomeFailure
	event.ReasonCode = reason
	if err := store.InsertAuthAuditEvent(ctx, event); err != nil {
		log.Printf("[engram-cloud] Google authorization failure audit failed: actor=%q: %v", actor.ID, err)
	}
}
