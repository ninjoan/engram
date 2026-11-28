package cloudserver

import (
	"fmt"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var errInvalidEndpointForProbe = fmt.Errorf("%w: endpoint must be an https origin such as https://<account>.r2.cloudflarestorage.com (http only for loopback hosts)", cloudstore.ErrInvalidBackupDestination)

func fmtAny(v any) string { return fmt.Sprintf("%+v", v) }
