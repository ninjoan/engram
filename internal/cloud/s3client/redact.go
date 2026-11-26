package s3client

import (
	"fmt"
	"strconv"
	"strings"
)

const redacted = "[REDACTED]"

// maskKeyID keeps only the last four characters of a long access key ID.
func maskKeyID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) < 8 {
		return "****"
	}
	return "****" + id[len(id)-4:]
}

func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return redacted
}

type field struct{ name, value string }

// formatRedacted renders a credential-free view of a struct for every fmt
// verb: %#v is Go-syntax-like, %q quotes, every other verb prints %+v style.
func formatRedacted(f fmt.State, verb rune, typeName string, fields []field) {
	var b strings.Builder
	if verb == 'v' && f.Flag('#') {
		b.WriteString("s3client." + typeName + "{")
		for i, fl := range fields {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fl.name + ":" + strconv.Quote(fl.value))
		}
		b.WriteByte('}')
		_, _ = f.Write([]byte(b.String()))
		return
	}
	b.WriteByte('{')
	for i, fl := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fl.name + ":" + fl.value)
	}
	b.WriteByte('}')
	out := b.String()
	if verb == 'q' {
		out = strconv.Quote(out)
	}
	_, _ = f.Write([]byte(out))
}

// Format implements fmt.Formatter so no verb ever prints SecretAccessKey.
func (c Config) Format(f fmt.State, verb rune) {
	httpClient := "nil"
	if c.HTTPClient != nil {
		httpClient = "custom"
	}
	formatRedacted(f, verb, "Config", []field{
		{"Endpoint", c.Endpoint},
		{"Region", c.Region},
		{"Bucket", c.Bucket},
		{"AccessKeyID", maskKeyID(c.AccessKeyID)},
		{"SecretAccessKey", redactSecret(c.SecretAccessKey)},
		{"HTTPClient", httpClient},
		{"StallTimeout", c.StallTimeout.String()},
	})
}

// Format implements fmt.Formatter so no verb ever prints the credentials.
func (c Client) Format(f fmt.State, verb rune) {
	formatRedacted(f, verb, "Client", []field{
		{"endpoint", c.scheme + "://" + c.host},
		{"bucket", c.bucket},
		{"region", c.region},
		{"accessKeyID", maskKeyID(c.accessKeyID)},
		{"secretAccessKey", redactSecret(c.secretAccessKey)},
	})
}
