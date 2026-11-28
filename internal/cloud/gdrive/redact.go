package gdrive

import (
	"fmt"
	"strconv"
	"strings"
)

const redacted = "[REDACTED]"

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
		b.WriteString("gdrive." + typeName + "{")
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

// Config and Client must stay fmt.Formatters: a logged destination must
// never print its credentials.
var (
	_ = fmt.Formatter(Config{})
	_ = fmt.Formatter(Client{})
)

func setOrNil(set bool) string {
	if set {
		return "custom"
	}
	return "nil"
}

// Format implements fmt.Formatter so no verb ever prints the credentials.
func (c Config) Format(f fmt.State, verb rune) {
	formatRedacted(f, verb, "Config", []field{
		{"ClientID", c.ClientID},
		{"ClientSecret", redactSecret(c.ClientSecret)},
		{"RefreshToken", redactSecret(c.RefreshToken)},
		{"HTTPClient", setOrNil(c.HTTPClient != nil)},
		{"Clock", setOrNil(c.Clock != nil)},
	})
}

// Format implements fmt.Formatter so no verb ever prints the credentials or
// the cached access token.
func (c Client) Format(f fmt.State, verb rune) {
	formatRedacted(f, verb, "Client", []field{
		{"clientID", c.clientID},
		{"clientSecret", redactSecret(c.clientSecret)},
		{"refreshToken", redactSecret(c.refreshToken)},
	})
}
