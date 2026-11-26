package s3client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, header-based authentication, for the "s3" service.
// Reference: "Signature Calculations for the Authorization Header: Transferring
// Payload in a Single Chunk (AWS Signature Version 4)".

const (
	sigV4Algorithm  = "AWS4-HMAC-SHA256"
	sigV4Service    = "s3"
	sigV4Terminator = "aws4_request"
	amzDateFormat   = "20060102T150405Z"
	scopeDateFormat = "20060102"
)

// signingInput is everything that enters the canonical request.
type signingInput struct {
	method      string
	path        string // unescaped absolute path, e.g. "/bucket/dir/key"
	query       url.Values
	headers     map[string]string // header name -> value; all of them are signed
	payloadHash string            // hex SHA-256 of the body
	time        time.Time
	region      string
}

// sigV4Escape URI-encodes s per SigV4: every byte except the unreserved set
// A-Z a-z 0-9 - _ . ~ becomes %XX with uppercase hex.
func sigV4Escape(s string, keepSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~', keepSlash && c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}

// canonicalURI encodes each path segment once, keeping "/" separators. S3
// paths are not normalized (no dot-segment removal, no double encoding).
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return sigV4Escape(path, true)
}

// canonicalQueryString encodes names and values and sorts by name, then value.
func canonicalQueryString(q url.Values) string {
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(q))
	for k, vs := range q {
		ek := sigV4Escape(k, false)
		for _, v := range vs {
			pairs = append(pairs, pair{ek, sigV4Escape(v, false)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// canonicalRequest returns the SigV4 canonical request and the signed headers list.
func canonicalRequest(in signingInput) (string, string) {
	names := make([]string, 0, len(in.headers))
	values := make(map[string]string, len(in.headers))
	for name, value := range in.headers {
		lower := strings.ToLower(strings.TrimSpace(name))
		names = append(names, lower)
		values[lower] = strings.Join(strings.Fields(value), " ")
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name)
		headers.WriteByte(':')
		headers.WriteString(values[name])
		headers.WriteByte('\n')
	}
	signed := strings.Join(names, ";")
	return strings.Join([]string{
		in.method,
		canonicalURI(in.path),
		canonicalQueryString(in.query),
		headers.String(),
		signed,
		in.payloadHash,
	}, "\n"), signed
}

func credentialScope(t time.Time, region string) string {
	return t.UTC().Format(scopeDateFormat) + "/" + region + "/" + sigV4Service + "/" + sigV4Terminator
}

func stringToSign(t time.Time, region, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return sigV4Algorithm + "\n" + t.UTC().Format(amzDateFormat) + "\n" + credentialScope(t, region) + "\n" + hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signature(secret string, t time.Time, region, sts string) string {
	key := hmacSHA256([]byte("AWS4"+secret), t.UTC().Format(scopeDateFormat))
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, sigV4Service)
	key = hmacSHA256(key, sigV4Terminator)
	return hex.EncodeToString(hmacSHA256(key, sts))
}

// authorization builds the Authorization header value for in.
func authorization(accessKeyID, secret string, in signingInput) string {
	canonical, signed := canonicalRequest(in)
	sig := signature(secret, in.time, in.region, stringToSign(in.time, in.region, canonical))
	return sigV4Algorithm + " Credential=" + accessKeyID + "/" + credentialScope(in.time, in.region) +
		",SignedHeaders=" + signed + ",Signature=" + sig
}
