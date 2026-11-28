package s3client

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"
	"time"
)

// Published vectors from the AWS S3 documentation "Signature Calculations for
// the Authorization Header: Transferring Payload in a Single Chunk (AWS
// Signature Version 4)" — examples section.
const (
	exampleAccessKey = "AKIAIOSFODNN7EXAMPLE"
	exampleSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	exampleHost      = "examplebucket.s3.amazonaws.com"
	exampleRegion    = "us-east-1"
	emptySHA256      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var exampleDate = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func TestSigV4ReproducesPublishedS3Examples(t *testing.T) {
	putBodyHash := sha256.Sum256([]byte("Welcome to Amazon S3."))
	if got := hex.EncodeToString(putBodyHash[:]); got != "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" {
		t.Fatalf("published PUT example payload hash = %s", got)
	}

	cases := []struct {
		name          string
		req           signingInput
		wantCanonical string
		wantSigned    string
		wantSignature string
	}{
		{
			name: "GET Object",
			req: signingInput{
				method: "GET",
				path:   "/test.txt",
				headers: map[string]string{
					"host":                 exampleHost,
					"range":                "bytes=0-9",
					"x-amz-content-sha256": emptySHA256,
					"x-amz-date":           "20130524T000000Z",
				},
				payloadHash: emptySHA256,
				time:        exampleDate,
				region:      exampleRegion,
			},
			wantCanonical: "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n" + emptySHA256,
			wantSigned:    "host;range;x-amz-content-sha256;x-amz-date",
			wantSignature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "PUT Object",
			req: signingInput{
				method: "PUT",
				path:   "/test$file.text",
				headers: map[string]string{
					"date":                 "Fri, 24 May 2013 00:00:00 GMT",
					"host":                 exampleHost,
					"x-amz-content-sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
					"x-amz-date":           "20130524T000000Z",
					"x-amz-storage-class":  "REDUCED_REDUNDANCY",
				},
				payloadHash: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
				time:        exampleDate,
				region:      exampleRegion,
			},
			wantCanonical: "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\nx-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\ndate;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			wantSigned:    "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
			wantSignature: "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "GET Bucket Lifecycle",
			req: signingInput{
				method: "GET",
				path:   "/",
				query:  url.Values{"lifecycle": {""}},
				headers: map[string]string{
					"host":                 exampleHost,
					"x-amz-content-sha256": emptySHA256,
					"x-amz-date":           "20130524T000000Z",
				},
				payloadHash: emptySHA256,
				time:        exampleDate,
				region:      exampleRegion,
			},
			wantCanonical: "GET\n/\nlifecycle=\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n" + emptySHA256,
			wantSigned:    "host;x-amz-content-sha256;x-amz-date",
			wantSignature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "Get Bucket (List Objects)",
			req: signingInput{
				method: "GET",
				path:   "/",
				query:  url.Values{"prefix": {"J"}, "max-keys": {"2"}},
				headers: map[string]string{
					"host":                 exampleHost,
					"x-amz-content-sha256": emptySHA256,
					"x-amz-date":           "20130524T000000Z",
				},
				payloadHash: emptySHA256,
				time:        exampleDate,
				region:      exampleRegion,
			},
			wantCanonical: "GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n" + emptySHA256,
			wantSigned:    "host;x-amz-content-sha256;x-amz-date",
			wantSignature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, signed := canonicalRequest(tc.req)
			if canonical != tc.wantCanonical {
				t.Fatalf("canonical request mismatch\n got: %q\nwant: %q", canonical, tc.wantCanonical)
			}
			if signed != tc.wantSigned {
				t.Fatalf("signed headers = %q, want %q", signed, tc.wantSigned)
			}
			sts := stringToSign(tc.req.time, tc.req.region, canonical)
			sum := sha256.Sum256([]byte(tc.wantCanonical))
			wantSTS := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n" + hex.EncodeToString(sum[:])
			if sts != wantSTS {
				t.Fatalf("string to sign mismatch\n got: %q\nwant: %q", sts, wantSTS)
			}
			if got := signature(exampleSecret, tc.req.time, tc.req.region, sts); got != tc.wantSignature {
				t.Fatalf("signature = %s, want published %s", got, tc.wantSignature)
			}
		})
	}
}

func TestSigV4PublishedGetObjectAuthorizationHeader(t *testing.T) {
	in := signingInput{
		method: "GET",
		path:   "/test.txt",
		headers: map[string]string{
			"host":                 exampleHost,
			"range":                "bytes=0-9",
			"x-amz-content-sha256": emptySHA256,
			"x-amz-date":           "20130524T000000Z",
		},
		payloadHash: emptySHA256,
		time:        exampleDate,
		region:      exampleRegion,
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := authorization(exampleAccessKey, exampleSecret, in); got != want {
		t.Fatalf("authorization\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalURIEncodesEachSegment(t *testing.T) {
	cases := map[string]string{
		"/":                         "/",
		"/bucket":                   "/bucket",
		"/bucket/a b":               "/bucket/a%20b",
		"/bucket/dir/ü.tar.gz":      "/bucket/dir/%C3%BC.tar.gz",
		"/bucket/a~-_.Z9":           "/bucket/a~-_.Z9",
		"/bucket/a+b=c&d$e:f@g,h;i": "/bucket/a%2Bb%3Dc%26d%24e%3Af%40g%2Ch%3Bi",
		"/bucket/x/y/z":             "/bucket/x/y/z",
		"/bucket/100%":              "/bucket/100%25",
	}
	for in, want := range cases {
		if got := canonicalURI(in); got != want {
			t.Errorf("canonicalURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalQueryStringSortsAndEncodes(t *testing.T) {
	cases := []struct {
		in   url.Values
		want string
	}{
		{nil, ""},
		{url.Values{"prefix": {"J"}, "max-keys": {"2"}}, "max-keys=2&prefix=J"},
		{url.Values{"lifecycle": {""}}, "lifecycle="},
		{url.Values{"a b": {"x/y z"}}, "a%20b=x%2Fy%20z"},
		{url.Values{"k": {"b", "a"}}, "k=a&k=b"},
		{url.Values{"list-type": {"2"}, "max-keys": {"1"}}, "list-type=2&max-keys=1"},
		{url.Values{"a": {"1"}, "a-b": {"2"}}, "a=1&a-b=2"},
	}
	for _, tc := range cases {
		if got := canonicalQueryString(tc.in); got != tc.want {
			t.Errorf("canonicalQueryString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalHeadersTrimAndCollapseSpaces(t *testing.T) {
	in := signingInput{
		method:      "GET",
		path:        "/",
		headers:     map[string]string{"Host": " h ", "X-Amz-Meta-Note": "  a   b  c "},
		payloadHash: emptySHA256,
	}
	canonical, signed := canonicalRequest(in)
	want := "GET\n/\n\nhost:h\nx-amz-meta-note:a b c\n\nhost;x-amz-meta-note\n" + emptySHA256
	if canonical != want || signed != "host;x-amz-meta-note" {
		t.Fatalf("canonical = %q signed = %q", canonical, signed)
	}
}
