package s3adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	fsapi "github.com/go-faster/fs"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

var (
	alice = config.Tenant{ID: "alice", S3Bucket: "alice-bucket", S3AccessKey: "ALICEKEY", S3SecretKey: "alice-secret-key-123"}
	bob   = config.Tenant{ID: "bob", S3Bucket: "bob-bucket", S3AccessKey: "BOBKEY", S3SecretKey: "bob-secret-key-12345"}
)

type env struct {
	st  *store.Store
	b   *Backend
	srv *httptest.Server
}

func start(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := tenant.NewRegistry([]config.Tenant{alice, bob})
	s := New(config.S3Config{Enabled: true}, reg, st, Options{Limits: config.Default().Limits, Auth: netguard.NewAuthLimiter(1000)}, nil)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &env{st: st, b: s.backend, srv: srv}
}

func (e *env) client(t config.Tenant) *awss3.Client {
	return awss3.New(awss3.Options{BaseEndpoint: aws.String(e.srv.URL), Region: "us-east-1", UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(t.S3AccessKey, t.S3SecretKey, ""), RetryMaxAttempts: 1})
}

func callerCtx(id string) context.Context {
	return context.WithValue(context.Background(), callerKey{}, id)
}

type gatedReader struct {
	started chan struct{}
	release chan struct{}
	data    []byte
	done    bool
}

func (r *gatedReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	close(r.started)
	<-r.release
	return copy(p, r.data), nil
}

func TestSignedS3SDKRoundTrip(t *testing.T) {
	e := start(t)
	c := e.client(alice)
	ctx := context.Background()
	body := []byte("signed payload")
	if _, err := c.PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("dir/file.txt"), Body: bytes.NewReader(body)}); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("dir/file.txt")})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if string(raw) != string(body) {
		t.Fatalf("got %q", raw)
	}
	listed, err := c.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(alice.S3Bucket), Delimiter: aws.String("/")})
	if err != nil || len(listed.CommonPrefixes) != 1 {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	buckets, err := c.ListBuckets(ctx, &awss3.ListBucketsInput{})
	if err != nil || len(buckets.Buckets) != 1 || *buckets.Buckets[0].Name != alice.S3Bucket {
		t.Fatalf("ListBuckets revealed other tenants: %+v, %v", buckets, err)
	}
	if _, err = c.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("dir/file.txt")}); err != nil {
		t.Fatal(err)
	}
}

// CopyObject resolved the source bucket without authorising it, so any tenant
// could read another tenant's objects through a copy.
func TestCrossTenantAccessIsRefused(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	if _, err := e.client(bob).PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(bob.S3Bucket), Key: aws.String("secret.txt"), Body: strings.NewReader("bob private data")}); err != nil {
		t.Fatal(err)
	}
	a := e.client(alice)
	if _, err := a.CopyObject(ctx, &awss3.CopyObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("stolen.txt"), CopySource: aws.String(bob.S3Bucket + "/secret.txt")}); err == nil {
		t.Fatal("cross-tenant CopyObject succeeded")
	}
	if _, err := a.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bob.S3Bucket), Key: aws.String("secret.txt")}); err == nil {
		t.Fatal("cross-tenant GetObject succeeded")
	}
	if _, err := a.PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(bob.S3Bucket), Key: aws.String("injected.txt"), Body: strings.NewReader("x")}); err == nil {
		t.Fatal("cross-tenant PutObject succeeded")
	}
	if _, err := e.st.Current("alice", "stolen.txt"); err == nil {
		t.Fatal("copied object exists")
	}
	// Backend-level defence in depth.
	if _, err := e.b.GetObject(callerCtx("alice"), bob.S3Bucket, "secret.txt"); !errors.Is(err, fsapi.ErrAccessDenied) {
		t.Fatalf("backend served another tenant's bucket: %v", err)
	}
}

// Browser form uploads (and anything posing as one) bypassed authorisation
// entirely, including DeleteObjects.
func TestUnsignedAndFormRequestsAreRefused(t *testing.T) {
	e := start(t)
	if _, err := e.client(bob).PutObject(context.Background(), &awss3.PutObjectInput{Bucket: aws.String(bob.S3Bucket), Key: aws.String("keep.txt"), Body: strings.NewReader("keep")}); err != nil {
		t.Fatal(err)
	}
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	_ = mw.WriteField("key", "injected.txt")
	fw, _ := mw.CreateFormFile("file", "injected.txt")
	_, _ = fw.Write([]byte("injected"))
	mw.Close()
	resp, err := http.Post(e.srv.URL+"/"+bob.S3Bucket, mw.FormDataContentType(), &form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("form upload status = %d", resp.StatusCode)
	}
	del := `<Delete><Object><Key>keep.txt</Key></Object></Delete>`
	resp, err = http.Post(e.srv.URL+"/"+bob.S3Bucket+"?delete", "multipart/form-data; boundary=x", strings.NewReader(del))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous DeleteObjects status = %d", resp.StatusCode)
	}
	if _, err := e.st.Current("bob", "keep.txt"); err != nil {
		t.Fatal("anonymous request deleted an object")
	}
	if _, err := e.st.Current("bob", "injected.txt"); err == nil {
		t.Fatal("anonymous form upload stored an object")
	}
	// Existence of buckets must not leak to anonymous callers.
	r1, _ := http.Get(e.srv.URL + "/" + bob.S3Bucket)
	r2, _ := http.Get(e.srv.URL + "/no-such-bucket")
	r1.Body.Close()
	r2.Body.Close()
	if r1.StatusCode != r2.StatusCode {
		t.Fatalf("anonymous probe distinguishes buckets: %d vs %d", r1.StatusCode, r2.StatusCode)
	}
}

func TestOversizedControlBodyIsRejected(t *testing.T) {
	e := start(t)
	var keys strings.Builder
	keys.WriteString("<Delete>")
	for keys.Len() < 4<<20 {
		keys.WriteString("<Object><Key>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</Key></Object>")
	}
	keys.WriteString("</Delete>")
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/"+alice.S3Bucket+"?delete", strings.NewReader(keys.String()))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ALICEKEY/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("oversized request accepted: %d", resp.StatusCode)
	}
}

func TestFolderMarkersBecomeDirectoriesAndKeysAreNotRewritten(t *testing.T) {
	e := start(t)
	c := e.client(alice)
	ctx := context.Background()
	if _, err := c.PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("reports/"), Body: bytes.NewReader(nil)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("reports/q1.csv"), Body: strings.NewReader("q1")}); err != nil {
		t.Fatal(err)
	}
	claim, err := e.st.ClaimNext("alice", "c", "", time.Minute)
	if err != nil || claim.Path != "reports/q1.csv" {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
	if _, err := e.st.ClaimNext("alice", "c", "", time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("folder marker was delivered as a file")
	}
	if _, err := c.PutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(alice.S3Bucket), Key: aws.String("a//b"), Body: strings.NewReader("x")}); err == nil {
		t.Fatal("key that normalises to another name was accepted")
	}
}

func TestMultipartPartsForSameUploadRunConcurrently(t *testing.T) {
	e := start(t)
	ctx := callerCtx("alice")
	first, err := e.b.CreateMultipartUpload(ctx, &fsapi.CreateMultipartUploadRequest{Bucket: alice.S3Bucket, Key: "first"})
	if err != nil {
		t.Fatal(err)
	}
	reader := &gatedReader{started: make(chan struct{}), release: make(chan struct{}), data: []byte("first")}
	firstDone := make(chan error, 1)
	go func() {
		_, uploadErr := e.b.UploadPart(ctx, &fsapi.UploadPartRequest{Bucket: alice.S3Bucket, Key: "first", UploadID: first.UploadID, PartNumber: 1, Reader: reader})
		firstDone <- uploadErr
	}()
	<-reader.started
	secondDone := make(chan error, 1)
	go func() {
		_, uploadErr := e.b.UploadPart(ctx, &fsapi.UploadPartRequest{Bucket: alice.S3Bucket, Key: "first", UploadID: first.UploadID, PartNumber: 2, Reader: bytes.NewBufferString("second")})
		secondDone <- uploadErr
	}()
	select {
	case err = <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second part was blocked by the first")
	}
	close(reader.release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	parts, err := e.b.ListParts(ctx, alice.S3Bucket, "first", first.UploadID)
	if err != nil || len(parts) != 2 {
		t.Fatalf("parts=%+v err=%v", parts, err)
	}
}

// A client that gave up waiting used to make the server drop the assembled
// object and the parts; a retry then failed with NoSuchUpload.
func TestCompleteSurvivesClientDisconnectAndIsIdempotent(t *testing.T) {
	e := start(t)
	ctx := callerCtx("alice")
	up, err := e.b.CreateMultipartUpload(ctx, &fsapi.CreateMultipartUploadRequest{Bucket: alice.S3Bucket, Key: "big.bin"})
	if err != nil {
		t.Fatal(err)
	}
	p1, err := e.b.UploadPart(ctx, &fsapi.UploadPartRequest{Bucket: alice.S3Bucket, Key: "big.bin", UploadID: up.UploadID, PartNumber: 1, Reader: strings.NewReader("hello ")})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := e.b.UploadPart(ctx, &fsapi.UploadPartRequest{Bucket: alice.S3Bucket, Key: "big.bin", UploadID: up.UploadID, PartNumber: 2, Reader: strings.NewReader("world")})
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	req := &fsapi.CompleteMultipartUploadRequest{Bucket: alice.S3Bucket, Key: "big.bin", UploadID: up.UploadID, Parts: []fsapi.CompletedPart{{PartNumber: 1, ETag: p1.ETag}, {PartNumber: 2, ETag: p2.ETag}}}
	first, err := e.b.CompleteMultipartUpload(canceled, req)
	if err != nil {
		t.Fatalf("complete with a departed client: %v", err)
	}
	f, _, err := e.st.OpenCurrent("alice", "big.bin")
	if err != nil {
		t.Fatalf("assembled object not published: %v", err)
	}
	raw, _ := io.ReadAll(f)
	f.Close()
	if string(raw) != "hello world" {
		t.Fatalf("assembled %q", raw)
	}
	again, err := e.b.CompleteMultipartUpload(ctx, req)
	if err != nil || again.ETag != first.ETag {
		t.Fatalf("retried complete = %+v, %v", again, err)
	}
	if o, _ := e.st.Current("alice", "big.bin"); o.ETag != first.ETag {
		t.Fatalf("object etag %q, want %q", o.ETag, first.ETag)
	}
}

func TestCleanupMultipartRemovesOnlyIdleUploads(t *testing.T) {
	e := start(t)
	ctx := callerCtx("alice")
	stale, err := e.b.CreateMultipartUpload(ctx, &fsapi.CreateMultipartUploadRequest{Bucket: alice.S3Bucket, Key: "stale"})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := e.b.CreateMultipartUpload(ctx, &fsapi.CreateMultipartUploadRequest{Bucket: alice.S3Bucket, Key: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	dir := filepath.Join(e.b.multipartRoot, stale.UploadID)
	_ = os.Chtimes(filepath.Join(dir, "meta.json"), old, old)
	_ = os.Chtimes(dir, old, old)
	if err = e.b.cleanupMultipart(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired multipart directory remains: %v", err)
	}
	if _, err = os.Stat(filepath.Join(e.b.multipartRoot, fresh.UploadID)); err != nil {
		t.Fatalf("active upload removed: %v", err)
	}
}
