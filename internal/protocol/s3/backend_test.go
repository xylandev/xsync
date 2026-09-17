package s3adapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	fsapi "github.com/go-faster/fs"
	"github.com/go-faster/fs/auth"
	fsserver "github.com/go-faster/fs/server"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
)

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

func TestBackendPutGetListDelete(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	b := NewBackend(st, []config.Tenant{{ID: "tenant", S3Bucket: "bucket"}})
	put, err := b.PutObject(context.Background(), &fsapi.PutObjectRequest{Bucket: "bucket", Key: "dir/file", Reader: bytes.NewBufferString("payload"), Size: 7})
	if err != nil {
		t.Fatal(err)
	}
	if put.ETag == "" {
		t.Fatal("empty ETag")
	}
	got, err := b.GetObject(context.Background(), "bucket", "dir/file")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(got.Reader)
	got.Reader.Close()
	if string(raw) != "payload" {
		t.Fatalf("got %q", raw)
	}
	listed, err := b.ListObjects(context.Background(), &fsapi.ListObjectsRequest{Bucket: "bucket", Prefix: "dir/", Limit: 100})
	if err != nil || len(listed.Objects) != 1 {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	if err = b.DeleteObject(context.Background(), "bucket", "dir/file"); err != nil {
		t.Fatal(err)
	}
}

func TestSignedS3SDKRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tenant := config.Tenant{ID: "tenant", S3Bucket: "bucket", S3AccessKey: "ACCESSKEY", S3SecretKey: "secret-key-for-test"}
	backend := NewBackend(st, []config.Tenant{tenant})
	authStore, err := auth.NewStore(auth.Config{Keys: []auth.Key{{AccessKey: tenant.S3AccessKey, SecretKey: tenant.S3SecretKey, Grants: []auth.Grant{{Pattern: tenant.S3Bucket, Permission: auth.Write}}}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(accessKeyContext(fsserver.NewHandler(backend, fsserver.WithAuth(authStore))))
	defer srv.Close()
	client := awss3.New(awss3.Options{BaseEndpoint: aws.String(srv.URL), Region: "us-east-1", UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(tenant.S3AccessKey, tenant.S3SecretKey, "")})
	body := []byte("signed payload")
	if _, err = client.PutObject(context.Background(), &awss3.PutObjectInput{Bucket: aws.String("bucket"), Key: aws.String("file.txt"), Body: bytes.NewReader(body)}); err != nil {
		t.Fatal(err)
	}
	got, err := client.GetObject(context.Background(), &awss3.GetObjectInput{Bucket: aws.String("bucket"), Key: aws.String("file.txt")})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if string(raw) != string(body) {
		t.Fatalf("got %q", raw)
	}
	if _, err = client.CopyObject(context.Background(), &awss3.CopyObjectInput{Bucket: aws.String("bucket"), Key: aws.String("copy.txt"), CopySource: aws.String("bucket/file.txt")}); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListObjectsV2(context.Background(), &awss3.ListObjectsV2Input{Bucket: aws.String("bucket")})
	if err != nil || len(listed.Contents) != 2 {
		t.Fatalf("list count=%d err=%v", len(listed.Contents), err)
	}
	if _, err = client.DeleteObject(context.Background(), &awss3.DeleteObjectInput{Bucket: aws.String("bucket"), Key: aws.String("file.txt")}); err != nil {
		t.Fatal(err)
	}
}

func TestMultipartPartsForSameUploadRunConcurrently(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	b := NewBackend(st, []config.Tenant{{ID: "tenant", S3Bucket: "bucket"}})
	first, err := b.CreateMultipartUpload(context.Background(), &fsapi.CreateMultipartUploadRequest{Bucket: "bucket", Key: "first"})
	if err != nil {
		t.Fatal(err)
	}
	reader := &gatedReader{started: make(chan struct{}), release: make(chan struct{}), data: []byte("first")}
	firstDone := make(chan error, 1)
	go func() {
		_, uploadErr := b.UploadPart(context.Background(), &fsapi.UploadPartRequest{Bucket: "bucket", Key: "first", UploadID: first.UploadID, PartNumber: 1, Reader: reader})
		firstDone <- uploadErr
	}()
	<-reader.started
	secondDone := make(chan error, 1)
	go func() {
		_, uploadErr := b.UploadPart(context.Background(), &fsapi.UploadPartRequest{Bucket: "bucket", Key: "first", UploadID: first.UploadID, PartNumber: 2, Reader: bytes.NewBufferString("second")})
		secondDone <- uploadErr
	}()
	select {
	case err = <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second multipart upload was blocked by the first upload")
	}
	close(reader.release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	parts, err := b.ListParts(context.Background(), "bucket", "first", first.UploadID)
	if err != nil || len(parts) != 2 {
		t.Fatalf("parts=%+v err=%v", parts, err)
	}
}

func TestCleanupMultipartRemovesExpiredUpload(t *testing.T) {
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	b := NewBackend(st, []config.Tenant{{ID: "tenant", S3Bucket: "bucket"}})
	upload, err := b.CreateMultipartUpload(context.Background(), &fsapi.CreateMultipartUploadRequest{Bucket: "bucket", Key: "stale"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.loadMultipart(upload.UploadID)
	if err != nil {
		t.Fatal(err)
	}
	m.UpdatedAt = time.Now().Add(-2 * time.Hour)
	if err = b.saveMultipart(m); err != nil {
		t.Fatal(err)
	}
	if err = b.cleanupMultipart(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(filepath.Join(b.multipartRoot, upload.UploadID))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired multipart directory remains: %v", err)
	}
}
