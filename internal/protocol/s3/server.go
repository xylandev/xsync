package s3adapter

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fsapi "github.com/go-faster/fs"
	"github.com/go-faster/fs/auth"
	fsserver "github.com/go-faster/fs/server"
	"github.com/xylandev/xsync/internal/certstore"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/netguard"
	"github.com/xylandev/xsync/internal/store"
	"github.com/xylandev/xsync/internal/tenant"
)

type Options struct {
	Limits     config.LimitsConfig
	Auth       *netguard.AuthLimiter
	Certs      *certstore.Store
	PartialTTL time.Duration
}

type Server struct {
	cfg     config.S3Config
	tenants *tenant.Registry
	backend *Backend
	log     *slog.Logger
	opts    Options
	handler atomic.Pointer[http.Handler]
	http    *http.Server
	mu      sync.Mutex
}

func New(cfg config.S3Config, tenants *tenant.Registry, st *store.Store, opts Options, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Limits.MaxRequestBody <= 0 {
		opts.Limits = config.Default().Limits
	}
	s := &Server{cfg: cfg, tenants: tenants, backend: NewBackend(st, tenants), log: log, opts: opts}
	return s
}

// buildHandler rebuilds the upstream handler with the current credentials.
// It runs at start and whenever the account table changes.
func (s *Server) buildHandler(snap *tenant.Snapshot) error {
	keys := make([]auth.Key, 0, len(snap.All()))
	for _, t := range snap.All() {
		if t.Disabled || t.S3AccessKey == "" {
			continue
		}
		keys = append(keys, auth.Key{AccessKey: t.S3AccessKey, SecretKey: t.S3SecretKey, UserID: t.ID, DisplayName: t.ID, Grants: []auth.Grant{{Pattern: t.S3Bucket, Permission: auth.Write}}})
	}
	authStore, err := auth.NewStore(auth.Config{Keys: keys})
	if err != nil {
		return err
	}
	var h http.Handler = fsserver.NewHandler(s.backend, fsserver.WithAuth(authStore), fsserver.WithOwnerIsolation(false))
	s.handler.Store(&h)
	return nil
}

// Handler returns the complete S3 handler: guard, stall deadlines, upstream.
func (s *Server) Handler() http.Handler {
	if s.handler.Load() == nil {
		if err := s.buildHandler(s.tenants.Load()); err != nil {
			s.log.Error("S3 credentials", "error", err)
		}
		s.tenants.Subscribe(func(snap *tenant.Snapshot) {
			if err := s.buildHandler(snap); err != nil {
				s.log.Error("reload S3 credentials", "error", err)
			}
		})
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*s.handler.Load()).ServeHTTP(w, r) })
	return netguard.StallGuard(s.opts.Limits.IdleTimeout, s.guard(upstream))
}

func (s *Server) Serve(ctx context.Context) error {
	handler := s.Handler()
	go s.backend.MaintainMultipart(ctx, 30*time.Second, s.opts.PartialTTL)
	inner, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	ln := netguard.NewListener(inner, netguard.Limits{MaxConns: s.opts.Limits.MaxConnections, MaxConnsPerIP: s.opts.Limits.MaxConnectionsPerIP})
	tlsCfg := s.opts.Certs.TLSConfig()
	s.mu.Lock()
	s.http = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: tlsCfg, MaxHeaderBytes: 64 << 10}
	srv := s.http
	s.mu.Unlock()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	s.log.Info("S3 HTTPS listening", "addr", s.cfg.Listen)
	err = srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// Shutdown stops accepting requests and waits for in-flight ones.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.http
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// Abort closes every connection.
func (s *Server) Abort() {
	s.mu.Lock()
	srv := s.http
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

type callerKey struct{}

func callerTenant(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(callerKey{}).(string)
	return id, ok
}

// accessKeyOf extracts the access key a request claims to be signed with.
// The upstream handler verifies the signature; the guard only uses the key to
// bind the caller to its own bucket before any storage call can happen.
func accessKeyOf(r *http.Request) string {
	value := r.URL.Query().Get("X-Amz-Credential")
	if value == "" {
		authz := r.Header.Get("Authorization")
		if i := strings.Index(authz, "Credential="); i >= 0 {
			value = authz[i+len("Credential="):]
			if j := strings.IndexAny(value, ", "); j >= 0 {
				value = value[:j]
			}
		}
	}
	key, _, _ := strings.Cut(value, "/")
	return key
}

func signed(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") || r.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
}

// Subresources the transfer service supports. Anything else is refused before
// it reaches the upstream handler, whose broader feature set was not designed
// for multi-tenant isolation.
var allowedQuery = map[string]bool{
	"uploads": true, "uploadId": true, "partNumber": true, "delete": true, "tagging": true,
	"list-type": true, "prefix": true, "delimiter": true, "marker": true, "max-keys": true,
	"continuation-token": true, "start-after": true, "fetch-owner": true, "encoding-type": true,
	"location": true, "key-marker": true, "upload-id-marker": true, "max-uploads": true,
	"max-parts": true, "part-number-marker": true, "x-id": true, "acl": true, "versioning": true,
	"response-content-type": true, "response-content-disposition": true, "response-cache-control": true,
	"response-content-encoding": true, "response-content-language": true, "response-expires": true,
}

func s3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "30")
	}
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>%s</Code><Message>%s</Message></Error>", code, message)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !s.opts.Auth.Allow(ip) {
			s3Error(w, http.StatusServiceUnavailable, "SlowDown", "too many failed authentication attempts")
			return
		}
		// Only SigV4-signed requests are served. Anonymous requests, browser
		// form uploads (whose policy the attacker writes) and legacy
		// signatures are all refused with the same answer, which also means
		// an unauthenticated caller cannot learn which buckets exist.
		if !signed(r) || (r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")) {
			s.opts.Auth.Fail(ip)
			s3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			s3Error(w, http.StatusNotImplemented, "NotImplemented", "server-side copy is not supported")
			return
		}
		for k := range r.URL.Query() {
			if !allowedQuery[k] && !strings.HasPrefix(strings.ToLower(k), "x-amz-") {
				s3Error(w, http.StatusNotImplemented, "NotImplemented", "unsupported request")
				return
			}
		}
		t, ok := s.tenants.Load().ByAccessKey(accessKeyOf(r))
		if !ok {
			s.opts.Auth.Fail(ip)
			s3Error(w, http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
			return
		}
		bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if bucket != "" && bucket != t.S3Bucket {
			s3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		q := r.URL.Query()
		objectData := key != "" && r.Method == http.MethodPut && !q.Has("tagging") && !q.Has("acl")
		if !objectData {
			r.Body = http.MaxBytesReader(w, r.Body, s.opts.Limits.MaxRequestBody)
		}
		newUpload := key != "" && ((r.Method == http.MethodPut && objectData && !q.Has("uploadId")) || (r.Method == http.MethodPost && q.Has("uploads")))
		if newUpload {
			if err := s.backend.st.AdmitUpload(t.ID); err != nil {
				s3Error(w, http.StatusServiceUnavailable, "SlowDown", "uploads are temporarily refused: "+err.Error())
				return
			}
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), callerKey{}, t.ID)))
		if rec.status == http.StatusForbidden {
			s.opts.Auth.Fail(ip)
		}
	})
}

// Backend implements go-faster/fs storage on top of the transfer store.
type Backend struct {
	st            *store.Store
	tenants       *tenant.Registry
	multipartRoot string
	locksMu       sync.Mutex
	locks         map[string]*multipartLock
	assembly      chan struct{}
}

type multipartLock struct {
	lifecycle sync.RWMutex
	refs      int
}

func NewBackend(st *store.Store, tenants *tenant.Registry) *Backend {
	b := &Backend{st: st, tenants: tenants, multipartRoot: filepath.Join(st.Root(), "staging", "s3-multipart"), locks: map[string]*multipartLock{}, assembly: make(chan struct{}, 2)}
	_ = os.MkdirAll(b.multipartRoot, 0o750)
	return b
}

func (b *Backend) retain(id string) *multipartLock {
	b.locksMu.Lock()
	defer b.locksMu.Unlock()
	l := b.locks[id]
	if l == nil {
		l = &multipartLock{}
		b.locks[id] = l
	}
	l.refs++
	return l
}

func (b *Backend) release(id string, l *multipartLock) {
	b.locksMu.Lock()
	defer b.locksMu.Unlock()
	if l.refs--; l.refs == 0 && b.locks[id] == l {
		delete(b.locks, id)
	}
}

func (b *Backend) lockRead(id string) func() {
	l := b.retain(id)
	l.lifecycle.RLock()
	return func() { l.lifecycle.RUnlock(); b.release(id, l) }
}

func (b *Backend) lockWrite(id string) func() {
	l := b.retain(id)
	l.lifecycle.Lock()
	return func() { l.lifecycle.Unlock(); b.release(id, l) }
}

// tenant resolves a bucket and checks it belongs to the caller. The guard
// already enforces this; checking again here keeps the isolation independent
// of the upstream handler's routing.
func (b *Backend) tenant(ctx context.Context, bucket string) (string, error) {
	t, ok := b.tenants.Load().ByBucket(bucket)
	if !ok {
		return "", fsapi.ErrBucketNotFound
	}
	if caller, set := callerTenant(ctx); set && caller != t.ID {
		return "", fsapi.ErrAccessDenied
	}
	return t.ID, nil
}

// objectKey validates an S3 key against the path namespace. Keys that would
// be rewritten by normalisation ("a//b", "./x") are refused instead of being
// stored under a different name than the client used.
func objectKey(key string) (string, error) {
	clean, err := store.CleanPath(key)
	if err != nil || clean == "" || clean != key {
		return "", fsapi.ErrInvalidKey
	}
	return clean, nil
}

func (b *Backend) ListBuckets(ctx context.Context) ([]fsapi.Bucket, error) {
	caller, ok := callerTenant(ctx)
	if !ok {
		return nil, nil
	}
	t, found := b.tenants.Load().Get(caller)
	if !found || t.S3Bucket == "" {
		return nil, nil
	}
	return []fsapi.Bucket{{Name: t.S3Bucket, CreationDate: time.Unix(0, 0).UTC()}}, nil
}

func (b *Backend) CreateBucket(ctx context.Context, bucket string) error {
	if _, err := b.tenant(ctx, bucket); err == nil {
		return fsapi.ErrBucketAlreadyExists
	}
	return fsapi.ErrUnsupportedOperation
}
func (b *Backend) DeleteBucket(context.Context, string) error { return fsapi.ErrUnsupportedOperation }
func (b *Backend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	_, err := b.tenant(ctx, bucket)
	return err == nil, nil
}

func (b *Backend) ListObjects(ctx context.Context, req *fsapi.ListObjectsRequest) (*fsapi.ListObjectsResponse, error) {
	tenantID, err := b.tenant(ctx, req.Bucket)
	if err != nil {
		return nil, err
	}
	page, err := b.st.ListKeys(tenantID, req.Prefix, req.Delimiter, req.StartAfter, req.Limit)
	if err != nil {
		return nil, err
	}
	out := &fsapi.ListObjectsResponse{CommonPrefixes: page.CommonPrefixes, IsTruncated: page.Truncated, NextStartAfter: page.NextAfter}
	for _, o := range page.Objects {
		out.Objects = append(out.Objects, fsapi.Object{Key: o.Path, Size: o.Size, LastModified: o.CreatedAt, ETag: o.ETag})
	}
	return out, nil
}

func (b *Backend) PutObject(ctx context.Context, req *fsapi.PutObjectRequest) (*fsapi.PutObjectResponse, error) {
	tenantID, err := b.tenant(ctx, req.Bucket)
	if err != nil {
		return nil, err
	}
	// A key ending in "/" is a folder marker made by consoles and sync
	// tools. It becomes a directory, never a file: a file named like a
	// directory could not be written next to the directory's children.
	if strings.HasSuffix(req.Key, "/") {
		var probe [1]byte
		if n, _ := io.ReadFull(req.Reader, probe[:]); n > 0 {
			return nil, fsapi.ErrInvalidKey
		}
		if err := b.st.Mkdir(tenantID, req.Key); err != nil {
			return nil, fsapi.ErrInvalidKey
		}
		return &fsapi.PutObjectResponse{ETag: "d41d8cd98f00b204e9800998ecf8427e"}, nil
	}
	key, err := objectKey(req.Key)
	if err != nil {
		return nil, err
	}
	h, err := b.st.BeginUpload(ctx, tenantID, key, "s3")
	if err != nil {
		return nil, err
	}
	sum := md5.New()
	var off int64
	buf := make([]byte, 1<<20)
	for {
		n, rerr := req.Reader.Read(buf)
		if n > 0 {
			if _, werr := h.WriteAt(buf[:n], off); werr != nil {
				h.TransferError(werr)
				_ = h.Close()
				return nil, werr
			}
			sum.Write(buf[:n])
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			h.TransferError(rerr)
			_ = h.Close()
			return nil, rerr
		}
	}
	etag := hex.EncodeToString(sum.Sum(nil))
	if req.ContentMD5 != "" && !strings.EqualFold(req.ContentMD5, etag) {
		// Corrupt content must never become a resumable base.
		h.Fail(fsapi.ErrBadDigest)
		_ = h.Close()
		return nil, fsapi.ErrBadDigest
	}
	h.SetObjectMeta(store.ObjectMeta{ETag: etag, Metadata: metadataMap(req.Metadata), Tags: tagMap(req.Tags)})
	if err := h.Close(); err != nil {
		return nil, err
	}
	return &fsapi.PutObjectResponse{ETag: etag}, nil
}

func (b *Backend) GetObject(ctx context.Context, bucket, key string) (*fsapi.GetObjectResponse, error) {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return nil, err
	}
	f, o, err := b.st.OpenCurrent(tenantID, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fsapi.ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return &fsapi.GetObjectResponse{Reader: f, Size: o.Size, LastModified: o.CreatedAt, ETag: o.ETag, Metadata: metadataFromMap(o.Metadata), TagCount: len(o.Tags)}, nil
}

func (b *Backend) DeleteObject(ctx context.Context, bucket, key string) error {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return err
	}
	err = b.st.Remove(tenantID, key)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrIsDirectory) {
		return fsapi.ErrObjectNotFound
	}
	return err
}

func (b *Backend) GetObjectTagging(ctx context.Context, bucket, key string) ([]fsapi.Tag, error) {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return nil, err
	}
	o, err := b.st.Current(tenantID, key)
	if err != nil {
		return nil, fsapi.ErrObjectNotFound
	}
	out := make([]fsapi.Tag, 0, len(o.Tags))
	for k, v := range o.Tags {
		out = append(out, fsapi.Tag{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (b *Backend) PutObjectTagging(ctx context.Context, bucket, key string, tags []fsapi.Tag) error {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return err
	}
	o, err := b.st.Current(tenantID, key)
	if err != nil {
		return fsapi.ErrObjectNotFound
	}
	return b.st.UpdateObject(o.ID, func(o *model.ObjectVersion) error { o.Tags = tagMap(tags); return nil })
}

func (b *Backend) DeleteObjectTagging(ctx context.Context, bucket, key string) error {
	return b.PutObjectTagging(ctx, bucket, key, nil)
}
func (b *Backend) SetBucketACL(context.Context, string, fsapi.ACL) error {
	return fsapi.ErrUnsupportedOperation
}
func (b *Backend) BucketACL(ctx context.Context, bucket string) (fsapi.ACL, error) {
	_, err := b.tenant(ctx, bucket)
	return fsapi.ACLPrivate, err
}
func (b *Backend) ObjectACL(ctx context.Context, bucket, key string) (fsapi.ACL, error) {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return fsapi.ACLPrivate, err
	}
	if _, err = b.st.Current(tenantID, key); err != nil {
		return fsapi.ACLPrivate, fsapi.ErrObjectNotFound
	}
	return fsapi.ACLPrivate, nil
}
func (b *Backend) SetObjectACL(context.Context, string, string, fsapi.ACL) error {
	return fsapi.ErrUnsupportedOperation
}
func (b *Backend) ObjectOwner(context.Context, string, string) (fsapi.Owner, error) {
	return fsapi.Owner{}, nil
}

// Multipart uploads live under staging/s3-multipart/<id>/: meta.json for the
// upload, <n>.part plus <n>.json for each part (so recording a part never
// rewrites the others), and complete.json once the object is published, which
// makes a retried CompleteMultipartUpload return the same answer.
type multipartMeta struct {
	UploadID  string               `json:"upload_id"`
	Tenant    string               `json:"tenant"`
	Bucket    string               `json:"bucket"`
	Key       string               `json:"key"`
	Initiated time.Time            `json:"initiated"`
	Metadata  fsapi.ObjectMetadata `json:"metadata"`
	Tags      []fsapi.Tag          `json:"tags"`
}

type completion struct {
	ETag        string    `json:"etag"`
	ObjectID    string    `json:"object_id"`
	CompletedAt time.Time `json:"completed_at"`
}

func (b *Backend) dir(id string) string { return filepath.Join(b.multipartRoot, filepath.Base(id)) }

func (b *Backend) loadMultipart(id string) (multipartMeta, error) {
	var m multipartMeta
	raw, err := os.ReadFile(filepath.Join(b.dir(id), "meta.json"))
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return m, fsapi.ErrUploadNotFound
	}
	return m, nil
}

func writeJSONFile(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := name + ".tmp"
	if err = os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

func (b *Backend) upload(ctx context.Context, bucket, key, id string) (multipartMeta, error) {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return multipartMeta{}, err
	}
	m, err := b.loadMultipart(id)
	if err != nil || m.Bucket != bucket || m.Key != key || m.Tenant != tenantID {
		return m, fsapi.ErrUploadNotFound
	}
	return m, nil
}

func (b *Backend) CreateMultipartUpload(ctx context.Context, req *fsapi.CreateMultipartUploadRequest) (*fsapi.MultipartUpload, error) {
	tenantID, err := b.tenant(ctx, req.Bucket)
	if err != nil {
		return nil, err
	}
	if _, err := objectKey(req.Key); err != nil {
		return nil, err
	}
	if err := b.st.AdmitUpload(tenantID); err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	m := multipartMeta{UploadID: id, Tenant: tenantID, Bucket: req.Bucket, Key: req.Key, Initiated: time.Now().UTC(), Metadata: req.Metadata, Tags: req.Tags}
	if err = os.MkdirAll(b.dir(id), 0o750); err != nil {
		return nil, err
	}
	if err = writeJSONFile(filepath.Join(b.dir(id), "meta.json"), m); err != nil {
		return nil, err
	}
	return &fsapi.MultipartUpload{UploadID: id, Bucket: req.Bucket, Key: req.Key, Initiated: m.Initiated}, nil
}

func (b *Backend) UploadPart(ctx context.Context, req *fsapi.UploadPartRequest) (*fsapi.Part, error) {
	unlock := b.lockRead(req.UploadID)
	defer unlock()
	m, err := b.upload(ctx, req.Bucket, req.Key, req.UploadID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(b.dir(m.UploadID), "complete.json")); err == nil {
		return nil, fsapi.ErrUploadNotFound
	}
	// Parts count against the tenant's concurrent-upload limit like any
	// other upload.
	release, err := b.st.AcquireSlot(ctx, m.Tenant)
	if err != nil {
		return nil, err
	}
	defer release()
	dir := b.dir(m.UploadID)
	tmpID, err := randomID()
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, strconv.Itoa(req.PartNumber)+"."+tmpID+".tmp")
	defer os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	h := md5.New()
	n, copyErr := copyMetered(ctx, b.st, m.Tenant, io.MultiWriter(f, h), req.Reader)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	p := fsapi.Part{PartNumber: req.PartNumber, ETag: hex.EncodeToString(h.Sum(nil)), Size: n, LastModified: time.Now().UTC()}
	final := filepath.Join(dir, strconv.Itoa(req.PartNumber))
	if err = os.Rename(tmp, final+".part"); err != nil {
		return nil, err
	}
	if err = writeJSONFile(final+".json", p); err != nil {
		return nil, err
	}
	return &p, nil
}

func copyMetered(ctx context.Context, st *store.Store, tenantID string, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 1<<20)
	var n int64
	for {
		r, rerr := src.Read(buf)
		if r > 0 {
			if err := st.WaitUpload(ctx, tenantID, r); err != nil {
				return n, err
			}
			w, werr := dst.Write(buf[:r])
			n += int64(w)
			if werr != nil {
				return n, werr
			}
		}
		if rerr == io.EOF {
			return n, nil
		}
		if rerr != nil {
			return n, rerr
		}
	}
}

func (b *Backend) parts(id string) (map[int]fsapi.Part, error) {
	entries, err := os.ReadDir(b.dir(id))
	if err != nil {
		return nil, fsapi.ErrUploadNotFound
	}
	out := map[int]fsapi.Part{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || name == "meta.json" || name == "complete.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(b.dir(id), name))
		if err != nil {
			continue
		}
		var p fsapi.Part
		if json.Unmarshal(raw, &p) == nil {
			out[p.PartNumber] = p
		}
	}
	return out, nil
}

func (b *Backend) ListParts(ctx context.Context, bucket, key, id string) ([]fsapi.Part, error) {
	if _, err := b.upload(ctx, bucket, key, id); err != nil {
		return nil, err
	}
	parts, err := b.parts(id)
	if err != nil {
		return nil, err
	}
	out := make([]fsapi.Part, 0, len(parts))
	for _, p := range parts {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PartNumber < out[j].PartNumber })
	return out, nil
}

func (b *Backend) ListMultipartUploads(ctx context.Context, bucket string) ([]fsapi.MultipartUpload, error) {
	tenantID, err := b.tenant(ctx, bucket)
	if err != nil {
		return nil, err
	}
	dirs, err := os.ReadDir(b.multipartRoot)
	if err != nil {
		return nil, err
	}
	out := []fsapi.MultipartUpload{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(b.dir(d.Name()), "complete.json")); err == nil {
			continue
		}
		m, e := b.loadMultipart(d.Name())
		if e == nil && m.Tenant == tenantID && m.Bucket == bucket {
			out = append(out, fsapi.MultipartUpload{UploadID: m.UploadID, Bucket: m.Bucket, Key: m.Key, Initiated: m.Initiated})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key == out[j].Key {
			return out[i].UploadID < out[j].UploadID
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// CompleteMultipartUpload assembles the parts into one object. The work is
// detached from the request: a client whose read timeout expires during a
// long assembly retries, waits for the same assembly, and gets the same
// answer, instead of the parts being thrown away.
func (b *Backend) CompleteMultipartUpload(ctx context.Context, req *fsapi.CompleteMultipartUploadRequest) (*fsapi.CompleteMultipartUploadResponse, error) {
	unlock := b.lockWrite(req.UploadID)
	defer unlock()
	m, err := b.upload(ctx, req.Bucket, req.Key, req.UploadID)
	if err != nil {
		return nil, err
	}
	done := filepath.Join(b.dir(m.UploadID), "complete.json")
	if raw, err := os.ReadFile(done); err == nil {
		var c completion
		if json.Unmarshal(raw, &c) == nil {
			return &fsapi.CompleteMultipartUploadResponse{Location: "/" + req.Bucket + "/" + req.Key, Bucket: req.Bucket, Key: req.Key, ETag: c.ETag}, nil
		}
	}
	all, err := b.parts(m.UploadID)
	if err != nil {
		return nil, err
	}
	ordered := make([]fsapi.Part, 0, len(req.Parts))
	var total int64
	last := 0
	for _, wanted := range req.Parts {
		p, ok := all[wanted.PartNumber]
		if !ok || !strings.EqualFold(strings.Trim(wanted.ETag, "\""), p.ETag) {
			return nil, fsapi.ErrInvalidPart
		}
		if wanted.PartNumber <= last {
			return nil, fsapi.ErrInvalidPartOrder
		}
		last = wanted.PartNumber
		ordered = append(ordered, p)
		total += p.Size
	}
	// The parts stay on disk while the object is assembled, so completion
	// needs room for a second copy. Reserve it, so concurrent completions
	// cannot all pass against the same free space.
	releaseSpace, ok := b.st.Reserve(total)
	if !ok {
		return nil, store.ErrInsufficient
	}
	defer releaseSpace()
	b.assembly <- struct{}{}
	defer func() { <-b.assembly }()
	work := context.WithoutCancel(ctx)
	h, err := b.st.BeginInternalUpload(work, m.Tenant, m.Key, "s3-multipart")
	if err != nil {
		return nil, err
	}
	whole := md5.New()
	var off int64
	for _, p := range ordered {
		if off, err = appendPart(h, filepath.Join(b.dir(m.UploadID), strconv.Itoa(p.PartNumber)+".part"), off); err != nil {
			h.Fail(err)
			_ = h.Close()
			return nil, err
		}
		raw, _ := hex.DecodeString(p.ETag)
		whole.Write(raw)
	}
	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(whole.Sum(nil)), len(ordered))
	h.SetObjectMeta(store.ObjectMeta{ETag: etag, Metadata: metadataMap(m.Metadata), Tags: tagMap(m.Tags)})
	if err = h.Close(); err != nil {
		// The parts are kept: the client can retry the completion.
		return nil, err
	}
	if err := writeJSONFile(done, completion{ETag: etag, ObjectID: h.ID(), CompletedAt: time.Now().UTC()}); err != nil {
		return nil, err
	}
	b.removeParts(m.UploadID)
	return &fsapi.CompleteMultipartUploadResponse{Location: "/" + req.Bucket + "/" + req.Key, Bucket: req.Bucket, Key: req.Key, ETag: etag}, nil
}

func appendPart(h *store.UploadHandle, name string, off int64) (int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return off, err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, err := h.WriteAt(buf[:n], off); err != nil {
				return off, err
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			return off, nil
		}
		if rerr != nil {
			return off, rerr
		}
	}
}

// removeParts deletes the part files of a completed upload but keeps meta and
// the completion record until the cleanup TTL, for idempotent retries.
func (b *Backend) removeParts(id string) {
	entries, _ := os.ReadDir(b.dir(id))
	for _, e := range entries {
		if n := e.Name(); n != "meta.json" && n != "complete.json" {
			_ = os.Remove(filepath.Join(b.dir(id), n))
		}
	}
}

func (b *Backend) AbortMultipartUpload(ctx context.Context, bucket, key, id string) error {
	unlock := b.lockWrite(id)
	defer unlock()
	if _, err := b.upload(ctx, bucket, key, id); err != nil {
		return err
	}
	return os.RemoveAll(b.dir(id))
}

func (b *Backend) MaintainMultipart(ctx context.Context, interval, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = b.cleanupMultipart(ctx, ttl)
		}
	}
}

// lastActivity is the newest modification time inside an upload directory.
func (b *Backend) lastActivity(id string) (time.Time, error) {
	info, err := os.Stat(b.dir(id))
	if err != nil {
		return time.Time{}, err
	}
	latest := info.ModTime()
	entries, _ := os.ReadDir(b.dir(id))
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	return latest, nil
}

// cleanupMultipart removes uploads idle for longer than ttl. Only candidates
// are locked, so active uploads are never paused by the sweep.
func (b *Backend) cleanupMultipart(ctx context.Context, ttl time.Duration) error {
	entries, err := os.ReadDir(b.multipartRoot)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		if last, err := b.lastActivity(id); err != nil || now.Sub(last) < ttl {
			continue
		}
		unlock := b.lockWrite(id)
		if last, err := b.lastActivity(id); err == nil && now.Sub(last) >= ttl {
			_ = os.RemoveAll(b.dir(id))
		}
		unlock()
	}
	return nil
}

func metadataMap(m fsapi.ObjectMetadata) map[string]string {
	out := map[string]string{}
	for k, v := range map[string]string{"content-type": m.ContentType, "cache-control": m.CacheControl, "content-disposition": m.ContentDisposition, "content-encoding": m.ContentEncoding, "expires": m.Expires} {
		if v != "" {
			out[k] = v
		}
	}
	for k, v := range m.UserMetadata {
		out["meta-"+k] = v
	}
	return out
}

func metadataFromMap(m map[string]string) fsapi.ObjectMetadata {
	out := fsapi.ObjectMetadata{ContentType: m["content-type"], CacheControl: m["cache-control"], ContentDisposition: m["content-disposition"], ContentEncoding: m["content-encoding"], Expires: m["expires"], UserMetadata: map[string]string{}}
	for k, v := range m {
		if strings.HasPrefix(k, "meta-") {
			out.UserMetadata[strings.TrimPrefix(k, "meta-")] = v
		}
	}
	return out
}

func tagMap(tags []fsapi.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		out[t.Key] = t.Value
	}
	return out
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
