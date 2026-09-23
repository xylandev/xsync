package s3adapter

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	fsapi "github.com/go-faster/fs"
	"github.com/go-faster/fs/auth"
	fsserver "github.com/go-faster/fs/server"
	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/model"
	"github.com/xylandev/xsync/internal/store"
)

type Server struct {
	cfg        config.S3Config
	tls        config.TLSConfig
	tenants    []config.Tenant
	backend    *Backend
	partialTTL time.Duration
	log        *slog.Logger
}

func New(cfg config.S3Config, tlsCfg config.TLSConfig, tenants []config.Tenant, st *store.Store, partialTTL time.Duration, log *slog.Logger) *Server {
	return &Server{cfg: cfg, tls: tlsCfg, tenants: tenants, backend: NewBackend(st, tenants), partialTTL: partialTTL, log: log}
}
func (s *Server) Serve(ctx context.Context) error {
	go s.backend.MaintainMultipart(ctx, 30*time.Second, s.partialTTL)
	keys := make([]auth.Key, 0, len(s.tenants))
	for _, t := range s.tenants {
		if t.S3AccessKey != "" {
			keys = append(keys, auth.Key{AccessKey: t.S3AccessKey, SecretKey: t.S3SecretKey, UserID: t.ID, DisplayName: t.ID, Grants: []auth.Grant{{Pattern: t.S3Bucket, Permission: auth.Write}}})
		}
	}
	authStore, err := auth.NewStore(auth.Config{Keys: keys})
	if err != nil {
		return err
	}
	h := s.capacityGuard(accessKeyContext(fsserver.NewHandler(s.backend, fsserver.WithAuth(authStore), fsserver.WithOwnerIsolation(false))))
	httpServer := &http.Server{Addr: s.cfg.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	s.log.Info("S3 HTTPS listening", "addr", s.cfg.Listen)
	err = httpServer.ListenAndServeTLS(s.tls.CertFile, s.tls.KeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) capacityGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodPut || r.Method == http.MethodPost) && !s.backend.st.AllowNewUpload() {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "<Error><Code>SlowDown</Code><Message>storage capacity protection is active</Message></Error>")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Backend struct {
	st            *store.Store
	tenants       []config.Tenant
	buckets       map[string]string
	created       map[string]time.Time
	multipartRoot string
	locksMu       sync.Mutex
	locks         map[string]*multipartLock
}

type multipartLock struct {
	lifecycle sync.RWMutex
	metadata  sync.Mutex
	refs      int
}

func NewBackend(st *store.Store, tenants []config.Tenant) *Backend {
	b := &Backend{st: st, tenants: tenants, buckets: map[string]string{}, created: map[string]time.Time{}, multipartRoot: filepath.Join(st.Root(), "staging", "s3-multipart"), locks: map[string]*multipartLock{}}
	_ = os.MkdirAll(b.multipartRoot, 0o750)
	for _, t := range tenants {
		if t.S3Bucket != "" {
			b.buckets[t.S3Bucket] = t.ID
			b.created[t.S3Bucket] = time.Now().UTC()
		}
	}
	return b
}

func (b *Backend) retainMultipartLock(id string) *multipartLock {
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

func (b *Backend) releaseMultipartLock(id string, l *multipartLock) {
	b.locksMu.Lock()
	defer b.locksMu.Unlock()
	l.refs--
	if l.refs == 0 && b.locks[id] == l {
		delete(b.locks, id)
	}
}

func (b *Backend) lockMultipartRead(id string) (*multipartLock, func()) {
	l := b.retainMultipartLock(id)
	l.lifecycle.RLock()
	return l, func() {
		l.lifecycle.RUnlock()
		b.releaseMultipartLock(id, l)
	}
}

func (b *Backend) lockMultipartWrite(id string) (*multipartLock, func()) {
	l := b.retainMultipartLock(id)
	l.lifecycle.Lock()
	return l, func() {
		l.lifecycle.Unlock()
		b.releaseMultipartLock(id, l)
	}
}
func (b *Backend) tenant(bucket string) (string, error) {
	t, ok := b.buckets[bucket]
	if !ok {
		return "", fsapi.ErrBucketNotFound
	}
	return t, nil
}

type accessKeyContextKey struct{}

func accessKeyContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("X-Amz-Credential")
		if value == "" {
			authz := r.Header.Get("Authorization")
			if i := strings.Index(authz, "Credential="); i >= 0 {
				value = authz[i+len("Credential="):]
				if j := strings.IndexAny(value, "/, "); j >= 0 {
					value = value[:j]
				}
			}
		}
		if i := strings.IndexByte(value, '/'); i >= 0 {
			value = value[:i]
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessKeyContextKey{}, value)))
	})
}

func (b *Backend) ListBuckets(ctx context.Context) ([]fsapi.Bucket, error) {
	out := make([]fsapi.Bucket, 0, len(b.buckets))
	access, _ := ctx.Value(accessKeyContextKey{}).(string)
	for n, tenant := range b.buckets {
		if access != "" {
			matched := false
			for _, t := range b.tenants {
				if t.S3AccessKey == access && t.ID == tenant {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, fsapi.Bucket{Name: n, CreationDate: b.created[n]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (b *Backend) CreateBucket(_ context.Context, bucket string) error {
	if _, ok := b.buckets[bucket]; ok {
		return fsapi.ErrBucketAlreadyExists
	}
	return fsapi.ErrUnsupportedOperation
}
func (b *Backend) DeleteBucket(context.Context, string) error { return fsapi.ErrUnsupportedOperation }
func (b *Backend) BucketExists(_ context.Context, bucket string) (bool, error) {
	_, ok := b.buckets[bucket]
	return ok, nil
}
func (b *Backend) ListObjects(_ context.Context, req *fsapi.ListObjectsRequest) (*fsapi.ListObjectsResponse, error) {
	tenant, err := b.tenant(req.Bucket)
	if err != nil {
		return nil, err
	}
	objects, err := b.st.ListAll(tenant, req.Prefix)
	if err != nil {
		return nil, err
	}
	out := make([]fsapi.Object, 0, len(objects))
	for _, o := range objects {
		out = append(out, fsapi.Object{Key: o.Path, Size: o.Size, LastModified: o.CreatedAt, ETag: o.ETag})
	}
	return req.FoldPage(out), nil
}

type seqWriter struct {
	h      *store.UploadHandle
	off    int64
	digest hash.Hash
}

func (w *seqWriter) Write(p []byte) (int, error) {
	n, err := w.h.WriteAt(p, w.off)
	if n > 0 {
		w.off += int64(n)
		_, _ = w.digest.Write(p[:n])
	}
	return n, err
}
func (b *Backend) PutObject(ctx context.Context, req *fsapi.PutObjectRequest) (*fsapi.PutObjectResponse, error) {
	tenant, err := b.tenant(req.Bucket)
	if err != nil {
		return nil, err
	}
	h, err := b.st.BeginUpload(ctx, tenant, req.Key, "s3")
	if err != nil {
		return nil, err
	}
	sw := &seqWriter{h: h, digest: md5.New()}
	_, copyErr := io.CopyBuffer(sw, req.Reader, make([]byte, 1<<20))
	etag := hex.EncodeToString(sw.digest.Sum(nil))
	if copyErr != nil {
		h.TransferError(copyErr)
		_ = h.Close()
		return nil, copyErr
	}
	if req.ContentMD5 != "" && !strings.EqualFold(req.ContentMD5, etag) {
		h.TransferError(fsapi.ErrBadDigest)
		_ = h.Close()
		return nil, fsapi.ErrBadDigest
	}
	if err := h.Close(); err != nil {
		return nil, err
	}
	metadata := metadataMap(req.Metadata)
	tags := tagMap(req.Tags)
	_ = b.st.UpdateObject(h.ID(), func(o *model.ObjectVersion) error { o.ETag = etag; o.Metadata = metadata; o.Tags = tags; return nil })
	return &fsapi.PutObjectResponse{ETag: etag}, nil
}
func (b *Backend) GetObject(_ context.Context, bucket, key string) (*fsapi.GetObjectResponse, error) {
	tenant, err := b.tenant(bucket)
	if err != nil {
		return nil, err
	}
	f, o, err := b.st.OpenCurrent(tenant, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fsapi.ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return &fsapi.GetObjectResponse{Reader: f, Size: o.Size, LastModified: o.CreatedAt, ETag: o.ETag, Metadata: metadataFromMap(o.Metadata), TagCount: len(o.Tags)}, nil
}
func (b *Backend) DeleteObject(_ context.Context, bucket, key string) error {
	tenant, err := b.tenant(bucket)
	if err != nil {
		return err
	}
	err = b.st.Remove(tenant, key)
	if errors.Is(err, store.ErrNotFound) {
		return fsapi.ErrObjectNotFound
	}
	return err
}

func (b *Backend) GetObjectTagging(_ context.Context, bucket, key string) ([]fsapi.Tag, error) {
	tenant, err := b.tenant(bucket)
	if err != nil {
		return nil, err
	}
	o, err := b.st.Current(tenant, key)
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
func (b *Backend) PutObjectTagging(_ context.Context, bucket, key string, tags []fsapi.Tag) error {
	tenant, err := b.tenant(bucket)
	if err != nil {
		return err
	}
	o, err := b.st.Current(tenant, key)
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
func (b *Backend) BucketACL(_ context.Context, bucket string) (fsapi.ACL, error) {
	if _, err := b.tenant(bucket); err != nil {
		return fsapi.ACLPrivate, err
	}
	return fsapi.ACLPrivate, nil
}
func (b *Backend) ObjectACL(_ context.Context, bucket, key string) (fsapi.ACL, error) {
	tenant, err := b.tenant(bucket)
	if err != nil {
		return fsapi.ACLPrivate, err
	}
	if _, err = b.st.Current(tenant, key); err != nil {
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

type multipartMeta struct {
	UploadID  string               `json:"upload_id"`
	Bucket    string               `json:"bucket"`
	Key       string               `json:"key"`
	Initiated time.Time            `json:"initiated"`
	UpdatedAt time.Time            `json:"updated_at"`
	Metadata  fsapi.ObjectMetadata `json:"metadata"`
	Tags      []fsapi.Tag          `json:"tags"`
	Parts     map[int]fsapi.Part   `json:"parts"`
}

func (b *Backend) loadMultipart(id string) (multipartMeta, error) {
	var m multipartMeta
	raw, err := os.ReadFile(filepath.Join(b.multipartRoot, id, "meta.json"))
	if err != nil {
		return m, fsapi.ErrUploadNotFound
	}
	if json.Unmarshal(raw, &m) != nil {
		return m, fsapi.ErrUploadNotFound
	}
	return m, nil
}
func (b *Backend) saveMultipart(m multipartMeta) error {
	dir := filepath.Join(b.multipartRoot, m.UploadID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "meta.tmp")
	if err = os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "meta.json"))
}
func (b *Backend) CreateMultipartUpload(_ context.Context, req *fsapi.CreateMultipartUploadRequest) (*fsapi.MultipartUpload, error) {
	if _, err := b.tenant(req.Bucket); err != nil {
		return nil, err
	}
	if !b.st.AllowNewUpload() {
		return nil, store.ErrUploadBlocked
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	m := multipartMeta{UploadID: id, Bucket: req.Bucket, Key: req.Key, Initiated: now, UpdatedAt: now, Metadata: req.Metadata, Tags: req.Tags, Parts: map[int]fsapi.Part{}}
	if err = b.saveMultipart(m); err != nil {
		return nil, err
	}
	return &fsapi.MultipartUpload{UploadID: id, Bucket: req.Bucket, Key: req.Key, Initiated: m.Initiated}, nil
}
func (b *Backend) UploadPart(ctx context.Context, req *fsapi.UploadPartRequest) (*fsapi.Part, error) {
	lock, unlock := b.lockMultipartRead(req.UploadID)
	defer unlock()
	m, err := b.loadMultipart(req.UploadID)
	if err != nil || m.Bucket != req.Bucket || m.Key != req.Key {
		return nil, fsapi.ErrUploadNotFound
	}
	dir := filepath.Join(b.multipartRoot, req.UploadID)
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
	tenant, _ := b.tenant(req.Bucket)
	var n int64
	buf := make([]byte, 1<<20)
	var copyErr error
	for {
		readN, readErr := req.Reader.Read(buf)
		if readN > 0 {
			if waitErr := b.st.WaitUpload(ctx, tenant, readN); waitErr != nil {
				copyErr = waitErr
				break
			}
			writeN, writeErr := io.MultiWriter(f, h).Write(buf[:readN])
			n += int64(writeN)
			if writeErr != nil {
				copyErr = writeErr
				break
			}
			if writeN != readN {
				copyErr = io.ErrShortWrite
				break
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			copyErr = readErr
			break
		}
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if syncErr != nil {
		return nil, syncErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	final := filepath.Join(dir, strconv.Itoa(req.PartNumber)+".part")
	lock.metadata.Lock()
	defer lock.metadata.Unlock()
	if err = os.Rename(tmp, final); err != nil {
		return nil, err
	}
	p := fsapi.Part{PartNumber: req.PartNumber, ETag: hex.EncodeToString(h.Sum(nil)), Size: n, LastModified: time.Now().UTC()}
	m, err = b.loadMultipart(req.UploadID)
	if err != nil || m.Bucket != req.Bucket || m.Key != req.Key {
		return nil, fsapi.ErrUploadNotFound
	}
	m.Parts[req.PartNumber] = p
	m.UpdatedAt = time.Now().UTC()
	if err = b.saveMultipart(m); err != nil {
		return nil, err
	}
	return &p, nil
}
func (b *Backend) ListParts(_ context.Context, bucket, key, id string) ([]fsapi.Part, error) {
	m, err := b.loadMultipart(id)
	if err != nil || m.Bucket != bucket || m.Key != key {
		return nil, fsapi.ErrUploadNotFound
	}
	out := make([]fsapi.Part, 0, len(m.Parts))
	for _, p := range m.Parts {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PartNumber < out[j].PartNumber })
	return out, nil
}
func (b *Backend) ListMultipartUploads(_ context.Context, bucket string) ([]fsapi.MultipartUpload, error) {
	if _, err := b.tenant(bucket); err != nil {
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
		m, e := b.loadMultipart(d.Name())
		if e == nil && m.Bucket == bucket {
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
func (b *Backend) CompleteMultipartUpload(ctx context.Context, req *fsapi.CompleteMultipartUploadRequest) (*fsapi.CompleteMultipartUploadResponse, error) {
	_, unlock := b.lockMultipartWrite(req.UploadID)
	defer unlock()
	m, err := b.loadMultipart(req.UploadID)
	if err != nil || m.Bucket != req.Bucket || m.Key != req.Key {
		return nil, fsapi.ErrUploadNotFound
	}
	tenant, _ := b.tenant(req.Bucket)
	// Validate the requested parts and budget for the copy before writing
	// anything: the parts stay on disk while the object is assembled, so
	// completion transiently needs room for a second copy of the whole object.
	ordered := make([]fsapi.Part, 0, len(req.Parts))
	var total int64
	for _, wanted := range req.Parts {
		p, ok := m.Parts[wanted.PartNumber]
		if !ok || !strings.EqualFold(strings.Trim(wanted.ETag, "\""), p.ETag) {
			return nil, fsapi.ErrInvalidPart
		}
		ordered = append(ordered, p)
		total += p.Size
	}
	if !b.st.HasRoomFor(total) {
		return nil, store.ErrUploadBlocked
	}
	// Assembly bytes were already metered when the parts were uploaded, so this
	// local copy must not be rate limited or counted as ingress again.
	h, err := b.st.BeginInternalUpload(ctx, tenant, req.Key, "s3-multipart")
	if err != nil {
		return nil, err
	}
	whole := md5.New()
	var off int64
	for _, p := range ordered {
		f, e := os.Open(filepath.Join(b.multipartRoot, req.UploadID, strconv.Itoa(p.PartNumber)+".part"))
		if e != nil {
			h.TransferError(e)
			_ = h.Close()
			return nil, e
		}
		buf := make([]byte, 1<<20)
		for {
			n, re := f.Read(buf)
			if n > 0 {
				if _, e = h.WriteAt(buf[:n], off); e != nil {
					f.Close()
					h.TransferError(e)
					_ = h.Close()
					return nil, e
				}
				off += int64(n)
			}
			if re == io.EOF {
				break
			}
			if re != nil {
				f.Close()
				h.TransferError(re)
				_ = h.Close()
				return nil, re
			}
		}
		f.Close()
		raw, _ := hex.DecodeString(p.ETag)
		_, _ = whole.Write(raw)
	}
	if err = h.Close(); err != nil {
		return nil, err
	}
	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(whole.Sum(nil)), len(ordered))
	_ = b.st.UpdateObject(h.ID(), func(o *model.ObjectVersion) error {
		o.ETag = etag
		o.Metadata = metadataMap(m.Metadata)
		o.Tags = tagMap(m.Tags)
		return nil
	})
	_ = os.RemoveAll(filepath.Join(b.multipartRoot, req.UploadID))
	return &fsapi.CompleteMultipartUploadResponse{Location: "/" + req.Bucket + "/" + req.Key, Bucket: req.Bucket, Key: req.Key, ETag: etag}, nil
}
func (b *Backend) AbortMultipartUpload(_ context.Context, bucket, key, id string) error {
	_, unlock := b.lockMultipartWrite(id)
	defer unlock()
	m, err := b.loadMultipart(id)
	if err != nil || m.Bucket != bucket || m.Key != key {
		return fsapi.ErrUploadNotFound
	}
	return os.RemoveAll(filepath.Join(b.multipartRoot, id))
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

func (b *Backend) cleanupMultipart(ctx context.Context, ttl time.Duration) error {
	entries, err := os.ReadDir(b.multipartRoot)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, unlock := b.lockMultipartWrite(entry.Name())
		m, loadErr := b.loadMultipart(entry.Name())
		remove := false
		if loadErr == nil {
			updated := m.UpdatedAt
			if updated.IsZero() {
				updated = m.Initiated
			}
			if now.Sub(updated) >= ttl {
				remove = true
			}
		} else if errors.Is(loadErr, fsapi.ErrUploadNotFound) {
			info, infoErr := entry.Info()
			if infoErr != nil {
				loadErr = infoErr
			} else if now.Sub(info.ModTime()) >= ttl {
				remove = true
			}
		}
		if remove {
			loadErr = os.RemoveAll(filepath.Join(b.multipartRoot, entry.Name()))
		}
		unlock()
		if loadErr != nil && !errors.Is(loadErr, fsapi.ErrUploadNotFound) {
			return loadErr
		}
	}
	return nil
}

func metadataMap(m fsapi.ObjectMetadata) map[string]string {
	out := map[string]string{"content-type": m.ContentType, "cache-control": m.CacheControl, "content-disposition": m.ContentDisposition, "content-encoding": m.ContentEncoding, "expires": m.Expires}
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
