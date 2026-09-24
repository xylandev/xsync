package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

// The streaming digest is only usable when every byte was written in order. If
// the invalidation were wrong, the catalog would carry a SHA-256 that the
// downloader can never match and the object could never be committed away.
func TestPublishedDigestAlwaysMatchesFileContents(t *testing.T) {
	payload := bytes.Repeat([]byte("xsync-digest-"), 4096)
	want := sha256.Sum256(payload)
	split := len(payload) / 3

	cases := []struct {
		name  string
		write func(t *testing.T, h *UploadHandle)
	}{
		{
			name: "sequential",
			write: func(t *testing.T, h *UploadHandle) {
				for off := 0; off < len(payload); off += split {
					end := min(off+split, len(payload))
					if _, err := h.WriteAt(payload[off:end], int64(off)); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "out of order",
			write: func(t *testing.T, h *UploadHandle) {
				if _, err := h.WriteAt(payload[split:], int64(split)); err != nil {
					t.Fatal(err)
				}
				if _, err := h.WriteAt(payload[:split], 0); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "rewritten prefix",
			write: func(t *testing.T, h *UploadHandle) {
				if _, err := h.WriteAt(bytes.Repeat([]byte("Z"), len(payload)), 0); err != nil {
					t.Fatal(err)
				}
				if _, err := h.WriteAt(payload, 0); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated after write",
			write: func(t *testing.T, h *UploadHandle) {
				if _, err := h.WriteAt(append(bytes.Clone(payload), "trailing junk"...), 0); err != nil {
					t.Fatal(err)
				}
				if err := h.Truncate(int64(len(payload))); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(t.TempDir(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			h, err := s.BeginUpload(context.Background(), "t", "object.bin", "test")
			if err != nil {
				t.Fatal(err)
			}
			tc.write(t, h)
			if err = h.Close(); err != nil {
				t.Fatal(err)
			}

			o, err := s.Current("t", "object.bin")
			if err != nil {
				t.Fatal(err)
			}
			if o.SHA256 != hex.EncodeToString(want[:]) {
				t.Errorf("catalog sha256 = %s, want %s", o.SHA256, hex.EncodeToString(want[:]))
			}
			if o.Size != int64(len(payload)) {
				t.Errorf("catalog size = %d, want %d", o.Size, len(payload))
			}

			// Cross-check against the bytes actually on disk.
			f, _, err := s.OpenCurrent("t", "object.bin")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sum := sha256.New()
			n, err := io.Copy(sum, f)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(sum.Sum(nil)); got != o.SHA256 {
				t.Errorf("blob sha256 = %s, but catalog says %s", got, o.SHA256)
			}
			if n != o.Size {
				t.Errorf("blob is %d bytes, but catalog says %d", n, o.Size)
			}
		})
	}
}

// Resuming reuses a staging file whose existing bytes were never hashed, so the
// digest must come from a full reread.
func TestResumedUploadDigestMatchesContents(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h, err := s.BeginUpload(context.Background(), "t", "resume.bin", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.WriteAt([]byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	h.TransferError(io.ErrUnexpectedEOF)
	if err = h.Close(); err == nil {
		t.Fatal("interrupted upload reported success")
	}

	resumed, err := s.BeginUploadFromCurrent(context.Background(), "t", "resume.bin", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resumed.WriteAt([]byte(" world"), 5); err != nil {
		t.Fatal(err)
	}
	if err = resumed.Close(); err != nil {
		t.Fatal(err)
	}

	o, err := s.Current("t", "resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("hello world"))
	if o.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 = %s, want %s", o.SHA256, hex.EncodeToString(want[:]))
	}
	if o.Size != 11 {
		t.Fatalf("size = %d, want 11", o.Size)
	}
}
