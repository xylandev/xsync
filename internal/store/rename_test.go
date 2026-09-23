package store

import (
	"errors"
	"testing"
)

func TestRenameFile(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := put(t, s, "t", "dir/old.txt", "payload")

	if err = s.Rename("t", "dir/old.txt", "dir/new.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Current("t", "dir/old.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old path still resolves: %v", err)
	}
	o, err := s.Current("t", "dir/new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if o.ID != h.ID() {
		t.Fatalf("new path points at %s, want %s", o.ID, h.ID())
	}
	// The object record must carry the new path, not just the namespace key.
	if o.Path != "dir/new.txt" {
		t.Fatalf("object path = %q, want dir/new.txt", o.Path)
	}
}

func TestRenameDirectoryTree(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	top := put(t, s, "t", "src/top.txt", "a")
	deep := put(t, s, "t", "src/nested/deep.txt", "b")
	if err = s.Mkdir("t", "src/empty"); err != nil {
		t.Fatal(err)
	}

	if err = s.Rename("t", "src", "dst"); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"dst/top.txt": top.ID(), "dst/nested/deep.txt": deep.ID()} {
		o, e := s.Current("t", path)
		if e != nil {
			t.Fatalf("%s: %v", path, e)
		}
		if o.ID != want {
			t.Fatalf("%s points at %s, want %s", path, o.ID, want)
		}
		if o.Path != path {
			t.Fatalf("object path = %q, want %q", o.Path, path)
		}
	}
	if _, err = s.Current("t", "src/top.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old tree still resolves: %v", err)
	}
	// Explicitly created directories move too, including empty ones.
	exists, err := s.DirectoryExists("t", "dst/empty")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("empty directory was not moved")
	}
	if exists, err = s.DirectoryExists("t", "src"); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Fatal("source directory still exists")
	}
}

func TestRenameEdgeCases(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put(t, s, "t", "file.txt", "a")
	put(t, s, "t", "tree/inner.txt", "b")
	put(t, s, "t", "other.txt", "c")

	cases := []struct {
		name     string
		from, to string
		want     error
	}{
		{"file onto itself", "file.txt", "file.txt", nil},
		{"directory onto itself", "tree", "tree", nil},
		{"missing path onto itself", "ghost", "ghost", ErrNotFound},
		{"missing source", "ghost", "somewhere", ErrNotFound},
		{"destination taken by file", "file.txt", "other.txt", ErrConflict},
		{"destination taken by directory", "file.txt", "tree", ErrConflict},
		{"directory into its own subtree", "tree", "tree/inner", ErrConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Rename("t", tc.from, tc.to)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// A rejected rename must leave everything where it was.
	for _, path := range []string{"file.txt", "tree/inner.txt", "other.txt"} {
		if _, err = s.Current("t", path); err != nil {
			t.Fatalf("%s disappeared after rejected renames: %v", path, err)
		}
	}
}

func TestRenameRejectsEmptyDestination(t *testing.T) {
	s, err := Open(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	put(t, s, "t", "file.txt", "a")
	err = s.Rename("t", "file.txt", "/")
	if err == nil {
		t.Fatal("renaming to an empty path succeeded")
	}
	// The message must not leak a formatting placeholder for a nil cause.
	if got := err.Error(); got != "invalid destination: empty path" {
		t.Fatalf("err = %q", got)
	}
}
