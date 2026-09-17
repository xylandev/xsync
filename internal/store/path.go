package store

import (
	"errors"
	"path"
	"strings"
)

func CleanPath(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", errors.New("path contains NUL")
	}
	name = strings.ReplaceAll(name, "\\", "/")
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", errors.New("path traversal is not allowed")
		}
	}
	clean := path.Clean("/" + name)
	if clean == "/" {
		return "", nil
	}
	clean = strings.TrimPrefix(clean, "/")
	for _, part := range strings.Split(clean, "/") {
		if part == ".." || part == "." || part == "" {
			return "", errors.New("invalid path component")
		}
	}
	return clean, nil
}

func nsKey(tenant, name string) []byte { return []byte(tenant + "\x00" + name) }
