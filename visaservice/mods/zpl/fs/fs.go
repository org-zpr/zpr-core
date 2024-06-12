package fs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type FileStore interface {
	// Get the base "working directory" for the store.
	GetCWD() string

	// Abs returns arg as absolute path based on working directory of this FileStore.
	Abs(string) (string, error)

	// Abs2 returns arg as absolute path based on a passed base directory.
	Abs2(path, base string) (string, error)

	// Dir is implementation of filepath.Dir
	Dir(string) string

	// Exists returns true if a file exists in the store.
	Exists(string) bool

	// ReadFile returns the file contents.
	ReadFile(string) ([]byte, error)
}

type DiskFileStore struct {
	wd string
}

func NewLocalDiskFileStore(basedir string) (*DiskFileStore, error) {
	bd, err := filepath.Abs(basedir)
	if err != nil {
		return nil, err
	}
	return &DiskFileStore{
		wd: bd,
	}, nil
}

func (fs *DiskFileStore) Dir(path string) string {
	return filepath.Dir(path)
}

func (fs *DiskFileStore) GetCWD() string {
	return fs.wd
}

func (fs *DiskFileStore) Abs(path string) (string, error) {
	return fs.Abs2(path, fs.wd)
}

func (fs *DiskFileStore) Abs2(path, base string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Join(base, path), nil
}

func (fs *DiskFileStore) Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func (fs *DiskFileStore) ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

type MemoryFileStore struct {
	files map[string][]byte // name -> data
}

// NewMemoryFileStore create the memory file store. Uses "/" as separator.
func NewMemoryFileStore() (*MemoryFileStore, error) {
	return &MemoryFileStore{
		files: make(map[string][]byte), // empty
	}, nil
}

// Dir mimics unix filepath.Dir
func (mfs *MemoryFileStore) Dir(path string) string {
	bits := strings.Split(path, "/")
	if sz := len(bits); sz > 1 {
		var clean []string
		for i, seg := range bits {
			if (i > 0 && seg == "") || i >= (sz-1) {
				continue
			}
			clean = append(clean, seg)
		}
		dir := strings.Join(clean, "/")
		if dir == "" {
			return "/"
		}
		return dir
	} else if sz == 1 {
		return "."
	}
	return "/"
}

func (mfs *MemoryFileStore) AddFile(name string, data []byte) {
	mfs.files[mfs.abs(name)] = data
}

func (mfs *MemoryFileStore) GetCWD() string {
	return "/"
}

func (mfs *MemoryFileStore) abs(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func (mfs *MemoryFileStore) Abs(p string) (string, error) {
	return mfs.abs(p), nil
}

func (mfs *MemoryFileStore) Abs2(path, base string) (string, error) {
	if strings.HasPrefix(path, base) {
		return path, nil
	}
	return base + path, nil
}

func (mfs *MemoryFileStore) Exists(p string) bool {
	_, ok := mfs.files[mfs.abs(p)]
	return ok
}

func (mfs *MemoryFileStore) ReadFile(p string) ([]byte, error) {
	data, ok := mfs.files[mfs.abs(p)]
	if !ok {
		return nil, fmt.Errorf("file not found: %v", p)
	}
	return data, nil
}
