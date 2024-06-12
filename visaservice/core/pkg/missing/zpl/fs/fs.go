package fs

import "errors"

type FileStore interface {
	// Get the base "working directory" for the store.
	//GetCWD() string

	// Abs returns arg as absolute path based on working directory of this FileStore.
	//Abs(string) (string, error)

	// Abs2 returns arg as absolute path based on a passed base directory.
	//Abs2(path, base string) (string, error)

	// Dir is implementation of filepath.Dir
	//Dir(string) string

	// Exists returns true if a file exists in the store.
	//Exists(string) bool

	// ReadFile returns the file contents.
	//ReadFile(string) ([]byte, error)
}

type MemoryFileStore struct{}

func NewMemoryFileStore() (*MemoryFileStore, error) {
	return nil, errors.New("not implemented")
}

func (mfs *MemoryFileStore) AddFile(name string, data []byte) {}
