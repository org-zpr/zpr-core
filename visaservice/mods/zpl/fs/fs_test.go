package fs_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/fs"
)

func TestFileStore(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "zplfstest")
	err := os.MkdirAll(dir, 0775)
	require.Nil(t, err)
	defer os.RemoveAll(dir)

	fs, err := fs.NewLocalDiskFileStore(dir)
	require.Nil(t, err)
	require.Equal(t, dir, fs.GetCWD())
	require.False(t, fs.Exists("file_not_there"))

	{
		p, err := fs.Abs("foo")
		require.Nil(t, err)
		require.Equal(t, filepath.Join(dir, "foo"), p)
	}
	{
		p, err := fs.Abs2("foo", "fee")
		require.Nil(t, err)
		require.Equal(t, filepath.Join("fee", "foo"), p)
	}

	fname := filepath.Join(dir, "thisisthe.way")
	fmt.Printf("writing: %v\n", fname)
	err = ioutil.WriteFile(fname, []byte("baby yoda\n"), 0644)
	require.Nil(t, err)

	{
		// Oddity: I think when I wrote the fs interface I expected the store to convert paths itself.
		//         Anyway, turns out you need to convert them yourself. So why even bother with a basedir?
		pp, err := fs.Abs("thisisthe.way")
		require.Nil(t, err)
		require.True(t, fs.Exists(pp))
		data, err := fs.ReadFile(pp)
		require.Nil(t, err)
		require.Equal(t, "baby yoda\n", string(data))
	}
}

func TestMemoryFileStore(t *testing.T) {
	mfs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)

	// Make sure that dir behaves link unix filepath.Dir
	require.Equal(t, "/foo/bar", mfs.Dir("/foo/bar/baz.js"))
	require.Equal(t, "/foo/bar", mfs.Dir("/foo/bar/baz"))
	require.Equal(t, "/foo/bar/baz", mfs.Dir("/foo/bar/baz/"))
	require.Equal(t, "/dirty/path", mfs.Dir("/dirty//path///"))
	require.Equal(t, ".", mfs.Dir("dev.txt"))
	require.Equal(t, "..", mfs.Dir("../todo.txt"))
	require.Equal(t, ".", mfs.Dir(".."))
	require.Equal(t, ".", mfs.Dir("."))
	require.Equal(t, "/", mfs.Dir("/"))
	require.Equal(t, ".", mfs.Dir(""))
}
