package piperutils

import (
	"archive/zip"
	"errors"
	"fmt"
	"github.com/bmatcuk/doublestar"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
)

// FileUtils ...
type FileUtils interface {
	FileExists(filename string) (bool, error)
	Copy(src, dest string) (int64, error)
	FileRead(path string) ([]byte, error)
	FileWrite(path string, content []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}

// Files ...
type Files struct {
}

// FileExists returns true if the file system entry for the given path exists and is not a directory.
func (f Files) FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)

	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return !info.IsDir(), nil
}

// FileExists returns true if the file system entry for the given path exists and is not a directory.
func FileExists(filename string) (bool, error) {
	return Files{}.FileExists(filename)
}

// DirExists returns true if the file system entry for the given path exists and is a directory.
func (f Files) DirExists(path string) (bool, error) {
	info, err := os.Stat(path)

	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return info.IsDir(), nil
}

// Copy ...
func (f Files) Copy(src, dst string) (int64, error) {

	exists, err := f.FileExists(src)

	if err != nil {
		return 0, err
	}

	if !exists {
		return 0, errors.New("Source file '" + src + "' does not exist")
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

// FindFiles ...
func FindFiles(root string, pattern string) ([]string, error) {

	var files []string

	r, e := regexp.Compile(pattern)
	if e != nil {
		return files, e
	}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if ! info.IsDir() && r.MatchString(info.Name()) {
			files = append(files, path + "/" + info.Name())
		}

		return nil

	}); err != nil {
		return files, err
	}

	return files, nil
}
