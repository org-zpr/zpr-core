package vsio

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
)

// WriteVisaArchive writes a list of visas to a zip file.
func WriteVisaArchive(filename string, baseVisaName string, visas []*Visa) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := zip.NewWriter(file)
	for _, visa := range visas {
		header := &zip.FileHeader{
			Name:     fmt.Sprintf("%s.%d", baseVisaName, visa.IssuerId),
			Modified: time.Now(),
			Method:   zip.Deflate,
		}
		f, err := w.CreateHeader(header)
		if err != nil {
			return err
		}
		vbuf, err := proto.Marshal(visa)
		if err != nil {
			return err
		}
		_, err = f.Write(vbuf)
		if err != nil {
			return err
		}
	}
	return w.Close()
}

// ReadVisaArchive reads a list of visas from a zip file.
func ReadVisaArchive(filename string) ([]*Visa, error) {
	r, err := zip.OpenReader(filename)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var visas []*Visa
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		vbuff, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		rc.Close()
		visa := new(Visa)
		if err := proto.Unmarshal(vbuff, visa); err != nil {
			return nil, err
		}
		visas = append(visas, visa)
	}
	return visas, nil
}
