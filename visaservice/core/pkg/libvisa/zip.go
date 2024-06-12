package libvisa

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"zpr.org/vsx/polio"
)

// Decompress decompresses and unmarshalls a PolicyContainer.
func Decompress(buf []byte) (*polio.PolicyContainer, error) {
	rdr := bytes.NewReader(buf)
	zr, err := gzip.NewReader(rdr)
	if err != nil {
		return nil, err
	}
	// Copy compressed data into a buffer:
	tmp := &bytes.Buffer{}
	if _, err := io.Copy(tmp, zr); err != nil {
		return nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, err
	}
	pc := &polio.PolicyContainer{}
	if err := proto.Unmarshal(tmp.Bytes(), pc); err != nil {
		return nil, err
	}
	return pc, nil
}

// Compress marshalls and compresses the PolicyContainer.
func Compress(pc *polio.PolicyContainer) ([]byte, error) {
	if pc == nil {
		return nil, errors.New("compress called on nil policy")
	}
	pbunData, err := proto.Marshal(pc)
	if err != nil {
		return nil, fmt.Errorf("policy serialization failure: %v", err)
	}
	var buf bytes.Buffer
	zipper := gzip.NewWriter(&buf)
	if _, err := zipper.Write(pbunData); err != nil {
		return nil, fmt.Errorf("compression error: %v", err)
	}
	if err := zipper.Close(); err != nil {
		return nil, fmt.Errorf("compression error: %v", err)
	}
	return buf.Bytes(), nil
}
