package auth

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// See also adapter/ph/src/auth.rs

const BlobTypeSS = "SS"
const BlobTypeAC = "AC"

type BlobT int

const (
	BlobT_SS BlobT = iota + 1
	BlobT_AC
)

// The two supported blobs are wildly different.  This simple interface
// is a convenience for grouping them together but user will usually end
// up having to type assert to the concrete type anyway.
type Blob interface {
	GetBlobType() BlobT
}

type ZdpSelfSignedBlob struct {
	BlobType string `json:"blob_type"`
	Ts       uint64 `json:"ts"`
	Cn       string `json:"cn"`

	// Challenge is a base64 encoded byte buffer.
	// This is created by the node and is opaque to the visa service.
	Challange string `json:"challenge"`

	// Signature is a base64 encoded byte buffer.
	// This is the signature created by the adapter using its private RSA
	// key.  The signature is SHA256/PKCS1 1.5 over these fields in order:
	//    - The `Ts` (timestamp) field in big endian order.
	//    - The `Cn` (common name) value in UTF-8.
	//    - The `Challenge` buffer (as bytes -- not as base64)
	Sig string `json:"sig"`
}

type ZdpAuthCodeBlob struct {
	BlobType string `json:"blob_type"`
	Code     string `json:"code"`
	Pkce     string `json:"pkce"`
	ClientId string `json:"client_id"`
	Asa      string `json:"asa"`
}

type ZdpBlobMinimal struct {
	BlobType string `json:"blob_type"`
}

// DecodeBlob decodes a base64 encoded blob and returns the blob object.
// The blob data is returned as an interface{} and should be
// type-asserted to the appropriate type (e.g. *ZdpSelfSignedBlob or
// *ZdpAuthCodeBlob).
func DecodeBlob(encoded string) (Blob, error) {
	blobBuf, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var typeCheck ZdpBlobMinimal
	err = json.Unmarshal(blobBuf, &typeCheck)
	if err != nil {
		return nil, err
	}

	switch typeCheck.BlobType {
	case BlobTypeSS:
		var blob ZdpSelfSignedBlob
		err = json.Unmarshal(blobBuf, &blob)
		if err != nil {
			return nil, err
		}
		return &blob, nil

	case BlobTypeAC:
		var blob ZdpAuthCodeBlob
		err = json.Unmarshal(blobBuf, &blob)
		if err != nil {
			return nil, err
		}
		return &blob, nil

	default:
		return nil, fmt.Errorf("unknown blob type: %s", typeCheck.BlobType)
	}
}

func (b *ZdpSelfSignedBlob) GetBlobType() BlobT {
	return BlobT_SS
}

func (b *ZdpAuthCodeBlob) GetBlobType() BlobT {
	return BlobT_AC
}

// Create an unsigned SS blob.
func NewZdpSelfSignedBlobUnsiged(cn string, challenge []byte) *ZdpSelfSignedBlob {
	return &ZdpSelfSignedBlob{
		BlobType:  BlobTypeSS,
		Ts:        uint64(time.Now().Unix()),
		Cn:        cn,
		Challange: base64.StdEncoding.EncodeToString(challenge),
		Sig:       "",
	}
}

// Return BLOB in transport format which is base64 encoded JSON string.
func (b *ZdpSelfSignedBlob) Encode() (string, error) {
	blobJson, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("failed to marshal blob: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blobJson), nil
}

func (b *ZdpSelfSignedBlob) Sign(privkey *rsa.PrivateKey) error {
	var msg bytes.Buffer
	binary.Write(&msg, binary.BigEndian, b.Ts)
	msg.WriteString(b.Cn)
	chalData, err := base64.StdEncoding.DecodeString(b.Challange)
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}
	msg.Write(chalData)

	hashed := sha256.Sum256(msg.Bytes())
	signature, err := rsa.SignPKCS1v15(nil, privkey, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("failed to sign blob: %w", err)
	}
	b.Sig = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifySignature verifies the signature of the self-signed blob using the
// provided public key. The passed `cn` must match the one in the blob too.
func (b *ZdpSelfSignedBlob) VerifySignature(cn string, pubkey *rsa.PublicKey) (bool, error) {
	if cn != b.Cn {
		return false, fmt.Errorf("CN mismatch: %s != %s", cn, b.Cn)
	}

	signature, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	chalData, err := base64.StdEncoding.DecodeString(b.Challange)
	if err != nil {
		return false, fmt.Errorf("failed to decode challenge: %w", err)
	}

	var msg bytes.Buffer
	binary.Write(&msg, binary.BigEndian, b.Ts)
	msg.WriteString(b.Cn)
	msg.Write(chalData)
	hashed := sha256.Sum256(msg.Bytes())
	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}
	return true, nil
}
