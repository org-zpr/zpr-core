package libvisa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"

	"zpr.org/vs/pkg/snio/vsio"
)

const sessionKeyFormat = 1

var (
	// For version 1, the visa services just encrypts each key with a simple word known to all.
	IngressSecret = []byte("ingress")
	EgressSecret  = []byte("egress")
)

// EncodeKeys writes the plaintext keys passed here into the visa after encrypting them for
// the ingress and egress docks.
//
// This encodes the `sessionKey` with the default secret keys for the ingress and egress nodes.
func EncodeKeysFormat1(sessionKey []byte, v *vsio.Visa) error {
	iKey, err := EncodeKey(sessionKey, IngressSecret)
	if err != nil {
		return err
	}
	eKey, err := EncodeKey(sessionKey, EgressSecret)
	if err != nil {
		return err
	}
	if v.SessionKey == nil {
		v.SessionKey = &vsio.Visa_KeySet{}
	}
	v.SessionKey.Format = 1
	v.SessionKey.IngressKey = iKey
	v.SessionKey.EgressKey = eKey
	return nil
}

// DecodeIngressKey decodes session key encoded for the ingress node using the given `secret`.
func DecodeIngressKey(v *vsio.Visa, secret []byte) ([]byte, error) {
	keys := v.GetSessionKey()
	if keys.GetFormat() != sessionKeyFormat {
		return nil, fmt.Errorf("invalid session key format: %v", keys.GetFormat())
	}
	// Format 1:
	//    md5 of the passphrase to produce 32 hex digit string
	//    hex digit string (lowercase) is used as AES key

	return DecodeKey(keys.GetIngressKey(), secret)
}

// DecodeEgressKey decodes the session key encoded for the egress node with the given `secret`.
func DecodeEgressKey(v *vsio.Visa, secret []byte) ([]byte, error) {
	keys := v.GetSessionKey()
	if keys.GetFormat() != sessionKeyFormat {
		return nil, fmt.Errorf("invalid session key format: %v", keys.GetFormat())
	}
	// Format 1:
	//    md5 of the passphrase to produce 32 hex digit string
	//    hex digit string (lowercase) is used as AES-128 key

	return DecodeKey(keys.GetEgressKey(), secret)
}

func EncodeKey(sessionkey []byte, secret []byte) ([]byte, error) {
	aesKey := makeAES128Key(secret)

	cb, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	NewNonce(nonce)
	ciphertext := gcm.Seal(nonce, nonce, sessionkey, nil) // Note we stuff the ciphertext onto the end of nonce.
	return ciphertext, nil
}

func DecodeKey(cipherTxt, secret []byte) ([]byte, error) {
	aesKey := makeAES128Key(secret)

	cb, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ctext := cipherTxt[:nonceSize], cipherTxt[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ctext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// makeAESKey makes a 128bit md5 hash which is conveniently 16bytes so we can use it as an AES-128 key.
//
// TODO: we should use a proper key derivation alg here.
func makeAES128Key(anykey []byte) []byte {
	sechash := md5.New()
	sechash.Write(anykey)
	return sechash.Sum(nil)
}
