package libvisa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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
func EncodeKeysFormat1(sessionKey []byte) (iKey []byte, eKey []byte, err error) {
	iKey, err = EncodeKey(sessionKey, IngressSecret)
	if err != nil {
		return
	}
	eKey, err = EncodeKey(sessionKey, EgressSecret)
	if err != nil {
		return
	}
	return
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
