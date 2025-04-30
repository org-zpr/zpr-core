package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/vservice/auth"
)

func TestDecodeSSBlob(t *testing.T) {
	blob := auth.ZdpSelfSignedBlob{
		BlobType:  auth.BlobTypeSS,
		Ts:        uint64(time.Now().Unix()),
		Cn:        "some.test.cn",
		Challange: "some test challenge",
		Sig:       "some test signature",
	}

	jsonBlob, err := json.Marshal(blob)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(jsonBlob)

	blobData, err := auth.DecodeBlob(encoded)
	blobType := blobData.GetBlobType()

	require.NoError(t, err)
	require.Equal(t, auth.BlobT_SS, blobType)
	require.IsType(t, &auth.ZdpSelfSignedBlob{}, blobData)

	blobDataDecoded := blobData.(*auth.ZdpSelfSignedBlob)
	require.Equal(t, blob.BlobType, blobDataDecoded.BlobType)
	require.Equal(t, blob.Ts, blobDataDecoded.Ts)
	require.Equal(t, blob.Cn, blobDataDecoded.Cn)
	require.Equal(t, blob.Challange, blobDataDecoded.Challange)
	require.Equal(t, blob.Sig, blobDataDecoded.Sig)
}

func TestDecodeAuthCodeBlon(t *testing.T) {
	blob := auth.ZdpAuthCodeBlob{
		BlobType: auth.BlobTypeAC,
		Code:     "some test code",
		Pkce:     "some test pkce",
		ClientId: "some test client id",
		Asa:      "some test asa",
	}

	jsonBlob, err := json.Marshal(blob)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(jsonBlob)

	blobData, err := auth.DecodeBlob(encoded)
	blobType := blobData.GetBlobType()

	require.NoError(t, err)
	require.Equal(t, auth.BlobT_AC, blobType)
	require.IsType(t, &auth.ZdpAuthCodeBlob{}, blobData)

	blobDataDecoded := blobData.(*auth.ZdpAuthCodeBlob)
	require.Equal(t, blob.BlobType, blobDataDecoded.BlobType)
	require.Equal(t, blob.Code, blobDataDecoded.Code)
	require.Equal(t, blob.Pkce, blobDataDecoded.Pkce)
	require.Equal(t, blob.ClientId, blobDataDecoded.ClientId)
	require.Equal(t, blob.Asa, blobDataDecoded.Asa)
}
