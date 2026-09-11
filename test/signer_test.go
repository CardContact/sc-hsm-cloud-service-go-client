package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"net/http"
	"testing"

	openapiclient "github.com/CardContact/sc-hsm-cloud-service-go-client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	configuration := openapiclient.NewConfiguration()
	if tlsConfig, err := getTLSConfiguration(); err == nil {
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		httpClient := &http.Client{
			Transport: transport,
		}
		configuration.HTTPClient = httpClient
	}
	configuration.Servers = openapiclient.ServerConfigurations{
		{
			URL:         serviceURL,
			Description: "URL of the SmartCard-HSM Cloud Service",
		},
	}
	apiClient := openapiclient.NewAPIClient(configuration)

	keys, _, err := apiClient.DefaultAPI.GetKeyList(context.Background()).Execute()
	if err != nil {
		t.Skipf("skipping test because service is not reachable: %v", err)
	}

	for _, key := range keys {
		t.Logf("Key ID: %s, Label: %s, Type: %s, Algorithms: %v, Pubkey: %v", key.Id, key.Label, key.Type, key.Algorithms, key.Pubkey != nil)
		if key.Type == openapiclient.AES {
			continue
		}

		signer, err := openapiclient.NewSigner(apiClient, key.Id)
		if err != nil {
			t.Logf("NewSigner error for key %s: %v", key.Id, err)
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, signer)

		pubKey := signer.Public()
		require.NotNil(t, pubKey)

		msg := []byte("test message for signing")
		hash := sha256.Sum256(msg)

		var opts crypto.SignerOpts = crypto.SHA256
		if _, ok := pubKey.(*rsa.PublicKey); ok {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			}
		}

		sig, err := signer.Sign(rand.Reader, hash[:], opts)
		require.NoError(t, err)
		require.NotEmpty(t, sig)

		switch pk := pubKey.(type) {
		case *rsa.PublicKey:
			err = rsa.VerifyPSS(pk, crypto.SHA256, hash[:], sig, opts.(*rsa.PSSOptions))
			assert.NoError(t, err)
		case *ecdsa.PublicKey:
			valid := ecdsa.VerifyASN1(pk, hash[:], sig)
			assert.True(t, valid, "ECDSA signature verification failed")
		}
	}
}
