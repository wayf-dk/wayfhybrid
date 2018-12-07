package jwt

import (
	"github.com/wayf-dk/goxml"
)

// Implements the RSA family of signing methods signing methods
// Expects *rsa.PrivateKey for signing and *rsa.PublicKey for validation
type SigningMethodHSM struct {
	Name, Algo string
}

// Specific instances for RS256 and company
var (
	SigningMethodHSM256 *SigningMethodHSM
)

func init() {
	SigningMethodHSM256 = &SigningMethodHSM{"HSM256", "sha256"}
	RegisterSigningMethod(SigningMethodHSM256.Alg(), func() SigningMethod {
		return SigningMethodHSM256
	})
}

func (m *SigningMethodHSM) Alg() string {
	return m.Name
}

func (m *SigningMethodHSM) Sign(signingString string, key interface{}) (string, error) {
	digest := goxml.Hash(goxml.Algos[m.Algo].Algo, signingString)
	if sigBytes, err := goxml.Sign([]byte(digest), []byte(key.(string)), []byte(""), m.Algo); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}

func (m *SigningMethodHSM) Verify(signingString, signature string, key interface{}) error {
    return nil
}