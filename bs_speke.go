package bs_speke

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/gob"
	"errors"
	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

const (
	registrationStep1Domain = "registration-step1"
)

type BSSpekeServer struct {
	// ServerDomain is a public string identifier for the server.
	ServerDomain string
	// EphemeralKey is a ephemeral private key that is used to encrypt server state
	EphemeralKey []byte
	// StaticKey is a static private key that is used to generate fake user salt for non-existent users
	StaticKey []byte
	// SaveUser is a function that saves a user to the database
	SaveUser func(username, salt, generator, publicKey []byte) error
}

type RegistrationStep1Response struct {
	// Blob is a blob which the client should use for registration step 2
	Blob []byte
	// BlindSalt is a blinded salt that the client should use for key derivation
	BlindSalt []byte
}

type RegistrationStep1Blob struct {
	ExpireEpoch uint64
	Salt        []byte
}

func NewBSSpekeServer(serverDomain string, staticKey []byte) *BSSpekeServer {
	ephemeralKey := make([]byte, chacha20poly1305.KeySize)
	_, err := cryptorand.Read(ephemeralKey)
	if err != nil {
		panic(err)
	}
	return &BSSpekeServer{
		ServerDomain: serverDomain,
		EphemeralKey: ephemeralKey,
		StaticKey:    staticKey,
	}
}

func (server *BSSpekeServer) encryptPacket(domain string, plaintext any, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(server.EphemeralKey)
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	err = gob.NewEncoder(buffer).Encode(plaintext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+buffer.Len()+aead.Overhead())
	if _, err = cryptorand.Read(nonce); err != nil {
		panic(err)
	}

	additionalData := make([]byte, len(domain)+1+len(ad))
	copy(additionalData, domain)
	additionalData[len(domain)] = 0
	copy(additionalData[len(domain)+1:], ad)
	return aead.Seal(nonce, nonce, buffer.Bytes(), additionalData), nil
}

func (server *BSSpekeServer) decryptPacket(domain string, ciphertext, ad []byte, result any) error {
	aead, err := chacha20poly1305.NewX(server.EphemeralKey)
	if err != nil {
		return err
	}

	if len(ciphertext) < aead.NonceSize() {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	additionalData := make([]byte, len(domain)+1+len(ad))
	copy(additionalData, domain)
	additionalData[len(domain)] = 0
	copy(additionalData[len(domain)+1:], ad)
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return err
	}

	return gob.NewDecoder(bytes.NewReader(plaintext)).Decode(result)
}

func (server *BSSpekeServer) RegistrationStep1(username []byte, blindSalt *ristretto.Point) (*RegistrationStep1Response, error) {
	var r ristretto.Scalar
	r.Rand()
	blindSalt.ScalarMult(blindSalt, &r)
	body := &RegistrationStep1Blob{
		ExpireEpoch: uint64(time.Now().Unix()) + 60,
		Salt:        r.Bytes(),
	}
	blob, err := server.encryptPacket(registrationStep1Domain, body, username)
	if err != nil {
		return nil, err
	}
	return &RegistrationStep1Response{
		Blob:      blob,
		BlindSalt: blindSalt.Bytes(),
	}, nil
}

func (server *BSSpekeServer) RegistrationStep2(username, blob []byte, generator, publicKey *ristretto.Point) error {
	var body RegistrationStep1Blob
	err := server.decryptPacket(registrationStep1Domain, blob, username, &body)
	if err != nil {
		return err
	}
	if uint64(time.Now().Unix()) > body.ExpireEpoch {
		return errors.New("registration blob expired")
	}

	return server.SaveUser(username, body.Salt, generator.Bytes(), publicKey.Bytes())
}
