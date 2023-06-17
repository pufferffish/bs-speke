package bs_speke

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

const (
	registrationStep1Domain = "registration-step1"
	loginStep1Domain        = "login-step1"
	clientVerifierModifier  = "client verifier modifier"
	sessionKeyModifier      = "session key modifier"
	sessionIVModifier       = "session IV modifier"
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
	// GetUserSaltAndGenerator is a function that retrieves a user's salt and generator from the database
	GetUserSaltAndGenerator func(username []byte) (salt, generator []byte, err error)
	// GetUserPublicKey is a function that retrieves a user's public key from the database
	GetUserPublicKey func(username []byte) (publicKey []byte, err error)
}

type RegistrationStep1Response struct {
	// Blob is a blob which the client should use for registration step 2
	Blob []byte
	// BlindSalt is a blinded salt that the client should use for key derivation
	BlindSalt []byte
}

type LoginStep1Response struct {
	// Blob is a blob which the client should use for registration step 2
	Blob []byte
	// BlindSalt is a blinded salt that the client should use for key derivation
	BlindSalt []byte
	// PublicKey is the server's ephemeral public key
	PublicKey []byte
}

type RegistrationStep1Blob struct {
	ExpireEpoch uint64
	Salt        []byte
}

type LoginStep1Blob struct {
	ExpireEpoch uint64
	PrivateKey  []byte
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

func keyedHash(size int, key []byte, domain string) ([]byte, error) {
	mac, err := blake2b.New(size, key)
	if err != nil {
		return nil, err
	}
	mac.Write([]byte(domain))
	return mac.Sum([]byte{}), nil
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

func (server *BSSpekeServer) LoginStep1(username []byte, blindSalt *ristretto.Point) (*LoginStep1Response, error) {
	var s, r ristretto.Scalar
	var g ristretto.Point

	salt, generator, err := server.GetUserSaltAndGenerator(username)
	if err != nil {
		// generate fake data to not leak whether the user exists
		key, err := keyedHash(32, server.StaticKey, string(username))
		if err != nil {
			return nil, err
		}
		g.SetElligator((*[32]byte)(key))
		s.Derive(key)
	} else {
		if !g.SetBytes((*[32]byte)(generator)) {
			return nil, errors.New("invalid generator")
		}
		s.SetBytes((*[32]byte)(salt))
	}

	r.Rand()
	blindSalt.ScalarMult(blindSalt, &s)
	body := &LoginStep1Blob{
		ExpireEpoch: uint64(time.Now().Unix()) + 60,
		PrivateKey:  r.Bytes(),
	}
	blob, err := server.encryptPacket(loginStep1Domain, body, username)
	if err != nil {
		return nil, err
	}
	return &LoginStep1Response{
		Blob:      blob,
		BlindSalt: blindSalt.Bytes(),
		PublicKey: g.ScalarMult(&g, &r).Bytes(),
	}, nil
}

func (server *BSSpekeServer) LoginStep2(username, verifier, blob []byte, ephemeralPublicKey *ristretto.Point) (key, iv []byte, err error) {
	var body LoginStep1Blob
	err = server.decryptPacket(loginStep1Domain, blob, username, &body)
	if err != nil {
		return nil, nil, err
	}
	if uint64(time.Now().Unix()) > body.ExpireEpoch {
		return nil, nil, errors.New("registration blob expired")
	}

	var privateKey ristretto.Scalar
	privateKey.SetBytes((*[32]byte)(body.PrivateKey))

	var userPublicKey ristretto.Point
	userPublicKeyBytes, userPKError := server.GetUserPublicKey(username)
	if userPKError != nil {
		userPublicKey.Rand()
	} else if !userPublicKey.SetBytes((*[32]byte)(userPublicKeyBytes)) {
		return nil, nil, errors.New("invalid user public key")
	}

	secrets := make([]byte, 64)
	ephemeralPublicKey.ScalarMult(ephemeralPublicKey, &privateKey).BytesInto((*[32]byte)(secrets[:32]))
	userPublicKey.ScalarMult(&userPublicKey, &privateKey).BytesInto((*[32]byte)(secrets[32:]))
	secrets, err = keyedHash(64, secrets, server.ServerDomain)
	if err != nil {
		return nil, nil, err
	}

	calculatedVerifier, err := keyedHash(32, secrets, clientVerifierModifier)
	if err != nil {
		return nil, nil, err
	}
	sessionKey, err := keyedHash(chacha20poly1305.KeySize, secrets, sessionKeyModifier)
	if err != nil {
		return nil, nil, err
	}
	sessionIV, err := keyedHash(chacha20poly1305.NonceSizeX, secrets, sessionIVModifier)
	if err != nil {
		return nil, nil, err
	}

	if userPKError != nil {
		return nil, nil, userPKError
	}

	if subtle.ConstantTimeCompare(calculatedVerifier, verifier) != 1 {
		return nil, nil, fmt.Errorf("invalid verifier")
	}

	return sessionKey, sessionIV, nil
}
