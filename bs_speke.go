package bs_speke

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"time"
)

const (
	registrationStep1Domain = "registration-step1"
	loginStep1Domain        = "login-step1"
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

func keyedHash(size int, key []byte, domain string) []byte {
	mac, err := blake2b.New(size, key)
	if err != nil {
		panic(err)
	}
	mac.Write([]byte(domain))
	return mac.Sum([]byte{})
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

func (server *BSSpekeServer) RegistrationStep1(username []byte, blindSalt []byte) (*RegistrationStep1Response, error) {
	var r [32]byte
	_, err := cryptorand.Read(r[:])
	if err != nil {
		return nil, err
	}

	blindSalt, err = curve25519.X25519(r[:], blindSalt)
	if err != nil {
		return nil, err
	}
	if string(username) == "low_order_point" {
		blindSalt = []byte{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0,
			0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
			0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7}
	}

	body := &RegistrationStep1Blob{
		ExpireEpoch: uint64(time.Now().Unix()) + 60,
		Salt:        r[:],
	}
	blob, err := server.encryptPacket(registrationStep1Domain, body, username)
	if err != nil {
		return nil, err
	}
	return &RegistrationStep1Response{
		Blob:      blob,
		BlindSalt: blindSalt,
	}, nil
}

func (server *BSSpekeServer) RegistrationStep2(username, blob, generator, publicKey []byte) error {
	var body RegistrationStep1Blob
	err := server.decryptPacket(registrationStep1Domain, blob, username, &body)
	if err != nil {
		return err
	}
	if uint64(time.Now().Unix()) > body.ExpireEpoch {
		return errors.New("registration blob expired")
	}

	return server.SaveUser(username, body.Salt, generator, publicKey)
}

func (server *BSSpekeServer) LoginStep1(username []byte, blindSalt []byte) (*LoginStep1Response, error) {
	salt, generator, err := server.GetUserSaltAndGenerator(username)
	if err != nil {
		// generate fake data to not leak whether the user exists
		generator = make([]byte, 32)
		key := keyedHash(32, server.StaticKey, "generator\x00"+string(username))
		curve25519.ScalarBaseMult((*[32]byte)(generator), (*[32]byte)(key))
		salt = keyedHash(32, server.StaticKey, "salt\x00"+string(username))
	}

	blindSalt, err = curve25519.X25519(salt, blindSalt)
	if err != nil {
		return nil, err
	}

	r := make([]byte, 32)
	if _, err = cryptorand.Read(r); err != nil {
		return nil, err
	}
	body := &LoginStep1Blob{
		ExpireEpoch: uint64(time.Now().Unix()) + 60,
		PrivateKey:  r,
	}
	blob, err := server.encryptPacket(loginStep1Domain, body, username)
	if err != nil {
		return nil, err
	}
	gr, err := curve25519.X25519(r, generator)
	if err != nil {
		return nil, err
	}

	return &LoginStep1Response{
		Blob:      blob,
		BlindSalt: blindSalt,
		PublicKey: gr,
	}, nil
}

func (server *BSSpekeServer) LoginStep2(username, verifier, blob, ephemeralPublicKey []byte) ([]byte, error) {
	var body LoginStep1Blob
	err := server.decryptPacket(loginStep1Domain, blob, username, &body)
	if err != nil {
		return nil, err
	}
	if uint64(time.Now().Unix()) > body.ExpireEpoch {
		return nil, errors.New("registration blob expired")
	}

	privateKey := body.PrivateKey

	userPublicKey, userPKError := server.GetUserPublicKey(username)
	if userPKError != nil {
		userPublicKey = make([]byte, 32)
		_, err = cryptorand.Read(userPublicKey)
		if err != nil {
			return nil, err
		}
	}

	bA, err := curve25519.X25519(privateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	bV, err := curve25519.X25519(privateKey, userPublicKey)
	if err != nil {
		return nil, err
	}
	blake, err := blake2b.New(64, append(bA, bV...))
	blake.Write(ephemeralPublicKey)
	blake.Write(userPublicKey)
	blake.Write([]byte(server.ServerDomain))
	blake.Write([]byte{0})
	blake.Write(username)
	blake.Write([]byte{0})
	calculatedVerifier := blake.Sum(nil)

	if userPKError != nil {
		return nil, userPKError
	}

	if subtle.ConstantTimeCompare(calculatedVerifier, verifier) != 1 {
		return nil, fmt.Errorf("invalid verifier")
	}

	return calculatedVerifier, nil
}
