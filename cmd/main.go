package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/bwesterb/go-ristretto"
	"github.com/patrickmn/go-cache"
	"github.com/pufferfish/bs-speke"
	"io"
	"log"
	"net/http"
	"time"
)

type HTTPHandler struct {
	fileHandler http.Handler
	bspServer   *bs_speke.BSSpekeServer
}

func respondError(w http.ResponseWriter, err error) {
	log.Println(err)
	w.WriteHeader(http.StatusInternalServerError)
	jsonResponse := make(map[string]string)
	jsonResponse["status"] = err.Error()
	err = json.NewEncoder(w).Encode(jsonResponse)
}

func checkAndDecode(w http.ResponseWriter, r map[string]string, key string) ([]byte, error) {
	value, ok := r[key]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("missing %s", key)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		respondError(w, err)
		return nil, err
	}
	return decoded, nil
}

func parseBlindSaltRequest(r map[string]string) (username string, saltPoint *ristretto.Point, err error) {
	username, ok := r["username"]
	if !ok {
		return "", nil, fmt.Errorf("missing username")
	}

	saltEncoded, ok := r["salt"]
	if !ok {
		return "", nil, fmt.Errorf("missing salt")
	}

	saltBlob, err := base64.RawURLEncoding.DecodeString(saltEncoded)
	if err != nil {
		return "", nil, err
	}

	var salt ristretto.Point
	if !salt.SetBytes((*[32]byte)(saltBlob)) {
		return "", nil, fmt.Errorf("invalid salt")
	}

	return username, &salt, nil
}

func (h *HTTPHandler) handleRegisterStep1(w http.ResponseWriter, r map[string]string) {
	username, salt, err := parseBlindSaltRequest(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	response, err := h.bspServer.RegistrationStep1([]byte(username), salt)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jsonResponse := make(map[string]string)
	jsonResponse["salt"] = base64.RawURLEncoding.EncodeToString(response.BlindSalt)
	jsonResponse["blob"] = base64.RawURLEncoding.EncodeToString(response.Blob)
	err = json.NewEncoder(w).Encode(jsonResponse)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *HTTPHandler) handleRegisterStep2(w http.ResponseWriter, r map[string]string) {
	username, ok := r["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	blob, err := checkAndDecode(w, r, "blob")
	if err != nil {
		return
	}

	generatorBytes, err := checkAndDecode(w, r, "generator")
	if err != nil {
		return
	}

	publicKeyBytes, err := checkAndDecode(w, r, "publicKey")
	if err != nil {
		return
	}

	var generatorPoint, publicKeyPoint ristretto.Point
	if !generatorPoint.SetBytes((*[32]byte)(generatorBytes)) || !publicKeyPoint.SetBytes((*[32]byte)(publicKeyBytes)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = h.bspServer.RegistrationStep2([]byte(username), blob, &generatorPoint, &publicKeyPoint)
	if err != nil {
		respondError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"Account registered"}`))
}

func (h *HTTPHandler) handleLoginStep1(w http.ResponseWriter, r map[string]string) {
	username, salt, err := parseBlindSaltRequest(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	response, err := h.bspServer.LoginStep1([]byte(username), salt)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jsonResponse := make(map[string]string)
	jsonResponse["salt"] = base64.RawURLEncoding.EncodeToString(response.BlindSalt)
	jsonResponse["blob"] = base64.RawURLEncoding.EncodeToString(response.Blob)
	jsonResponse["publicKey"] = base64.RawURLEncoding.EncodeToString(response.PublicKey)
	err = json.NewEncoder(w).Encode(jsonResponse)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *HTTPHandler) handleLoginStep2(w http.ResponseWriter, r map[string]string) {
	username, ok := r["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	blob, err := checkAndDecode(w, r, "blob")
	if err != nil {
		return
	}

	ephemeralPublic, err := checkAndDecode(w, r, "ephemeralPublic")
	if err != nil {
		return
	}

	verifier, err := checkAndDecode(w, r, "verifier")
	if err != nil {
		return
	}

	var ephemeralPublicPoint ristretto.Point
	if !ephemeralPublicPoint.SetBytes((*[32]byte)(ephemeralPublic)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, _, err = h.bspServer.LoginStep2([]byte(username), verifier, blob, &ephemeralPublicPoint)
	if err != nil {
		log.Println(err)
		respondError(w, fmt.Errorf("Invalid credentials"))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"Correct credentials"}`))
}

func (h *HTTPHandler) handlePost(w http.ResponseWriter, path string, r map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	switch path {
	case "/register/step1":
		h.handleRegisterStep1(w, r)
	case "/register/step2":
		h.handleRegisterStep2(w, r)
	case "/login/step1":
		h.handleLoginStep1(w, r)
	case "/login/step2":
		h.handleLoginStep2(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if r.ContentLength > 2048 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var request map[string]string
		err = json.Unmarshal(buf, &request)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		h.handlePost(w, r.URL.Path, request)
	} else {
		h.fileHandler.ServeHTTP(w, r)
	}
}

type UserRecord struct {
	username                   string
	salt, generator, publicKey []byte
}

func main() {
	bspServer := bs_speke.NewBSSpekeServer("test server", []byte("static key"))
	cache := cache.New(30*time.Minute, 5*time.Minute)
	bspServer.SaveUser = func(username, salt, generator, publicKey []byte) error {
		usernameStr := string(username)
		if _, found := cache.Get(usernameStr); found {
			return fmt.Errorf("User already exists")
		}
		fmt.Printf("SaveUser: %s\n", usernameStr)
		record := UserRecord{
			username:  usernameStr,
			salt:      salt,
			generator: generator,
			publicKey: publicKey,
		}
		cache.Set(string(username), record, 30*time.Minute)
		return nil
	}
	bspServer.GetUserSaltAndGenerator = func(username []byte) ([]byte, []byte, error) {
		usernameStr := string(username)
		if record, found := cache.Get(usernameStr); found {
			return record.(UserRecord).salt, record.(UserRecord).generator, nil
		} else {
			return nil, nil, fmt.Errorf("User not found")
		}
	}
	bspServer.GetUserPublicKey = func(username []byte) ([]byte, error) {
		usernameStr := string(username)
		if record, found := cache.Get(usernameStr); found {
			return record.(UserRecord).publicKey, nil
		} else {
			return nil, fmt.Errorf("User not found")
		}
	}
	handler := HTTPHandler{
		fileHandler: http.FileServer(http.Dir("./cmd/")),
		bspServer:   bspServer,
	}
	log.Fatal(http.ListenAndServe(":9009", &handler))
}
