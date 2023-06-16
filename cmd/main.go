package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/bwesterb/go-ristretto"
	"github.com/pufferfish/bs-speke"
	"io"
	"log"
	"net/http"
)

type HTTPHandler struct {
	fileHandler http.Handler
	bspServer   *bs_speke.BSSpekeServer
}

func (h *HTTPHandler) handleRegisterStep1(w http.ResponseWriter, r map[string]string) {
	username, ok := r["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	saltEncoded, ok := r["salt"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	saltBlob, err := base64.RawURLEncoding.DecodeString(saltEncoded)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var salt ristretto.Point
	if !salt.SetBytes((*[32]byte)(saltBlob)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	response, err := h.bspServer.RegistrationStep1([]byte(username), &salt)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jsonResponse := make(map[string]string)
	jsonResponse["salt"] = base64.RawURLEncoding.EncodeToString(response.BlindSalt)
	jsonResponse["blob"] = base64.RawURLEncoding.EncodeToString(response.Packet)
	err = json.NewEncoder(w).Encode(jsonResponse)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *HTTPHandler) handlePost(w http.ResponseWriter, path string, r map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	switch path {
	case "/register/step1":
		h.handleRegisterStep1(w, r)
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

func main() {
	handler := HTTPHandler{
		fileHandler: http.FileServer(http.Dir("./cmd/")),
		bspServer:   bs_speke.NewBSSpekeServer("test server", []byte("static key")),
	}
	log.Fatal(http.ListenAndServe(":9009", &handler))
}
