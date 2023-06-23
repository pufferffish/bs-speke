package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"github.com/pufferfish/bs-speke"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type HTTPHandler struct {
	fileHandler http.Handler
	bspServer   *bs_speke.BSSpekeServer
	jwtKey      []byte
}

func respondError(w http.ResponseWriter, err error) {
	log.Println(err)
	w.Header().Set("Content-Type", "application/json")
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
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		respondError(w, err)
		return nil, err
	}
	return decoded, nil
}

func parseBlindSaltRequest(r map[string]string) (username string, salt []byte, err error) {
	username, ok := r["username"]
	if !ok {
		return "", nil, fmt.Errorf("missing username")
	}

	saltEncoded, ok := r["salt"]
	if !ok {
		return "", nil, fmt.Errorf("missing salt")
	}

	salt, err = base64.StdEncoding.DecodeString(saltEncoded)
	if err != nil {
		return "", nil, err
	}

	return username, salt, nil
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
	jsonResponse["salt"] = base64.StdEncoding.EncodeToString(response.BlindSalt)
	jsonResponse["blob"] = base64.StdEncoding.EncodeToString(response.Blob)
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

	generator, err := checkAndDecode(w, r, "generator")
	if err != nil {
		return
	}

	publicKey, err := checkAndDecode(w, r, "publicKey")
	if err != nil {
		return
	}

	err = h.bspServer.RegistrationStep2([]byte(username), blob, generator, publicKey)
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
	jsonResponse["salt"] = base64.StdEncoding.EncodeToString(response.BlindSalt)
	jsonResponse["blob"] = base64.StdEncoding.EncodeToString(response.Blob)
	jsonResponse["publicKey"] = base64.StdEncoding.EncodeToString(response.PublicKey)
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

	_, err = h.bspServer.LoginStep2([]byte(username), verifier, blob, ephemeralPublic)
	if err != nil {
		log.Println(err)
		respondError(w, fmt.Errorf("Invalid credentials"))
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"nbf": time.Now().Unix(),
	})
	tokenString, err := token.SignedString(h.jwtKey)
	if err != nil {
		respondError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", "sid="+tokenString+"; Path=/; HttpOnly")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"OK"}`))
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
	case "/logout":
		w.Header().Set("Set-Cookie", "sid=; Path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *HTTPHandler) getLoggedInUser(cookie string) string {
	cookies := strings.Split(cookie, ";")
	var tokenString string
	for _, c := range cookies {
		kv := strings.Split(strings.TrimSpace(c), "=")
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		value := kv[1]
		if key == "sid" {
			tokenString = value
			break
		}
	}
	if tokenString == "" {
		return ""
	}
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.jwtKey, nil
	})
	if err != nil {
		return ""
	}
	return t.Claims.(jwt.MapClaims)["sub"].(string)
}

type TemplateData struct {
	Username   string
	IsLoggedIn bool
}

func (h *HTTPHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch path {
	case "/bs_speke.js", "/index.js":
		w.Header().Set("Content-Type", "application/javascript")
		file, err := os.Open("js" + path)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer file.Close()
		_, err = io.Copy(w, file)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "/":
		user := h.getLoggedInUser(r.Header.Get("Cookie"))
		fmt.Printf("Username: %s\n", user)
		w.Header().Set("Content-Type", "text/html")
		templ, err := template.ParseFiles("template/index.templ.html")
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var data TemplateData
		if user != "" {
			data.Username = user
			data.IsLoggedIn = true
		} else {
			data.IsLoggedIn = false
		}
		err = templ.Execute(w, &data)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "/favicon.ico":
		w.WriteHeader(http.StatusNotFound)
	default:
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusMovedPermanently)
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleGet(w, r)
	case "POST":
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
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
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
			return fmt.Errorf("Username already exists")
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
			return nil, nil, fmt.Errorf("Username not found")
		}
	}
	bspServer.GetUserPublicKey = func(username []byte) ([]byte, error) {
		usernameStr := string(username)
		if record, found := cache.Get(usernameStr); found {
			return record.(UserRecord).publicKey, nil
		} else {
			return nil, fmt.Errorf("Username not found")
		}
	}
	hmacSampleSecret := make([]byte, 32)
	_, err := cryptorand.Read(hmacSampleSecret)
	if err != nil {
		panic(err)
	}
	handler := HTTPHandler{
		fileHandler: http.FileServer(http.Dir("./cmd/")),
		bspServer:   bspServer,
		jwtKey:      hmacSampleSecret,
	}

	log.Fatal(http.ListenAndServe(":9009", &handler))
}
