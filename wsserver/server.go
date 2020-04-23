package wsserver

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
)

// WSServer :Handles http server states
type WSServer struct {
}

//GUID :
var GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

//ClientRequiredHeaders :Headers to be found in clients opening handshake
var ClientRequiredHeaders = []string{"Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version"}

//ClientOptionalHeaders :Headers that could be added in opening handshake
var ClientOptionalHeaders = []string{"Sec-WebSocket-Extensions", "Origin", "Sec-WebSocket-Protocol", "Host"}

// ServeHTTP :implements http.Handler func
func (wssrv *WSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := CheckHeaders(r, ClientRequiredHeaders)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
	}
	fmt.Println("Websocket Defaults Present")
	SendHandShake(r, w, GetOptHeaders(r, ClientOptionalHeaders))

}

//CheckHeaders :Confirm handshake has all needed headers for websocket
func CheckHeaders(r *http.Request, headers []string) error {
	var missingHeaders []string
	for _, header := range headers {
		if r.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}
	if len(missingHeaders) > 0 {
		return fmt.Errorf("%v headers not present in Request", missingHeaders)
	}
	return nil
}

//GetOptHeaders :Check which optional headers are present
func GetOptHeaders(r *http.Request, headers []string) (Optheaders []string) {
	for _, header := range headers {
		if r.Header.Get(header) != "" {
			Optheaders = append(Optheaders, header)
		}
	}
	return
}

//SendHandShake :Send Server Handshake to client
func SendHandShake(r *http.Request, w http.ResponseWriter, optionalHeaders []string) {
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Sec-WebSocket-Accept", GetKeyResponse(r.Header.Get("Sec-WebSocket-Key")))
	w.WriteHeader(http.StatusSwitchingProtocols)
	fmt.Println("Headers sent")
}

//GetKeyResponse :
func GetKeyResponse(key string) string {
	keyGUID := key + GUID
	encryptedkeyGUID := sha1.Sum([]byte(keyGUID))
	transformedKey := encryptedkeyGUID[:]
	encodedKeyStr := base64.StdEncoding.EncodeToString(transformedKey)
	return encodedKeyStr
}

// RunServer :
func RunServer() {
	myServer := WSServer{}
	server := &http.Server{Addr: ":6062", Handler: &myServer}
	server.ListenAndServe()
}
