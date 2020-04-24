package websockets

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
)

// WSServer :Handles http server states
type WSServer struct {
}

var client = Frame{}
var server = Frame{}

func (ws *WSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := client.CheckHeaders(r, clientRequiredHeaders)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
	}
	SendHandShake(r, w, client)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
	}
	//After handshake, let us go to TCP level
	conn, bufrw, err := hj.Hijack()
	//close the connection after all things
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	bufrw.Write([]byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f})
	bufrw.Flush()
	recvbuffer := []byte{}
	for {
		if s, err := bufrw.ReadByte(); s > 0 {
			if err != nil {
				log.Printf("error reading string: %v", err)
				return
			}
			recvbuffer = append(recvbuffer, s)
			client.DecodeBytes(bufrw, &recvbuffer)
		}
		bufrw.Write([]byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f})
		bufrw.Flush()
	}

}

// Frame :Handle the Data Frame
type Frame struct {
	Fin        byte
	Opcode     byte
	Rsv        byte
	Mask       byte
	PayloadLen uint64
	Key        uint32
	PayLoad    uint64
}

const (
	uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC 6455 1.3
)

var (
	clientRequiredHeaders = []string{"Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version"}
	clientOptionalHeaders = []string{"Sec-WebSocket-Extensions", "Origin", "Sec-WebSocket-Protocol", "Host"}
	maxFrameFields        = 0
)

//CheckHeaders :Confirm handshake has all needed headers for websocket
func (f *Frame) CheckHeaders(r *http.Request, headers []string) error {
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
func (f *Frame) GetOptHeaders(r *http.Request, headers []string) (Optheaders []string) {
	for _, header := range headers {
		if r.Header.Get(header) != "" {
			Optheaders = append(Optheaders, header)
		}
	}
	return
}

//SendHandShake :Send Server Handshake to client
func SendHandShake(r *http.Request, w http.ResponseWriter, f Frame) {
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Sec-WebSocket-Accept", f.GetKeyResponse(r.Header.Get("Sec-WebSocket-Key")))
	w.WriteHeader(http.StatusSwitchingProtocols)
}

//GetKeyResponse :
func (f *Frame) GetKeyResponse(key string) string {
	keyuuid := key + uuid
	encryptedkeyuuid := sha1.Sum([]byte(keyuuid))
	transformedKey := encryptedkeyuuid[:]
	encodedKeyStr := base64.StdEncoding.EncodeToString(transformedKey)
	return encodedKeyStr
}

//DecodeBytes :
func (f *Frame) DecodeBytes(b *bufio.ReadWriter, data *[]byte) {
	if len(*data) == 1 {
		f.Fin = (*data)[0] >> 0x07
		f.Rsv = (*data)[0] >> 4 & 0x07
		f.Opcode = (*data)[0] & 0x0f
	}
	if len(*data) >= 2 {
		f.Mask = (*data)[1] & 0x80
		if f.Mask != 0x80 {
			fmt.Println("Not masked, Danger!")
		}
		f.PayloadLen = uint64((*data)[1] & 0x7f)
		if f.PayloadLen < 126 && len(*data) == 2 {
			maxFrameFields += (2 + 4 + int(f.PayloadLen)) //Add the 32bits for key
		}
		if f.PayloadLen == 126 && len(*data) == 4 {
			f.PayloadLen = uint64(binary.BigEndian.Uint16((*data)[2:4]))
			maxFrameFields += (2 + 2 + 4 + int(f.PayloadLen))
		}
		if f.PayloadLen == 127 && len(*data) == 10 {
			f.PayloadLen = binary.BigEndian.Uint64((*data)[2:10])
			maxFrameFields += (2 + 8 + 4 + int(f.PayloadLen))
		}
	}
	if len(*data) == maxFrameFields {
		b.Write(*data)
		b.Flush()
		f.DecryptMessage(*data)
		*data = nil
		maxFrameFields = 0
	}
}

//DecryptMessage :
func (f *Frame) DecryptMessage(data []byte) {
	if f.PayloadLen <= 125 {
		keys := data[2:6]
		message := make([]byte, 0)
		var i uint64 = 0
		for i < f.PayloadLen {
			letter := data[6+i] ^ keys[0+(i%4)]
			message = append(message, letter)
			i++
		}
		fmt.Println("<<", string(message))
	}
	if f.PayloadLen == 126 {
		keys := data[4:8]
		message := make([]byte, 0)
		var i uint64 = 0
		for i < f.PayloadLen {
			letter := data[8+i] ^ keys[0+(i%4)]
			message = append(message, letter)
			i++
		}
		fmt.Println("<<", string(message))
	}
	if f.PayloadLen == 127 {
		keys := data[10:14]
		message := make([]byte, 0)
		var i uint64 = 0
		for i < f.PayloadLen {
			letter := data[8+i] ^ keys[0+(i%4)]
			message = append(message, letter)
			i++
		}
		fmt.Println("<<", string(message))
	}
}

// RunServer :
func RunServer() {
	var myServer = WSServer{}
	server := &http.Server{Addr: ":6062", Handler: &myServer}
	fmt.Println("Server Started")
	server.ListenAndServe()
}
