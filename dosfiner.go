package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- Globals / Flags ----------

var (
	targetURL       string
	dataPayload     string
	concurrency     int
	proxyAddress    string
	httpHeaders     headerSlice
	printedMessages []string
	wg              sync.WaitGroup
	flagGet         bool
	flagPost        bool
	verboseErrors   bool
	totalRequests   uint64
	firstErrors     uint64
	outputMu        sync.Mutex

	rawRequestFile string
	forceSSL       bool
)

const maxFirstErrors = 10

type headerSlice []string

func (h *headerSlice) String() string { return fmt.Sprintf("%v", *h) }
func (h *headerSlice) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func forceCRLF(input string) string {
	placeholder := "\x00CRLF\x00"
	out := strings.ReplaceAll(input, "\r\n", placeholder)
	out = strings.ReplaceAll(out, "\n", "\r\n")
	out = strings.ReplaceAll(out, placeholder, "\r\n")
	return out
}

// -------------------------------------

func main() {
	flag.BoolVar(&flagGet, "g", false, "Use GET request (requires -u)")
	flag.BoolVar(&flagPost, "p", false, "Use POST request (requires -u)")
	flag.StringVar(&targetURL, "u", "", "Target URL (ignored if -r used)")
	flag.StringVar(&dataPayload, "d", "", "POST data (x-www-form-urlencoded)")
	flag.IntVar(&concurrency, "t", 500, "Number of concurrent threads")
	flag.StringVar(&proxyAddress, "proxy", "", "Proxy address (http://127.0.0.1:8080, socks5://127.0.0.1:9050)")
	flag.Var(&httpHeaders, "H", "Custom HTTP header (repeatable)")
	flag.BoolVar(&verboseErrors, "v", false, "Print every request error")

	flag.StringVar(&rawRequestFile, "r", "", "Read raw HTTP request from file (like sqlmap -r)")
	flag.BoolVar(&forceSSL, "force-ssl", false, "Force https")

	flag.Usage = func() {
		fmt.Println("=====================================================")
		fmt.Println(" DoS Finder - by Paweł Zdunek (AFINE)")
		fmt.Println("=====================================================")
		fmt.Println("Usage: dosfiner [options]")
		fmt.Println("  -g, -p, -u, -d, -H, -t, -proxy, -v, etc.")
		fmt.Println("  -r <file> to send raw request from file")
		fmt.Println("  --force-ssl to switch http -> https")
		fmt.Println("Example: dosfiner -r request.txt -t 10 --force-ssl -proxy socks5://127.0.0.1:9050")
	}

	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	if concurrency <= 0 {
		fmt.Println("Invalid -t value: must be greater than 0.")
		return
	}

	if rawRequestFile != "" {
		// Raw mode
		rawData, err := parseRawRequestFromFile(rawRequestFile)
		if err != nil {
			fmt.Println("Error parsing raw request:", err)
			return
		}
		client, err := createHTTPClient(proxyAddress)
		if err != nil {
			fmt.Println("Error creating HTTP client:", err)
			return
		}
		wg.Add(concurrency)
		for i := 0; i < concurrency; i++ {
			go doRawRequest(client, rawData)
		}
		wg.Wait()
		fmt.Println("\nFinished sending requests (raw mode).")
		return
	}

	// Normal mode
	if targetURL == "" {
		fmt.Println("You must specify -u or use -r.")
		flag.Usage()
		return
	}
	if !flagGet && !flagPost {
		fmt.Println("You must choose -g or -p (unless using -r).")
		flag.Usage()
		return
	}

	if forceSSL {
		if strings.HasPrefix(strings.ToLower(targetURL), "http://") {
			targetURL = "https://" + targetURL[7:]
		} else if !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
			targetURL = "https://" + targetURL
		}
	}

	client, err := createHTTPClient(proxyAddress)
	if err != nil {
		fmt.Println("Error creating HTTP client:", err)
		return
	}

	// Parse -H flags
	headerMap := make(map[string]string)
	for _, h := range httpHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headerMap[name] = value
		}
	}

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		if flagPost {
			go doPOST(client, headerMap, targetURL, dataPayload)
		} else {
			go doGET(client, headerMap, targetURL)
		}
	}
	wg.Wait()
	fmt.Println("\nFinished sending requests.")
}

// -------------- Creating client with minimal rewriting --------------
func createHTTPClient(proxyAddr string) (*http.Client, error) {
	// custom transport to reduce rewriting
	dialer := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	tr := &http.Transport{
		DisableCompression: true,  // no transparent gz
		ForceAttemptHTTP2:  false, // skip http2
		DialContext:        dialer,
	}
	if proxyAddr != "" {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		switch strings.ToLower(proxyURL.Scheme) {
		case "http", "https":
			tr.Proxy = http.ProxyURL(proxyURL)
		case "socks5", "socks5h":
			socksDialer, err := newSOCKS5DialContext(proxyURL)
			if err != nil {
				return nil, err
			}
			tr.DialContext = socksDialer
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5, or socks5h)", proxyURL.Scheme)
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}, nil
}

// -------------- Normal GET/POST --------------
func doGET(client *http.Client, headers map[string]string, urlStr string) {
	defer wg.Done()
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		recordError("create GET request", err)
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		recordError("GET request", err)
		return
	}
	defer resp.Body.Close()
	handleResponseCode(resp.StatusCode)
}

func doPOST(client *http.Client, headers map[string]string, urlStr, bodyStr string) {
	defer wg.Done()
	req, err := http.NewRequest("POST", urlStr, strings.NewReader(bodyStr))
	if err != nil {
		recordError("create POST request", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		recordError("POST request", err)
		return
	}
	defer resp.Body.Close()
	handleResponseCode(resp.StatusCode)
}

// -------------- RAW MODE --------------
type rawRequestData struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

func doRawRequest(client *http.Client, raw *rawRequestData) {
	defer wg.Done()
	bodyReader := strings.NewReader(raw.Body)

	req, err := http.NewRequest(raw.Method, raw.URL, bodyReader)
	if err != nil {
		recordError("create raw request", err)
		return
	}
	req.ContentLength = int64(len(raw.Body))

	for k, v := range raw.Headers {
		if strings.ToLower(k) == "content-length" {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		recordError("raw request", err)
		return
	}
	defer resp.Body.Close()
	handleResponseCode(resp.StatusCode)
}

func parseRawRequestFromFile(filePath string) (*rawRequestData, error) {
	rawBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	rawStr := string(rawBytes)

	sepIndex := strings.Index(rawStr, "\r\n\r\n")
	sepLen := 4
	if sepIndex == -1 {
		sepIndex = strings.Index(rawStr, "\n\n")
		sepLen = 2
	}

	headerPart := rawStr
	bodyPart := ""
	if sepIndex != -1 {
		headerPart = rawStr[:sepIndex]
		bodyPart = rawStr[sepIndex+sepLen:]
	}

	var lines []string
	if strings.Contains(headerPart, "\r\n") {
		lines = strings.Split(headerPart, "\r\n")
	} else {
		lines = strings.Split(headerPart, "\n")
	}

	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid request file (no lines)")
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", firstLine)
	}
	method := parts[0]
	path := parts[1]

	hdrMap := make(map[string]string)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			hdrMap[k] = v
		}
	}
	host := getHeaderCaseInsensitive(hdrMap, "Host")
	if host == "" {
		return nil, fmt.Errorf("no Host header found")
	}

	scheme := "http"
	if strings.Contains(host, ":443") {
		scheme = "https"
	}
	if forceSSL {
		scheme = "https"
	}

	if ct := getHeaderCaseInsensitive(hdrMap, "Content-Type"); ct != "" {
		if strings.Contains(strings.ToLower(ct), "multipart/form-data") {
			bodyPart = forceCRLF(bodyPart)
		}
	}

	fullURL := path
	if !strings.HasPrefix(strings.ToLower(path), "http://") && !strings.HasPrefix(strings.ToLower(path), "https://") {
		fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
	}
	return &rawRequestData{
		Method:  method,
		URL:     fullURL,
		Headers: hdrMap,
		Body:    bodyPart,
	}, nil
}

// -------------- Helpers --------------
func handleResponseCode(sc int) {
	total := atomic.AddUint64(&totalRequests, 1)
	outputMu.Lock()
	fmt.Printf("\r%d requests have been sent", total)
	outputMu.Unlock()
	if sc == 429 {
		printOnce("You have been throttled (429)")
	} else if sc == 500 {
		printOnce("Status code 500 received")
	}
}

func printOnce(msg string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if !strings.Contains(strings.Join(printedMessages, " "), msg) {
		fmt.Printf("\n%s after %d requests\n", msg, atomic.LoadUint64(&totalRequests))
		printedMessages = append(printedMessages, msg)
	}
}

func recordError(operation string, err error) {
	count := atomic.AddUint64(&firstErrors, 1)
	if !verboseErrors && count > maxFirstErrors {
		return
	}

	outputMu.Lock()
	defer outputMu.Unlock()
	if verboseErrors || count <= maxFirstErrors {
		fmt.Printf("\n%s error: %v\n", operation, err)
	}
	if count == maxFirstErrors && !verboseErrors {
		fmt.Println("Further request errors suppressed. Use -v to print all errors.")
	}
}

func getHeaderCaseInsensitive(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func newSOCKS5DialContext(proxyURL *url.URL) (func(context.Context, string, string) (net.Conn, error), error) {
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("socks5 proxy must include host and port")
	}

	username := ""
	password := ""
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unsupported network for socks5 proxy: %s", network)
		}

		d := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, err
		}

		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
			defer conn.SetDeadline(time.Time{})
		}

		if err := socks5Handshake(conn, address, username, password); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, nil
}

func socks5Handshake(conn net.Conn, targetAddress, username, password string) error {
	methods := []byte{0x00}
	if username != "" || password != "" {
		methods = append(methods, 0x02)
	}
	if len(methods) > 255 {
		return fmt.Errorf("too many socks5 authentication methods")
	}

	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil {
		return err
	}
	if greeting[0] != 0x05 {
		return fmt.Errorf("invalid socks5 version in proxy response")
	}

	switch greeting[1] {
	case 0x00:
	case 0x02:
		if err := socks5UsernamePasswordAuth(conn, reader, username, password); err != nil {
			return err
		}
	case 0xff:
		return fmt.Errorf("socks5 proxy rejected authentication methods")
	default:
		return fmt.Errorf("unsupported socks5 authentication method: 0x%02x", greeting[1])
	}

	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portText)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("target host is too long for socks5: %s", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, replyHeader); err != nil {
		return err
	}
	if replyHeader[0] != 0x05 {
		return fmt.Errorf("invalid socks5 version in connect response")
	}
	if replyHeader[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %s", socks5ReplyError(replyHeader[1]))
	}

	switch replyHeader[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, reader, 4)
	case 0x03:
		length, err := reader.ReadByte()
		if err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, reader, int64(length))
	case 0x04:
		_, err = io.CopyN(io.Discard, reader, 16)
	default:
		return fmt.Errorf("invalid socks5 address type in connect response: 0x%02x", replyHeader[3])
	}
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, reader, 2)
	return err
}

func socks5UsernamePasswordAuth(conn net.Conn, reader *bufio.Reader, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("socks5 username and password must be at most 255 bytes")
	}

	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(reader, resp); err != nil {
		return err
	}
	if resp[0] != 0x01 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 username/password authentication failed")
	}
	return nil
}

func socks5ReplyError(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error 0x%02x", code)
	}
}
