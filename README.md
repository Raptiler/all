
# Dosfiner – HTTP Stress & DoS Testing Tool 🚀

**Dosfiner** is a lightweight and efficient HTTP stress-testing and Denial-of-Service (DoS) tool written in Go. Quickly simulate high-volume HTTP traffic to identify application performance bottlenecks and vulnerabilities.

## ⚡ Main Features
- Perform rapid GET/POST request flooding.
- Custom concurrency level using threads.
- Send HTTP requests directly from RAW files.
- Supports HTTP/HTTPS and SOCKS5 proxies (e.g., Burp Suite, Tor).
- Runs on macOS, Linux, and Windows.

## 📥 Installation
1. Clone the repository:
```bash
git clone https://github.com/afine-com/dosfiner.git
cd dosfiner
```
2. Build or Run Directly:
- Build binary:
```bash
go build dosfiner.go
```
- Build Windows binary from macOS/Linux:
```bash
GOOS=windows GOARCH=amd64 go build -o dosfiner.exe dosfiner.go
```
- Run directly:
```bash
go run dosfiner.go [options]
```

## 🚀 Usage Examples
- **GET request flooding (500 threads):**
```bash
./dosfiner -g -u "https://target.com/api/v1/search" -t 500
```
- **POST request flooding with data (300 threads):**
```bash
./dosfiner -p -u "https://target.com/login" -d "user=admin&pass=test" -t 300
```
- **Using HTTP Proxy (Burp Suite):**
```bash
./dosfiner -g -u "https://target.com/api" -proxy "http://127.0.0.1:8080" -t 200
```
- **Using SOCKS5 Proxy:**
```bash
./dosfiner -g -u "https://target.com/api" -proxy "socks5://127.0.0.1:9050" -t 200
```
- **Using SOCKS5 Proxy with authentication:**
```bash
./dosfiner -g -u "https://target.com/api" -proxy "socks5://user:pass@127.0.0.1:9050" -t 200
```
- **RAW HTTP Request from File:**
```bash
./dosfiner -r "/tmp/request.txt" -t 400 --force-ssl
```
- **Print all request errors while debugging:**
```bash
./dosfiner -g -u "https://target.com/api" -t 20 -v
```

## ⚠️ Important Notice
**Use responsibly.**  
Dosfiner generates intense traffic that may lead to real Denial-of-Service scenarios. Always obtain explicit permission and perform testing in controlled environments only.
