// From, https://medium.com/@KentGruber/building-a-high-performance-port-scanner-with-golang-9976181ec39d
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "agent/logging"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

type PortScanner struct {
	ip   string
	lock *semaphore.Weighted
}

func Ulimit() int64 {
	out, err := exec.Command("env", "bash", "-c", "ulimit -n").Output()
	if err != nil {
		panic(err)
	}

	s := strings.TrimSpace(string(out))

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}

	return i
}

func CheckCert(ip string, port int, timeout time.Duration) {
	conf := &tls.Config{InsecureSkipVerify: true}

	hostString := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	d := tls.Dialer{
		Config: conf,
	}
	conn, err := d.DialContext(ctx, "tcp", hostString)
	cancel() // Ensure cancel is always called

	if err != nil {
		logrus.Warnf("Failed to connect to %s: %v\n", hostString, err)
		return
	}

	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		fmt.Printf("Certificate for %s:\n", hostString)
		fmt.Printf("  Issuer Name: %s\n", cert.Issuer)
		fmt.Printf("  Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		fmt.Printf("  Common Name: %s \n", cert.Issuer.CommonName)
		fmt.Print("----\n\n")
	}
}

func ScanPort(ip string, port int, timeout time.Duration) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			ScanPort(ip, port, timeout)
		}
		return
	}

	conn.Close()
	CheckCert(ip, port, 10*time.Second)
}

func (ps *PortScanner) Start(f int, l int, timeout time.Duration) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := f; port <= l; port++ {
		ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer ps.lock.Release(1)
			defer wg.Done()
			ScanPort(ps.ip, port, timeout)
		}(port)
	}
}

func GetLocalIPs() ([]net.IP, error) {
	var ips []net.IP
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips, nil
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	var wg = sync.WaitGroup{}
	ips, err := GetLocalIPs()
	if err != nil {
		fmt.Printf("Failed to get local IPs: %s\n", err)
		return
	}
	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			ps := &PortScanner{
				ip:   ip.String(),
				lock: semaphore.NewWeighted(Ulimit()),
			}
			ps.Start(1, 65535, 500*time.Millisecond)
		}(ip)
	}

	wg.Wait()
}
