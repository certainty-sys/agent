package scanner

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"agent/api"
)

type PortScanner struct {
	Ip       string
	Hostname string
	Lock     *semaphore.Weighted
}

func CheckCert(ip string, port int, hostname string, timeout time.Duration) api.Endpoint {
	conf := &tls.Config{InsecureSkipVerify: true}

	if hostname != "" {
		conf.ServerName = hostname
	}

	hostString := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	d := tls.Dialer{
		Config: conf,
	}
	conn, err := d.DialContext(ctx, "tcp", hostString)
	cancel() // Ensure cancel is always called

	if err != nil {
		logrus.Warnf("Failed to connect to %s: %v\n", hostString, err)
		return api.Endpoint{}
	}

	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates

	if port == 443 {
		requestText := fmt.Sprintf("GET / HTTP/1.1\nhost: %s\nuser-agent: certainty-bot (+http://www.certainty-sys.com/bot)\n\n", ip)

		length, err := tlsConn.Write([]byte(requestText))
		if err != nil {
			logrus.Warnf("There was a problem sending a HTTP request to %s: %s\n", ip, err)
		}

		buf := make([]byte, length)

		tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = tlsConn.Read(buf)
		if err != nil {
			logrus.Warnf("There was a problem reading a HTTP response from %s: %s\n", ip, err)
		}
	}

	cert := certs[0]

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	certificate := api.CertDetails{
		CommonName: cert.Subject.CommonName,
		Expiry:     cert.NotAfter.Format("2006-January-02"),
		Issuer:     cert.Issuer.CommonName,
		Pem:        string(pem),
	}

	return api.Endpoint{
		Name:        conf.ServerName,
		Port:        port,
		Certificate: certificate,
	}
}

func ScanPort(ip string, port int, hostname string, timeout time.Duration) api.Endpoint {
	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			ScanPort(ip, port, hostname, timeout)
		}
		return api.Endpoint{}
	}

	conn.Close()

	return CheckCert(ip, port, hostname, 10*time.Second)
}

func (ps *PortScanner) Start(portList []int, timeout time.Duration) []api.Endpoint {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	var endpointList []api.Endpoint

	for _, port := range portList {
		ps.Lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer ps.Lock.Release(1)
			defer wg.Done()
			endpoint := ScanPort(ps.Ip, port, ps.Hostname, timeout)
			if endpoint.Name != "" {
				endpointList = append(endpointList, endpoint)
			}
		}(port)
	}

	wg.Wait()

	return endpointList
}
