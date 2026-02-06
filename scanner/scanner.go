package scanner

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
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
	// Skipping the certificate validation is intentional.
	// This allows for discovery of self-signed and expired certificates
	conf := &tls.Config{InsecureSkipVerify: true}

	if hostname != "" {
		conf.ServerName = hostname
	}

	hostString := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := tls.Dialer{
		Config: conf,
	}
	conn, err := d.DialContext(ctx, "tcp", hostString)
	if err != nil {
		logrus.Warnf("Failed to connect to %s: %v\n", hostString, err)
		return api.Endpoint{}
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates

	if port == 443 {
		requestText := fmt.Sprintf("GET / HTTP/1.1\r\nhost: %s\r\nuser-agent: certainty-bot (+http://www.certainty-sys.com/bot)\r\n\r\n", ip)

		_, err := tlsConn.Write([]byte(requestText))
		if err != nil {
			logrus.Warnf("There was a problem sending a HTTP request to %s: %s\n", ip, err)
		}

		buf := make([]byte, 8192)

		err = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			logrus.Warnf("There was a problem setting a deadline: %s\n", err)
		}
		// Ignore the output, we don't care
		_, err = tlsConn.Read(buf)
		if err != nil {
			logrus.Warnf("There was a problem reading a HTTP response from %s: %s\n", ip, err)
		}
	}

	if len(certs) == 0 {
		logrus.Warnf("No certificates found")
		return api.Endpoint{}
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
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			return ScanPort(ip, port, hostname, timeout)
		}
		return api.Endpoint{}
	}
	defer conn.Close()

	// Set tmieout to 10 seconds for querying an actual certificate
	return CheckCert(ip, port, hostname, 10*time.Second)
}

func (ps *PortScanner) Start(portList []int, timeout time.Duration) []api.Endpoint {
	wg := sync.WaitGroup{}
	ec := make(chan api.Endpoint)

	var endpointList []api.Endpoint
	go func() {
		for ep := range ec {
			endpointList = append(endpointList, ep)
		}
	}()

	for _, port := range portList {
		err := ps.Lock.Acquire(context.TODO(), 1)
		if err != nil {
			logrus.Error("Unable to obtain lock")
			return []api.Endpoint{}
		}
		wg.Add(1)
		go func(port int) {
			defer ps.Lock.Release(1)
			defer wg.Done()
			endpoint := ScanPort(ps.Ip, port, ps.Hostname, timeout)
			if endpoint.Name != "" {
				ec <- endpoint
			}
		}(port)
	}

	wg.Wait()
	close(ec)

	return endpointList
}
