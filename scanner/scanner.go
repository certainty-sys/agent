package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	Ip   string
	Lock *semaphore.Weighted
}

func CheckCert(ip string, port int, timeout time.Duration) api.Endpoint {
	var certList []api.CertDetails

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
		return api.Endpoint{}
	}

	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		certificate := api.CertDetails{
			CommonName: cert.Subject.CommonName,
			Expiry:     cert.NotAfter.Format("2006-January-02"),
			Issuer:     cert.Issuer.CommonName,
			Pem:        base64.StdEncoding.EncodeToString(cert.Raw),
		}

		certList = append(certList, certificate)
	}

	return api.Endpoint{
		Name:        ip,
		Port:        port,
		Certificate: certList,
	}
}

func ScanPort(ip string, port int, timeout time.Duration) api.Endpoint {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			ScanPort(ip, port, timeout)
		}
		return api.Endpoint{}
	}

	conn.Close()
	endpoint := CheckCert(ip, port, 10*time.Second)

	return endpoint
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
			endpoint := ScanPort(ps.Ip, port, timeout)
			if endpoint.Name != "" {
				endpointList = append(endpointList, endpoint)
			}
		}(port)
	}

	wg.Wait()

	return endpointList
}
