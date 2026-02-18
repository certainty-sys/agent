package scanner

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"agent/api"
)

type Host struct {
	Ip       string
	Hostname string
	Lock     *semaphore.Weighted
}

func (host Host) ScanPorts(portList []int, timeout time.Duration) []api.Endpoint {
	wg := sync.WaitGroup{}
	ec := make(chan api.Endpoint, len(portList))

	consumerWg := sync.WaitGroup{}
	consumerWg.Add(1)
	var endpointList []api.Endpoint
	go func() {
		defer consumerWg.Done()
		for ep := range ec {
			endpointList = append(endpointList, ep)
		}
	}()

	for _, port := range portList {
		err := host.Lock.Acquire(context.TODO(), 1)
		if err != nil {
			logrus.Error("Unable to obtain lock")
			break
		}
		wg.Add(1)
		go func(port int) {
			defer host.Lock.Release(1)
			defer wg.Done()
			endpoint := host.CheckCert(port, timeout)
			if endpoint.Name != "" {
				ec <- endpoint
			}
		}(port)
	}

	wg.Wait()
	close(ec)
	consumerWg.Wait()

	return endpointList
}

func (host Host) CheckCert(port int, timeout time.Duration) api.Endpoint {
	// Skipping the certificate validation is intentional.
	// This allows for discovery of self-signed and expired certificates
	conf := &tls.Config{InsecureSkipVerify: true}

	if host.Hostname != "" {
		conf.ServerName = host.Hostname
	}

	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		fmt.Sprintf("%s:%d", host.Ip, port),
		conf,
	)
	if err != nil {
		return api.Endpoint{}
	}
	defer tlsConn.Close()

	certs := tlsConn.ConnectionState().PeerCertificates

	if port == 443 {
		requestText := fmt.Sprintf("GET / HTTP/1.1\r\nhost: %s\r\nuser-agent: certainty-bot (+http://www.certainty-sys.com/bot)\r\n\r\n", host.Hostname)

		_, err := tlsConn.Write([]byte(requestText))
		if err != nil {
			logrus.Debugf("There was a problem sending a HTTP request to %s: %s\n", host.Ip, err)
		}

		buf := make([]byte, 8192)

		err = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			logrus.Debugf("There was a problem setting a deadline: %s\n", err)
		}
		// Ignore the output, we don't care
		_, err = tlsConn.Read(buf)
		if err != nil {
			logrus.Debugf("There was a problem reading a HTTP response from %s: %s\n", host.Ip, err)
		}
	}

	if len(certs) == 0 {
		logrus.Warnf("No certificates found")
		return api.Endpoint{}
	}

	cert := certs[0]

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	certificate := api.CertDetails{
		CommonName: cert.Subject.CommonName,
		Expiry:     cert.NotAfter.Format("2006-January-02"),
		Issuer:     cert.Issuer.CommonName,
		Pem:        string(pemCert),
	}

	return api.Endpoint{
		Name:        host.Hostname,
		Port:        port,
		Certificate: certificate,
	}
}
