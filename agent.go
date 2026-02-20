package main

import (
	"flag"
	"net"
	"sync"
	"syscall"
	"time"

	"agent/api"
	"agent/config"
	"agent/scanner"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

func ulimit() int64 {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return 1024
	}
	return int64(rLimit.Cur)
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	conf, err := config.LoadConfig("config.yml")
	if err != nil {
		logrus.Errorf("Failed to parse config file: %s", err)
		return
	}

	apiKey := conf.ApiKey
	testUrl := ""

	testMode := flag.Bool("test", false, "Enable test mode")
	flag.Parse()

	logrus.Info("Test mode:", *testMode)
	if *testMode {
		apiKey = conf.TestApiKey
		testUrl = conf.TestApiUrl
	}

	sharedLock := semaphore.NewWeighted(ulimit())

	// Goroutine to collect the found endpoints and add them to a single list of endpoints
	ec := make(chan api.Endpoint)
	consumerWG := sync.WaitGroup{}
	consumerWG.Add(1)
	var endpointList []api.Endpoint
	go func() {
		defer consumerWG.Done()
		for ep := range ec {
			endpointList = append(endpointList, ep)
		}
	}()

	generatorWG := sync.WaitGroup{}
	for _, cidr := range conf.Cidrs {
		ips := config.BuildCidrIpList(cidr)

		portList := config.BuildCidrPortList(cidr, conf.SkipPorts)

		// goroutine to discover all endpoints on a single IP
		for _, ip := range ips {
			generatorWG.Add(1)
			go func(ip net.IP) {
				defer generatorWG.Done()
				sh := &scanner.Host{
					Ip:       ip.String(),
					Hostname: ip.String(),
					Lock:     sharedLock,
				}
				for _, ep := range sh.ScanPorts(portList, 500*time.Millisecond) {
					ec <- ep
				}
			}(ip)
		}
	}

	for _, host := range conf.Hosts {
		ips, err := net.LookupIP(host.HostName)
		if err != nil {
			logrus.Warnf("Failed to lookup hostname %s: %s\n", host.HostName, err)
			continue
		}

		// goroutine to discover all endpoints on a single hostname
		for _, ip := range ips {
			generatorWG.Add(1)
			go func(ip net.IP, port int, hostname string) {
				defer generatorWG.Done()
				sh := &scanner.Host{
					Ip:       ip.String(),
					Hostname: hostname,
					Lock:     sharedLock,
				}
				for _, ep := range sh.ScanPorts([]int{port}, 500*time.Millisecond) {
					ec <- ep
				}
			}(ip, host.Port, host.HostName)
		}
	}

	// wait for the goroutines to finish and close the endpoint collection channel
	generatorWG.Wait()
	close(ec)

	// wait for the endpoint collector to finish
	consumerWG.Wait()

	agentData := api.Agent{
		Name:      conf.AgentName,
		Version:   "0.0.1a",
		Endpoints: endpointList,
	}

	api.API{AgentData: agentData, Key: apiKey, TestMode: testMode, TestApiUrl: testUrl}.Send()
}
