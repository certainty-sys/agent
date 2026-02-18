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

func Ulimit() int64 {
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

	sharedLock := semaphore.NewWeighted(Ulimit())
	ec := make(chan api.Endpoint)

	consumerWg := sync.WaitGroup{}
	consumerWg.Add(1)
	var endpointList []api.Endpoint
	go func() {
		defer consumerWg.Done()
		for ep := range ec {
			endpointList = append(endpointList, ep)
		}
	}()

	wg := sync.WaitGroup{}

	for _, cidr := range conf.Cidrs {
		ips := config.BuildCidrIpList(cidr)

		portList := config.BuildCidrPortList(cidr, conf.SkipPorts)

		for _, ip := range ips {
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
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

		for _, ip := range ips {
			wg.Add(1)
			go func(ip net.IP, port int, hostname string) {
				defer wg.Done()
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

	wg.Wait()
	close(ec)
	consumerWg.Wait()

	agentData := api.Agent{
		Name:      conf.AgentName,
		Version:   "0.0.1a",
		Endpoints: endpointList,
	}

	api.API{AgentData: agentData, Key: apiKey, TestMode: testMode, TestApiUrl: testUrl}.Send()
}
