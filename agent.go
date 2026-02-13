package main

import (
	"flag"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"agent/api"
	"agent/config"
	"agent/scanner"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

const ulimitDefault = 1024

func Ulimit() int64 {
	out, err := exec.Command("env", "bash", "-c", "ulimit -n").Output()
	if err != nil {
		logrus.Error(err)
		return ulimitDefault
	}

	s := strings.TrimSpace(string(out))

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		logrus.Error(err)
		return ulimitDefault
	}

	return i
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
	ec := make(chan api.Endpoint, 100)

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
				ps := &scanner.PortScanner{
					Ip:       ip.String(),
					Hostname: ip.String(),
					Lock:     sharedLock,
				}
				for _, ep := range ps.Start(portList, 500*time.Millisecond) {
					ec <- ep
				}
			}(ip)
		}
	}

	for _, host := range conf.Hosts {
		ips, err := net.LookupIP(host.HostName)
		if err != nil {
			logrus.Warningf("Failed to lookup hostname %s: %s\n", host.HostName, err)
			continue
		}

		for _, ip := range ips {
			wg.Add(1)
			go func(ip net.IP, port int, hostname string) {
				defer wg.Done()
				ps := &scanner.PortScanner{
					Ip:       ip.String(),
					Hostname: hostname,
					Lock:     sharedLock,
				}
				for _, ep := range ps.Start([]int{port}, 500*time.Millisecond) {
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

	api.Send(api.SendParams{AgentData: agentData, ApiKey: apiKey, TestMode: testMode, TestApiUrl: testUrl})
}
