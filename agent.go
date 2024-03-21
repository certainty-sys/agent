package main

import (
	"flag"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"agent/api"
	"agent/config"
	_ "agent/logging"
	"agent/scanner"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

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

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	conf, err := config.LoadConfig("config.yml")
	ApiKey := conf.ApiKey
	testUrl := ""

	////////////// Enable test mode /////////////////
	// TODO: Remove for production release
	testMode := flag.Bool("test", false, "Enable test mode")
	flag.Parse()

	println("Test mode:", *testMode)
	if *testMode {
		ApiKey = conf.TestApiKey
		testUrl = conf.TestApiUrl
	}
	////////////////////////////////////////////////

	var endpointList []api.Endpoint
	var wg = sync.WaitGroup{}

	for _, cidr := range conf.Cidrs {
		ips := config.BuildCidrIpList(cidr)

		portList := config.BuildCidrPortList(cidr, conf.SkipPorts)

		sni_names := cidr.SniNames
		if len(sni_names) == 0 {
			sni_names = []string{""}
		}

		if err != nil {
			fmt.Printf("Failed to get local IPs: %s\n", err)
			return
		}

		for _, ip := range ips {
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				ps := &scanner.PortScanner{
					Ip:   ip.String(),
					Lock: semaphore.NewWeighted(Ulimit()),
				}
				endpointList = append(endpointList, ps.Start(portList, sni_names, 500*time.Millisecond)...)
			}(ip)
		}
	}

	wg.Wait()

	agentData := api.Agent{
		Name:      conf.AgentName,
		Version:   "0.0.1a",
		Endpoints: endpointList,
	}

	api.Send(api.SendParams{AgentData: agentData, ApiKey: ApiKey, TestMode: testMode, TestApiUrl: testUrl})
}
