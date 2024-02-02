package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"agent/config"
	_ "agent/logging"
	"agent/scanner"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

type Agent struct {
	Name      string             `json:"agent_name"`
	Version   string             `json:"agent_version"`
	Endpoints []scanner.Endpoint `json:"endpoints"`
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

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	conf, err := config.LoadConfig("config.yml")

	var endpointList []scanner.Endpoint

	for _, cidr := range conf.Cidrs {
		ips := config.BuildCidrIpList(cidr)

		portList := config.BuildCidrPortList(cidr, conf.SkipPorts)

		var wg = sync.WaitGroup{}
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
				endpoints := ps.Start(portList, 500*time.Millisecond)
				endpointList = append(endpointList, endpoints...)
			}(ip)
		}

		wg.Wait()

		agentData := Agent{
			Name:      conf.AgentName,
			Version:   "0.0.1a",
			Endpoints: endpointList,
		}

		data, _ := json.MarshalIndent(agentData, "", "  ")
		fmt.Println(string(data))
	}
}
