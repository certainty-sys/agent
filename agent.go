package main

import (
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

	portList := config.BuildCidrPortList(conf, "dmz")
	fmt.Println(portList) // TODO Use portList

	var wg = sync.WaitGroup{}
	ips, err := scanner.GetLocalIPs()
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
			ps.Start(1, 65535, 500*time.Millisecond)
		}(ip)
	}

	wg.Wait()
}
