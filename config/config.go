package config

import (
	"encoding/binary"
	"net"
	"os"
	"slices"

	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v3"

	"github.com/sirupsen/logrus"
)

type Cidr struct {
	Cidr       string  `yaml:"cidr"`
	PortRanges [][]int `yaml:"port_ranges,omitempty"`
	Ports      []int   `yaml:"ports,omitempty"`
	SkipPorts  []int   `yaml:"skip_ports,omitempty"`
}

type Host struct {
	HostName string `yaml:"hostname"`
	Port     int    `yaml:"port,omitempty"`
}

type Configuration struct {
	AgentName  string          `yaml:"agent_name"`
	ApiKey     string          `yaml:"api_key"`
	Cidrs      map[string]Cidr `yaml:"cidrs,omitempty"`
	Hosts      map[string]Host `yaml:"hosts,omitempty"`
	ProxyHost  string          `yaml:"proxy_host,omitempty"`
	ProxyPort  int             `yaml:"proxy_port,omitempty"`
	SkipPorts  []int           `yaml:"skip_ports,omitempty"`
	TestApiKey string          `yaml:"test_api_key,omitempty"`
	TestApiUrl string          `yaml:"test_api_url,omitempty"`
}

func (h *Host) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if h.Port == 0 {
		h.Port = 443
	}

	type plain Host
	if err := unmarshal((*plain)(h)); err != nil {
		return err
	}

	return nil
}

func LoadConfig(filename string) (Configuration, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return Configuration{}, err
	}

	var config Configuration
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return Configuration{}, err
	}

	return config, nil
}

func BuildCidrPortList(cidr Cidr, globalSkipPorts []int) []int {
	var portList []int

	ports := cidr.Ports

	// Default to [443] if not provided
	if len(ports) == 0 {
		ports = []int{443}
	}

	portList = append(portList, ports...)

	for _, portRange := range cidr.PortRanges {
		if len(portRange) < 2 || portRange[0] > portRange[1] {
			continue
		}
		s := make([]int, portRange[1]-portRange[0]+1)
		for i := range s {
			s[i] = i + portRange[0]
		}
		portList = append(portList, s...)
	}

	// Remove the CIDR's skipped ports
	cleanCidrPortList := funk.Subtract(portList, cidr.SkipPorts)

	// Remove the globally skipped ports
	cleanPortList := funk.Subtract(cleanCidrPortList, globalSkipPorts).([]int)

	// De-duplicate the list
	slices.Sort(cleanPortList)
	return slices.Compact(cleanPortList)
}

func BuildCidrIpList(cidr Cidr) []net.IP {
	var ipList []net.IP

	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr.Cidr)
	if err != nil {
		logrus.Error(err)
		return []net.IP{}
	}

	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// Single IP (/32)
	if mask == 4294967295 {
		return []net.IP{ipv4Net.IP}
	}

	// Skip network address
	start++

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// Skip network broadcast
	finish--

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ipList = append(ipList, ip)
	}

	return ipList
}
