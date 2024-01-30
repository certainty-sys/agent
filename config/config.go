package config

import (
	"os"
	"slices"

	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v3"
)

type Cidr struct {
	Cidr       string  `yaml:"cidr"`
	SkipPorts  []int   `yaml:"skip_ports,omitempty"`
	Ports      []int   `yaml:"ports,omitempty"`
	PortRanges [][]int `yaml:"port_ranges,omitempty"`
}

type Host struct {
	HostName string `yaml:"hostname"`
	Port     int    `yaml:"port"`
}

type Configuration struct {
	AgentName string          `yaml:"agent_name"`
	ApiKey    string          `yaml:"api_key"`
	ProxyHost string          `yaml:"proxy_host,omitempty"`
	ProxyPort int             `yaml:"proxy_port,omitempty"`
	SkipPorts []int           `yaml:"skip_ports,omitempty"`
	Cidrs     map[string]Cidr `yaml:"cidrs,omitempty"`
	Hosts     map[string]Host `yaml:"hosts,omitempty"`
}

// func SaveConfig(c any, filename string) error {
// 	bytes, err := yaml.Marshal(c)
// 	if err != nil {
// 		return err
// 	}

// 	return os.WriteFile(filename, bytes, 0644)
// }

func LoadConfig(filename string) (Configuration, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return Configuration{}, err
	}

	var c Configuration
	err = yaml.Unmarshal(bytes, &c)
	if err != nil {
		return Configuration{}, err
	}

	return c, nil
}

func BuildCidrPortList(config Configuration, cidrName string) []int {
	var portList []int

	cidr := config.Cidrs[cidrName]

	ports := cidr.Ports

	// Default to [443] if not provided
	if len(ports) == 0 {
		ports = []int{443}
	}

	portList = append(portList, ports...)

	for _, portRange := range cidr.PortRanges {
		s := make([]int, portRange[1]-portRange[0]+1)
		for i := range s {
			s[i] = i + portRange[0]
		}
		portList = append(portList, s...)
	}

	// Remove the CIDR's skipped ports
	cleanCidrPortList := funk.Subtract(portList, cidr.SkipPorts)

	// Remove the globally skipped ports
	cleanPortList := funk.Subtract(cleanCidrPortList, config.SkipPorts).([]int)

	// De-duplicate the list
	slices.Sort(cleanPortList)
	return slices.Compact[[]int](cleanPortList)
}
