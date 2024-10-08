package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_BuildCidrPortList(t *testing.T) {
	yamlString := `
agent_name: test agent
api_key: __TEST_API_KEY__
skip_ports: [22, 80]
cidrs:
  test1:
    cidr: 10.0.1.0/24
    skip_ports: [8080]
  test2:
    cidr: 10.0.2.0/24
    ports: [81, 443, 8080]
    port_ranges:
      - [77, 83]
      - [20, 25]
  test3:
    cidr: 10.0.3.1/32
hosts:
  test4:
    hostname: api.third-party.invalid
    port: 8080
  test5:
    hostname: hostname.example.com
`

	var conf Configuration

	err := yaml.Unmarshal([]byte(yamlString), &conf)
	if err != nil {
		t.Error("Bad YAML")
	}

	gotPorts := BuildCidrPortList(conf.Cidrs["test1"], conf.SkipPorts)
	wantPorts := []int{443}

	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Errorf("Got %v, wanted %v", gotPorts, wantPorts)
	}

	gotPorts = BuildCidrPortList(conf.Cidrs["test2"], conf.SkipPorts)
	wantPorts = []int{20, 21, 23, 24, 25, 77, 78, 79, 81, 82, 83, 443, 8080}

	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Errorf("Got %v, wanted %v", gotPorts, wantPorts)
	}

	gotPorts = BuildCidrPortList(conf.Cidrs["test3"], conf.SkipPorts)
	wantPorts = []int{443}

	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Errorf("Got %v, wanted %v", gotPorts, wantPorts)
	}

	gotPorts = []int{conf.Hosts["test4"].Port}
	wantPorts = []int{8080}

	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Errorf("Got %v, wanted %v", gotPorts, wantPorts)
	}

	gotPorts = []int{conf.Hosts["test5"].Port}
	wantPorts = []int{443}

	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Errorf("Got %v, wanted %v", gotPorts, wantPorts)
	}
}
