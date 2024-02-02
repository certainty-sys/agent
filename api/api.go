package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type CertDetails struct {
	CommonName string `json:"common_name"`
	Issuer     string `json:"issuer"`
	Expiry     string `json:"expiry"`
	Pem        string `json:"PEM"`
}

type Endpoint struct {
	Name        string        `json:"name"`
	Port        int           `json:"port"`
	Certificate []CertDetails `json:"certificate"`
}

type Agent struct {
	Name      string     `json:"agent_name"`
	Version   string     `json:"agent_version"`
	Endpoints []Endpoint `json:"endpoints"`
}

func Send(agentData Agent, apiKey string) {
	url := "https://portal.certainty-sys.com/api/v1/agents/discovery"

	data, _ := json.MarshalIndent(agentData, "", "  ")
	payload := bytes.NewReader(data)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		fmt.Print(err.Error())
	}
	req.Header.Add("x-api-key", apiKey)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		fmt.Print(err.Error())
	}
	fmt.Println(string(body))
}
