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
	Name        string      `json:"name"`
	Port        int         `json:"port"`
	Certificate CertDetails `json:"certificate"`
}

type Agent struct {
	Name      string     `json:"agent_name"`
	Version   string     `json:"agent_version"`
	Endpoints []Endpoint `json:"endpoints"`
}

type SendParams struct {
	AgentData  Agent
	ApiKey     string
	TestMode   *bool
	TestApiUrl string
}

func Send(params SendParams) {
	if !*params.TestMode {
		*params.TestMode = false
	}

	url := "https://portal.certainty-sys.com/api/v1/agents/discovery"

	if *params.TestMode {
		url = params.TestApiUrl
	}

	data, _ := json.MarshalIndent(params.AgentData, "", "  ")
	payload := bytes.NewReader(data)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}
	req.Header.Add("x-api-key", params.ApiKey)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		fmt.Println("Error:", err.Error())
		return
	}
	fmt.Println(string(body))
}
