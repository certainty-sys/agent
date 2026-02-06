package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
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
	url := "https://portal.certainty-sys.com/api/v1/agents/discovery"

	if *params.TestMode {
		url = params.TestApiUrl
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	data, err := json.MarshalIndent(params.AgentData, "", "  ")
	if err != nil {
		logrus.Errorf("Unable to marshal JSON from: %s", data)
		return
	}
	payload := bytes.NewReader(data)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		logrus.Error(err)
		return
	}
	req = req.WithContext(ctx)
	req.Header.Add("x-api-key", params.ApiKey)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Info(string(body))
}
