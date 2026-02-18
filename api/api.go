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

type API struct {
	AgentData  Agent
	Key        string
	TestMode   *bool
	TestApiUrl string
}

func (api API) Send() {
	url := "https://portal.certainty-sys.com/api/v1/agents/discovery"

	if *api.TestMode {
		url = api.TestApiUrl
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	data, err := json.MarshalIndent(api.AgentData, "", "  ")
	if err != nil {
		logrus.Errorf("Unable to marshal JSON: %s", err)
		return
	}
	payload := bytes.NewReader(data)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		logrus.Error(err)
		return
	}
	req = req.WithContext(ctx)
	req.Header.Add("certainty-api-key", api.Key)
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
