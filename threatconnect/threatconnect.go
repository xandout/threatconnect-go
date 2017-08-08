package threatconnect

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/xandout/threatconnect-go/config"
	"github.com/xandout/threatconnect-go/resource"
	"github.com/xandout/threatconnect-go/signature"
)

// ThreatConnect is the base object used to interact with the TC API
type ThreatConnect struct {
	Config config.Config
}

// New creates a new ThreatConnect object from the Config object
func New(config config.Config) ThreatConnect {
	t := new(ThreatConnect)
	t.Config = config
	return *t
}

// Request performs a request to the TC API
func (t ThreatConnect) Request(resource resource.Resource) string {
	client := &http.Client{}
	signature := *signature.Sign(t.Config, resource)
	fullURLString := fmt.Sprintf("%s%s", t.Config.APIURL, resource.EndPoint)
	req, err := http.NewRequest(resource.Method, fullURLString, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Timestamp", fmt.Sprintf("%d", signature.Timestamp))
	req.Header.Add("Authorization", signature.Signed)
	resp, err := client.Do(req)

	responseData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	responseString := string(responseData)

	return responseString
}
