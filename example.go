package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/xandout/threatconnect-go/config"
	"github.com/xandout/threatconnect-go/resource"
	"github.com/xandout/threatconnect-go/signature"
)

func main() {

	config := *config.NewConfig("sandbox")

	r := *resource.NewResource("/v2/whoami", "GET")

	client := &http.Client{}

	fullURLString := fmt.Sprintf("%s%s", config.APIURL, r.EndPoint)
	signature := *signature.Sign(config, r)
	req, err := http.NewRequest(r.Method, fullURLString, nil)
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
	fmt.Println(responseString)
}
