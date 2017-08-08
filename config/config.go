package config

import (
	"fmt"
	"log"
	"os/user"
	"path"

	"github.com/zieckey/goini"
)

// Config contains information needed to make an API call
type Config struct {
	APIID     string
	APISecret string
	APIURL    string
}

// NewConfig creates a new config struct from the configuration file at $HOME/.threatconnect/config
func NewConfig(profile string) *Config {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	ini := goini.New()
	confFile := path.Join(user.HomeDir, ".threatconnect", "config")
	parseErr := ini.ParseFile(confFile)
	if parseErr != nil {
		log.Fatal(fmt.Sprintf("err: Does %s exist?", confFile))
	}
	apiID, ok := ini.SectionGet(profile, "api_id")
	if !ok {
		log.Fatalf("Unable to read api_id from %s", profile)
	}
	apiSecret, ok := ini.SectionGet(profile, "api_secret")
	if !ok {
		log.Fatalf("Unable to read api_secret from %s", profile)
	}
	apiURL, ok := ini.SectionGet(profile, "base_url")
	if !ok {
		log.Fatalf("Unable to read base_url from %s", profile)
	}
	c := new(Config)
	c.APIID = apiID
	c.APISecret = apiSecret
	c.APIURL = apiURL
	return c
}
