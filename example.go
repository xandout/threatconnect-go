package main

import (
	"fmt"

	"github.com/xandout/threatconnect-go/config"
	"github.com/xandout/threatconnect-go/resource"
	"github.com/xandout/threatconnect-go/threatconnect"
)

func main() {

	config := *config.NewConfig("sandbox")

	r := *resource.NewResource("/v2/groups", "GET")

	tc := threatconnect.New(config)
	fmt.Println(tc.Request(r))
}
