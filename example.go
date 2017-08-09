package main

import (
	"fmt"
	"log"

	"github.com/xandout/threatconnect-go/config"
	"github.com/xandout/threatconnect-go/threatconnect"
)

func main() {

	config := *config.NewConfig("sandbox")

	tc := threatconnect.New(config)
	owners, err := tc.GetOwners()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d owners \n", owners.Data.ResultCount)

	o, err := tc.GetOwner(427)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(o.Data.Owner.Name)
}
