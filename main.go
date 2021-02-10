package main

import (
	"fmt"
	"os"

	"github.com/mbrancato/edgeos/sdk"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	List struct {
		Network ListNetwork `command:"network"`
	} `command:"list"`
	Update struct {
		Network struct {
		} `command:"network"`
	} `command:"update"`
}

type ListNetwork struct {
	Local bool `long:"local" short:"l"`
}

var session sdk.Session

func (n *ListNetwork) Execute(args []string) error {

	fmt.Println(sdk.ReadNetworkInterfaces(session))
	return nil
}

func main() {
	var err error
	if session, err = sdk.NewSession(); err != nil {
		exitError(fmt.Sprintf("Failed to get session: %v\n", err))
	}
	options := Options{}
	_, err = flags.Parse(&options)
	if err != nil {
		exitError("Failed to parse options")
	}

}

func exitError(msg string) {
	println(msg)
	os.Exit(1)
}
