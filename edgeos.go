package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/mbrancato/edgeos/sdk"
	"strings"
)

type Cli struct {
	Create sdk.Cli `cmd`
	Read   sdk.Cli `cmd`
	Update sdk.Cli `cmd`
	Delete sdk.Cli `cmd`
}

var config Cli

func buildPathFromKong(ctx *kong.Context) string {
	command := []string{}
	for _, trace := range ctx.Path {
		switch {
		case trace.Argument != nil:
			command = append(command, "["+trace.Argument.Argument.Target.String()+"]")

		case trace.Command != nil:
			if trace.Command != nil && trace.Command.Aliases != nil && len(trace.Command.Aliases) > 0 {
				command = append(command, trace.Command.Aliases[0])
			}
		}
	}
	return strings.Join(command, "/")
}

func main() {
	ctx := kong.Parse(&config,
		kong.Name("edgeos"),
		kong.Description("An edgeos cli tool."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:             true,
			Summary:             true,
			NoExpandSubcommands: true,
		}))
	a := buildPathFromKong(ctx)
	fmt.Printf("%v\n%v\n", ctx.Command(), a)
	fmt.Printf("%v\n", ctx.Args)

}
