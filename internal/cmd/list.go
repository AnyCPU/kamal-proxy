package cmd

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/rpc"
	"slices"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type listCommand struct {
	cmd  *cobra.Command
	json bool
}

func newListCommand() *listCommand {
	listCommand := &listCommand{}
	listCommand.cmd = &cobra.Command{
		Use:     "list",
		Short:   "List the services currently running",
		RunE:    listCommand.run,
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
	}

	listCommand.cmd.Flags().BoolVar(&listCommand.json, "json", false, "Output the list as JSON")

	return listCommand
}

func (c *listCommand) run(cmd *cobra.Command, args []string) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response server.ListResponse

		err := client.Call("kamal-proxy.List", true, &response)
		if err != nil {
			return err
		}

		if c.json {
			return c.displayJSON(response)
		}

		c.displayTable(response)
		return nil
	})
}

func (c *listCommand) displayJSON(response server.ListResponse) error {
	output, err := json.MarshalIndent(response.Targets, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

func (c *listCommand) displayTable(response server.ListResponse) {
	table := NewTable()
	table.AddRow([]string{"Service", "Host", "Path", "Target", "State", "TLS", "Rollout"})

	sortedKeys := slices.Sorted(maps.Keys(response.Targets))
	for _, name := range sortedKeys {
		service := response.Targets[name]
		table.AddRow([]string{
			name,
			service.DisplayHosts(),
			service.DisplayPaths(),
			service.DisplayTargets(),
			service.State,
			yesNo(service.TLS),
			yesNo(service.Rollout.Enabled),
		})
	}

	table.Print()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
