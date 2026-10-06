package cmd

import (
	"net/rpc"

	"github.com/basecamp/kamal-proxy/internal/server"
	"github.com/spf13/cobra"
)

type rolloutDisableCommand struct {
	cmd  *cobra.Command
	args server.RolloutDisableArgs
}

func newRolloutDisableCommand() *rolloutDisableCommand {
	rolloutDisableCommand := &rolloutDisableCommand{}
	rolloutDisableCommand.cmd = &cobra.Command{
		Use:       "disable <service>",
		Short:     "Disable the rollout split",
		RunE:      rolloutDisableCommand.run,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"service"},
	}

	return rolloutDisableCommand
}

func (c *rolloutDisableCommand) run(cmd *cobra.Command, args []string) error {
	c.args.Service = args[0]

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response bool
		return client.Call("kamal-proxy.RolloutDisable", c.args, &response)
	})
}
