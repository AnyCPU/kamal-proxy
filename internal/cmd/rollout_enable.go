package cmd

import (
	"net/rpc"

	"github.com/basecamp/kamal-proxy/internal/server"
	"github.com/spf13/cobra"
)

type rolloutEnableCommand struct {
	cmd  *cobra.Command
	args server.RolloutEnableArgs
}

func newRolloutEnableCommand() *rolloutEnableCommand {
	rolloutEnableCommand := &rolloutEnableCommand{}
	rolloutEnableCommand.cmd = &cobra.Command{
		Use:       "enable <service>",
		Short:     "Enable the rollout split",
		RunE:      rolloutEnableCommand.run,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"service"},
	}

	return rolloutEnableCommand
}

func (c *rolloutEnableCommand) run(cmd *cobra.Command, args []string) error {
	c.args.Service = args[0]

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response bool
		return client.Call("kamal-proxy.RolloutEnable", c.args, &response)
	})
}
