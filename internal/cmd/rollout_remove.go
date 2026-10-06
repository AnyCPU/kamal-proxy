package cmd

import (
	"net/rpc"

	"github.com/basecamp/kamal-proxy/internal/server"
	"github.com/spf13/cobra"
)

type rolloutRemoveCommand struct {
	cmd  *cobra.Command
	args server.RolloutRemoveArgs
}

func newRolloutRemoveCommand() *rolloutRemoveCommand {
	rolloutRemoveCommand := &rolloutRemoveCommand{}
	rolloutRemoveCommand.cmd = &cobra.Command{
		Use:       "remove <service>",
		Short:     "Remove the rollout target(s)",
		RunE:      rolloutRemoveCommand.run,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"service"},
	}

	rolloutRemoveCommand.cmd.Flags().DurationVar(&rolloutRemoveCommand.args.DrainTimeout, "drain-timeout", server.DefaultDrainTimeout, "Maximum time to allow existing connections to drain before removing the rollout targets")

	return rolloutRemoveCommand
}

func (c *rolloutRemoveCommand) run(cmd *cobra.Command, args []string) error {
	c.args.Service = args[0]

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response bool
		return client.Call("kamal-proxy.RolloutRemove", c.args, &response)
	})
}
