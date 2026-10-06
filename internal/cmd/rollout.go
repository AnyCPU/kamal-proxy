package cmd

import "github.com/spf13/cobra"

type rolloutCommand struct {
	cmd *cobra.Command
}

func newRolloutCommand() *rolloutCommand {
	rolloutCommand := &rolloutCommand{}
	rolloutCommand.cmd = &cobra.Command{
		Use:   "rollout",
		Short: "Manage rollout settings",
	}

	rolloutCommand.cmd.AddCommand(newRolloutDeployCommand().cmd)
	rolloutCommand.cmd.AddCommand(newRolloutSetCommand().cmd)
	rolloutCommand.cmd.AddCommand(newRolloutEnableCommand().cmd)
	rolloutCommand.cmd.AddCommand(newRolloutDisableCommand().cmd)
	rolloutCommand.cmd.AddCommand(newRolloutRemoveCommand().cmd)

	return rolloutCommand
}
