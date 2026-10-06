package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/version"
)

type versionCommand struct {
	cmd *cobra.Command
}

func newVersionCommand() *versionCommand {
	versionCommand := &versionCommand{}
	versionCommand.cmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.Version)
		},
	}

	return versionCommand
}
