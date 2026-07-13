package main

import (
	"context"

	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Identity and breach exposure checks via DarkAPI.io",
	Long:  `Check whether an email address or other identifier appears in known breaches or PII exposures.`,
}

var identityExposureCmd = &cobra.Command{
	Use:   "exposure <email-or-value>",
	Short: "Check breach/PII exposure for a value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.IdentityExposure(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

func init() {
	identityCmd.AddCommand(identityExposureCmd)
}
