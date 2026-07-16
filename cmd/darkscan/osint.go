package main

import (
	"context"

	"github.com/spf13/cobra"
)

var osintCmd = &cobra.Command{
	Use:   "osint",
	Short: "OSINT identity enrichment and source status via DarkAPI.io",
	Long: `Run OSINT identity enrichment and inspect which external data sources are
enabled on the server.

The keyless sources (social probes, breach lookups, cert transparency, archives,
search) run on every tier. Paid per-query sources (HIBP, Dehashed, Intelligence X,
Numverify) are unlocked on Pro and above; on a free tier the result includes a
"locked" block naming what an upgrade would reveal.`,
}

var osintSourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List which external data sources are enabled on the server",
	Long:  "Reports each keyed source and whether it is currently live (enabled) or gated, so you can confirm a freshly-provisioned key is wired through.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.OsintSources(context.Background())
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

var osintPersonCmd = &cobra.Command{
	Use:   "person <query>",
	Short: "Full OSINT identity enrichment for an email, username, name, phone, or domain",
	Long:  "Enriches an identity across every source the caller's tier allows. Free-tier results include a \"locked\" block listing the paid sources an upgrade would unlock.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.OsintPerson(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

func init() {
	osintCmd.AddCommand(osintSourcesCmd)
	osintCmd.AddCommand(osintPersonCmd)
}
