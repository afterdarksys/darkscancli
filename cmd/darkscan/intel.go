package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/darkapi"
	"github.com/spf13/cobra"
)

var reputationBulkFile string

var intelCmd = &cobra.Command{
	Use:   "intel",
	Short: "Query DarkAPI.io threat intelligence",
	Long:  `Look up hashes, domains, IPs, threat feeds and indicator reputation via the DarkAPI.io threat-intelligence API.`,
}

var intelHashCmd = &cobra.Command{
	Use:   "hash <hash>",
	Short: "Look up a file hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.LookupHash(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

var intelDomainCmd = &cobra.Command{
	Use:   "domain <domain>",
	Short: "Look up a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.LookupDomain(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

var intelIPCmd = &cobra.Command{
	Use:   "ip <ip>",
	Short: "Look up an IP address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		raw, err := c.LookupIP(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

var intelFeedsCmd = &cobra.Command{
	Use:   "feeds [name]",
	Short: "List threat feeds, or fetch one by name",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()

		if len(args) == 1 {
			raw, err := c.GetFeed(ctx, args[0])
			if err != nil {
				return err
			}
			return printIntelPayload(raw)
		}

		list, err := c.ListFeeds(ctx)
		if err != nil {
			return err
		}
		if outputFormat == "json" {
			return printIntelPayload(list.Raw)
		}
		if len(list.Feeds) == 0 {
			return printIntelPayload(list.Raw)
		}
		fmt.Printf("%-24s %-10s %s\n", "NAME", "COUNT", "DESCRIPTION")
		for _, f := range list.Feeds {
			fmt.Printf("%-24s %-10d %s\n", f.Name, f.Count, f.Description)
		}
		return nil
	},
}

var intelReputationCmd = &cobra.Command{
	Use:   "reputation <indicator>",
	Short: "Look up reputation for an indicator (ip, domain, url, hash or email)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()

		if reputationBulkFile != "" {
			indicators, err := readLines(reputationBulkFile)
			if err != nil {
				return fmt.Errorf("failed to read bulk file: %w", err)
			}
			if len(indicators) == 0 {
				return fmt.Errorf("no indicators found in %s", reputationBulkFile)
			}
			raw, err := c.ReputationLookupBulk(ctx, indicators)
			if err != nil {
				return err
			}
			return printIntelPayload(raw)
		}

		if len(args) != 1 {
			return fmt.Errorf("an indicator argument is required unless --bulk is given")
		}
		raw, err := c.ReputationLookup(ctx, args[0], "")
		if err != nil {
			return err
		}
		return printIntelPayload(raw)
	},
}

func init() {
	intelReputationCmd.Flags().StringVar(&reputationBulkFile, "bulk", "", "File of indicators (one per line) for a bulk lookup")

	intelCmd.AddCommand(intelHashCmd)
	intelCmd.AddCommand(intelDomainCmd)
	intelCmd.AddCommand(intelIPCmd)
	intelCmd.AddCommand(intelFeedsCmd)
	intelCmd.AddCommand(intelReputationCmd)
}

// newDarkAPIClient loads config and constructs a DarkAPI client, returning a
// clear error if the integration is not configured.
func newDarkAPIClient() (*darkapi.Client, error) {
	if configPath == "" {
		p, err := config.GetDefaultConfigPath()
		if err != nil {
			return nil, err
		}
		configPath = p
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if !cfg.DarkAPI.Enabled || strings.TrimSpace(cfg.DarkAPI.APIKey) == "" {
		return nil, fmt.Errorf("darkapi is not configured — set \"darkapi.enabled\": true and \"darkapi.api_key\" in %s", configPath)
	}
	return darkapi.NewClient(cfg.DarkAPI)
}

// printIntelPayload pretty-prints a raw JSON payload to stdout for both text and
// json output modes (the API responses are already structured JSON).
func printIntelPayload(raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		// Not valid JSON to re-indent — emit as-is.
		fmt.Println(strings.TrimSpace(string(raw)))
		return nil
	}
	fmt.Println(buf.String())
	return nil
}

// readLines returns the non-empty, comment-free, trimmed lines of a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
