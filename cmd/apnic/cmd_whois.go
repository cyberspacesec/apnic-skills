package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	whoisCmd.AddCommand(whoisIPCmd)
	whoisCmd.AddCommand(whoisASNCmd)
	whoisCmd.AddCommand(whoisRawCmd)
	rootCmd.AddCommand(whoisCmd)
	rootCmd.AddCommand(reverseDNSCmd)
}

var whoisCmd = &cobra.Command{
	Use:   "whois",
	Short: "Whois queries against the APNIC whois server",
}

var whoisIPCmd = &cobra.Command{
	Use:   "ip <ip>",
	Short: "Parsed whois lookup for an IP address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newClient()
		ctx := context.Background()
		info, err := client.QueryWhoisIP(ctx, args[0])
		if err != nil {
			return err
		}
		if flagJSON {
			printJSON(info)
			return nil
		}
		fmt.Printf("Network: %s\n", info.Network)
		fmt.Printf("CIDR:    %v\n", info.CIDR)
		fmt.Printf("Country: %s\n", info.Country)
		fmt.Printf("Org:     %s\n", info.OrgName)
		fmt.Printf("Parent:  %s\n", info.Parent)
		fmt.Printf("Created: %s\n", info.Created)
		fmt.Printf("Updated: %s\n", info.LastUpdated)
		return nil
	},
}

var whoisASNCmd = &cobra.Command{
	Use:   "asn <asn>",
	Short: "Parsed whois lookup for an ASN (e.g. 13335 or AS13335)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		asn, err := strconv.ParseInt(normalizeASN(args[0]), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ASN %q: %w", args[0], err)
		}
		client := newClient()
		ctx := context.Background()
		info, err := client.QueryWhoisASN(ctx, asn)
		if err != nil {
			return err
		}
		if flagJSON {
			printJSON(info)
			return nil
		}
		fmt.Printf("Network: %s\n", info.Network)
		fmt.Printf("Country: %s\n", info.Country)
		fmt.Printf("Org:     %s\n", info.OrgName)
		return nil
	},
}

var whoisRawCmd = &cobra.Command{
	Use:   "raw <query>",
	Short: "Raw whois query (returns unparsed text)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newClient()
		ctx := context.Background()
		resp, err := client.QueryWhois(ctx, args[0])
		if err != nil {
			return err
		}
		fmt.Print(resp)
		return nil
	},
}

var reverseDNSCmd = &cobra.Command{
	Use:   "reverse-dns <ip>",
	Short: "Reverse DNS lookup for an IP address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newClient()
		ctx := context.Background()
		names, err := client.ReverseDNS(ctx, args[0])
		if err != nil {
			return err
		}
		if flagJSON {
			printJSON(names)
			return nil
		}
		if len(names) == 0 {
			fmt.Println("(no PTR records)")
			return nil
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

// normalizeASN strips an optional "AS" prefix so the user can pass either 13335 or AS13335.
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "AS")
	s = strings.TrimPrefix(s, "as")
	return s
}
